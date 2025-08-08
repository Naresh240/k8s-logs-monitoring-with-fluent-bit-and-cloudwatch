import boto3
import base64
import os
import json
import re
import time
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from botocore.signers import RequestSigner

# Environment variables or defaults
CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "eksdemo")
REGION = os.environ.get("REGION", "us-east-1")
LOG_GROUP = os.environ.get("LOG_GROUP", "/aws/eks/fluentbit-logs")

def get_secret(secret_name, region_name):
    """Fetch AWS creds JSON from Secrets Manager."""
    session = boto3.session.Session()
    client_sm = session.client(service_name='secretsmanager', region_name=region_name)
    
    response = client_sm.get_secret_value(SecretId=secret_name)

    if 'SecretString' in response:
        secret = response['SecretString']
    else:
        secret = base64.b64decode(response['SecretBinary'])

    return json.loads(secret)

def get_bearer_token(cluster_name, region, session):
    eks = session.client("eks", region_name=region)
    service_id = eks.meta.service_model.service_id

    signer = RequestSigner(
        service_id,
        region,
        "sts",
        "v4",
        session.get_credentials(),
        session.events
    )

    request_params = {
        'method': 'GET',
        'url': f'https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
        'body': b'',
        'headers': {'x-k8s-aws-id': cluster_name},
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        request_params,
        region_name=region,
        expires_in=60,
        operation_name=''
    )

    return 'k8s-aws-v1.' + base64.urlsafe_b64encode(
        signed_url.encode('utf-8')
    ).decode('utf-8').rstrip('=')

def get_recent_error_logs(log_group, region):
    logs_client = boto3.client('logs', region_name=region)

    # Look at logs from the last 5 minutes
    now = int(time.time() * 1000)
    five_minutes_ago = now - 5 * 60 * 1000

    response = logs_client.filter_log_events(
        logGroupName=log_group,
        filterPattern='ERROR',
        startTime=five_minutes_ago,
        endTime=now,
        limit=50  # Increase limit to capture more recent matches
    )
    events = response.get('events', [])
    if not events:
        return None

    # Sort to be safe
    sorted_events = sorted(events, key=lambda x: x['timestamp'], reverse=True)
    return sorted_events[0]['message']


def parse_log_for_pod_details(log_line):
    try:
        # Try direct JSON parse
        try:
            log_json = json.loads(log_line)
        except json.JSONDecodeError:
            print("Trying to extract JSON string from message...")
            json_match = re.search(r'{.*}', log_line)
            if json_match:
                log_json = json.loads(json_match.group())
            else:
                raise

        pod = log_json.get("kubernetes", {}).get("pod_name")
        namespace = log_json.get("kubernetes", {}).get("namespace_name")
        if pod and namespace:
            print(f"Extracted Pod Name: {pod}")
            print(f"Extracted Namespace: {namespace}")
            return pod, namespace
        else:
            print("Pod or namespace not found in log.")
    except Exception as e:
        print(f"Error while parsing log: {e}")
    
    return None, None

def delete_pod(pod_name, namespace):
    v1 = client.CoreV1Api()
    print(f"Deleting pod '{pod_name}' in namespace '{namespace}'")
    try:
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
    except ApiException as e:
        print("Failed to delete pod:", e)
        print("Response body:", e.body)
        raise

def lambda_handler(event, context):
    secret_name = "dev/lambda/aws_creds"
    region = "us-east-1"
    cluster_name = "eksdemo"

    # Fetch creds from Secrets Manager
    creds = get_secret(secret_name, region)

    # Set AWS creds for boto3
    os.environ["AWS_ACCESS_KEY_ID"] = creds["AWS_ACCESS_KEY_ID"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = creds["AWS_SECRET_ACCESS_KEY"]
    if "AWS_SESSION_TOKEN" in creds:
        os.environ["AWS_SESSION_TOKEN"] = creds["AWS_SESSION_TOKEN"]

    # Start session with creds
    session = boto3.session.Session()
    eks = session.client("eks", region_name=region)
    cluster_info = eks.describe_cluster(name=cluster_name)

    token = get_bearer_token(cluster_name, region, session)

    # Write CA file
    ca_data = base64.b64decode(cluster_info["cluster"]["certificateAuthority"]["data"])
    ca_path = "/tmp/ca.crt"
    with open(ca_path, "wb") as f:
        f.write(ca_data)

    # Configure Kubernetes client
    configuration = client.Configuration()
    configuration.host = cluster_info["cluster"]["endpoint"]
    configuration.verify_ssl = True
    configuration.ssl_ca_cert = ca_path
    configuration.api_key = {"authorization": "Bearer " + token}

    client.Configuration.set_default(configuration)

    log_line = get_recent_error_logs(LOG_GROUP, REGION)
    if not log_line:
        print("No ERROR logs found.")
        return {"status": "no-error-logs"}

    print("Log line:", log_line)

    pod_name, namespace = parse_log_for_pod_details(log_line)
    if not pod_name or not namespace:
        print("Could not extract pod name or namespace.")
        return {
            "status": "parse-failure",
            "log_line": log_line
        }

    delete_pod(pod_name, namespace)

    return {
        "status": "pod-deleted",
        "pod": pod_name,
        "namespace": namespace
    }
