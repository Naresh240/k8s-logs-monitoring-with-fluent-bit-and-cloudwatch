import boto3
import os
import base64
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

def get_bearer_token(cluster_name, region):
    STS_TOKEN_EXPIRES_IN = 60
    session = boto3.session.Session(region_name=region)
    client = session.client('sts')
    service_id = client.meta.service_model.service_id
    signer = RequestSigner(
        service_id,
        region,
        'sts',
        'v4',
        session.get_credentials(),
        session.events
    )
    params = {
        'method': 'GET',
        'url': f'https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
        'body': {},
        'headers': {'x-k8s-aws-id': cluster_name},
        'context': {}
    }
    signed_url = signer.generate_presigned_url(
        params,
        region_name=region,
        expires_in=STS_TOKEN_EXPIRES_IN,
        operation_name=''
    )
    base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')
    token = 'k8s-aws-v1.' + base64_url.rstrip('=')
    print("Generated bearer token (truncated):", token[:80])
    return token

def load_k8s_config():
    eks = boto3.client('eks', region_name=REGION)
    cluster_info = eks.describe_cluster(name=CLUSTER_NAME)['cluster']

    print("Using endpoint:", cluster_info['endpoint'])

    ca_data = base64.b64decode(cluster_info['certificateAuthority']['data'])
    ca_path = "/tmp/ca.crt"
    with open(ca_path, "wb") as f:
        f.write(ca_data)
    print("CA cert written to:", ca_path)

    configuration = Configuration()
    configuration.host = cluster_info['endpoint']
    configuration.verify_ssl = True
    configuration.ssl_ca_cert = ca_path
    configuration.debug = True

    configuration.api_key = {
        "authorization": get_bearer_token(CLUSTER_NAME, REGION)
    }
    configuration.api_key_prefix = {
        "authorization": "Bearer"
    }

    Configuration.set_default(configuration)

def get_k8s_nodes():
    v1 = client.CoreV1Api()
    try:
        nodes = v1.list_node()
        node_names = [node.metadata.name for node in nodes.items]
        print("Cluster Nodes:")
        for name in node_names:
            print(f" - {name}")
        return node_names
    except ApiException as e:
        print("Kubernetes API Exception:", e)
        print("Response body:", e.body)
        raise

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
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    print("STS Caller Identity:", identity)

    try:
        load_k8s_config()
        get_k8s_nodes()

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

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }
