import boto3
import base64
import os
from kubernetes import client
from botocore.signers import RequestSigner

def get_bearer_token(cluster_name, region, session):
    eks = session.client("eks", region_name=region)

    # Service ID is always "eks" for EKS clusters
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
        operation_name=''  # must be empty string here
    )

    return 'k8s-aws-v1.' + base64.urlsafe_b64encode(
        signed_url.encode('utf-8')
    ).decode('utf-8').rstrip('=')


def restart_pod(pod_name, namespace="default"):
    v1 = client.CoreV1Api()
    try:
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
        return f"Pod {pod_name} deleted — it will be restarted by the deployment."
    except client.rest.ApiException as e:
        return f"Exception when deleting pod: {e}"


def lambda_handler(event, context):
    os.environ["AWS_ACCESS_KEY_ID"] = event["AWS_ACCESS_KEY_ID"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = event["AWS_SECRET_ACCESS_KEY"]
    os.environ["AWS_SESSION_TOKEN"] = event.get("AWS_SESSION_TOKEN", "")

    cluster_name = "eksdemo"
    region = "us-east-1"

    session = boto3.session.Session()
    eks = session.client("eks", region_name=region)
    cluster_info = eks.describe_cluster(name=cluster_name)

    token = get_bearer_token(cluster_name, region, session)

    # Write CA file
    ca_data = base64.b64decode(
        cluster_info["cluster"]["certificateAuthority"]["data"]
    )
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

    # Restart the specific pod
    restart_result = restart_pod("error-logger-756c89674b-mzz49", namespace="error-logs-demo")

    # Optionally, list nodes to confirm access
    v1 = client.CoreV1Api()
    nodes = v1.list_node()
    node_names = [node.metadata.name for node in nodes.items]

    return {
        "restart_status": restart_result,
        "nodes": node_names
    }
