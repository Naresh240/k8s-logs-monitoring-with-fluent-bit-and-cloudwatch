# Kubernetes Logs Monitoring with Fluent-bit and Cloudwatch

## Pre-Requisites

```bash
EKS Cluster
```

## Enable OIDC in EKS cluster

```bash
eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=eksdemo --approve
```

## Fluent-bit Setup

1. Create policy using ```awscli``` command

```bash
aws iam create-policy \
  --policy-name FluentBitCloudWatchPolicy \
  --policy-document file://fluent-bit-policy.json
```

2. Create IRSA to communicate fluent bit pod to cloudwatch

```bash
eksctl create iamserviceaccount \
  --name fluent-bit \
  --namespace kube-system \
  --cluster eksdemo \
  --attach-policy-arn arn:aws:iam::400095111010:policy/FluentBitCloudWatchPolicy \
  --approve \
  --region us-east-1
```

3. Add Fluent Bit Helm Repo

```bash
helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
```

4. Install fluent bit using helm

```bash
helm install fluent-bit fluent/fluent-bit \
  --namespace kube-system \
  -f fluentbit-values.yaml
```