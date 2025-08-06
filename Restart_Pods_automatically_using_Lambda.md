# Restart Pods Automatically using Lambda

## Architecture overview — How it works

![Architecture overview](./images/authentication.jpg)

## Creating zip file to add Layer to lambda if not exists, here I am already providing ```python.zip``` file

```bash
mkdir python
pip install -t python kubernetes --no-user
# compress package directory
zip -r python
```

## Add Kubernetes layer to Lambda Service

Lambda  --> Layer  --> Create Layer (Add name + upload zip file)

![Lambda-Layer-Creation](./images/lambda-layer.jpg)

## Create Lambda function

1. Create Policy and Role for Lambda fucntion

```bash
# Create Policy
aws iam create-policy \
  --policy-name lambda-eks-policy \
  --policy-document file://lambda-eks-connection.json

# Create Role
aws iam create-role \
  --role-name lambda-eks-role \
  --assume-role-policy-document file://lambda-trust-policy.json

# Attach Policy to Role
aws iam attach-role-policy \
  --role-name lambda-eks-role \
  --policy-arn arn:aws:iam::400095111010:policy/lambda-eks-policy
```

2. To authenticate EKS cluster to AWS Services need to add below content with in auth-config file

```bash
mapRoles: |
  - rolearn: arn:aws:iam::<account-number>:role/<role-name>
    username: <role-name>
    groups:
      - system:masters
```

3. Create lambda function with ```lambda.py``` script attach the above role 

![Lambda_creation](./images/lambda-creation.jpg)

4. Adding Layer to Lambda function

![Layer_Usage_in_Lambda](./images/layer_usage_in_lambda.jpg)

5. Create SNS Topic to trigger Lambda Function

![trigger_lambda_function](./images/trigger_lambda_function.jpg)

6. Create Subscription to trigger Lambda function

![Subscription_to_trigger_Lambda](./images/subscription_to_trigger_lambda.jpg)

7. Create Custom metric under cloudwatch loggroups using metric filter

![metric_filter](./images/metric_filter.jpg)

8. Select filter pattern

![filter_pattern](./images/filter-pattern.jpg)

9. Specify details for filter name and metric namespace

![Assign_metric_name](./images/assign-metric-name.jpg)

10. Review and Create metric

![Review_and_Create_metric](./images/review-create-metric.png)

11. Create Alarm to send notifications to SNS

![Start_Creating_Alarm](./images/start-creating-alarm.jpg)

12. Select Custom Namespace under Alarm

![Select_Custom_Namespace](./images/select-custom-namespace.jpg)

13. Select Metric name under Alarm

![Select_Metric_Name](./images/select-metric-for-alarm.jpg)

14. Specify Metric and Conditions

![Specify_Metric_and_Conditions](./images/specify_metric_and_conditions.jpg)

15. Select SNS topic for alarm

![Slect_SNS_Topic](./images/select-sns-topic.jpg)

15. Review and Create Alarm

![Providing_alarm_name](./images/alarm-name.jpg)
