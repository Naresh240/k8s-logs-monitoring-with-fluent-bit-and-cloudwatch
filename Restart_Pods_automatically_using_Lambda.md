# Restart Pods Automatically using Lambda

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

2. Create lambda function with ```lambda.py``` script attach the above role 

![Lambda_creation](./images/lambda-creation.jpg)

3. Adding Layer to Lambda function

![Layer_Usage_in_Lambda](./images/layer_usage_in_lambda.jpg)

4. Create SNS Topic to trigger Lambda Function

![trigger_lambda_function](./images/trigger_lambda_function.jpg)

5. Create Subscription to trigger Lambda function

![Subscription_to_trigger_Lambda](./images/subscription_to_trigger_lambda.jpg)

6. Create Custom metric under cloudwatch loggroups using metric filter

![metric_filter](./images/metric_filter.jpg)

7. Select filter pattern

![filter_pattern](./images/filter-pattern.jpg)

8. Specify details for filter name and metric namespace

![Assign_metric_name](./images/assign-metric-name.jpg)

9. Review and Create metric

![Review_and_Create_metric](./images/review-create-metric.png)

10. Create Alarm to send notifications to SNS

![Start_Creating_Alarm](./images/start-creating-alarm.jpg)

11. Select Custom Namespace under Alarm

![Select_Custom_Namespace](./images/select-custom-namespace.jpg)

12. Select Metric name under Alarm

![Select_Metric_Name](./images/select-metric-for-alarm.jpg)

13. Specify Metric and Conditions

![Specify_Metric_and_Conditions](./images/specify_metric_and_conditions.jpg)

14. Select SNS topic for alarm

![Slect_SNS_Topic](./images/select-sns-topic.jpg)

15. Review and Create Alarm

![Providing_alarm_name](./images/alarm-name.jpg)