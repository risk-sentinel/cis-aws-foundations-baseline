# encoding: UTF-8

control 'C-2.21' do
  title 'Ensure AWS resource policies do not allow unrestricted access using "Principal": "*"'
  desc  "
    Ensure AWS resource-based policies, such as Amazon S3 bucket policies, Amazon SQS queue policies, Amazon SNS topic policies, and AWS Lambda resource policies, do not grant unrestricted access using `\"Principal\": \"*\"` with `\"Effect\": \"Allow\"` unless the policy includes restrictive conditions that limit access to specific trusted identities, accounts, services, or network boundaries.

    Resource-based policies are evaluated alongside identity-based IAM policies during authorization decisions. When a policy statement specifies `\"Principal\": \"*\"` with `\"Effect\": \"Allow\"`, it grants the specified permissions to any AWS principal unless additional conditions restrict the request. This may unintentionally allow access from users, roles, or services in any AWS account. Such broad access significantly increases the risk of unauthorized data access, resource abuse, or data exfiltration.
  "
  desc  'rationale', "
    Ensure AWS resource-based policies, such as Amazon S3 bucket policies, Amazon SQS queue policies, Amazon SNS topic policies, and AWS Lambda resource policies, do not grant unrestricted access using `\"Principal\": \"*\"` with `\"Effect\": \"Allow\"` unless the policy includes restrictive conditions that limit access to specific trusted identities, accounts, services, or network boundaries.

    Resource-based policies are evaluated alongside identity-based IAM policies during authorization decisions. When a policy statement specifies `\"Principal\": \"*\"` with `\"Effect\": \"Allow\"`, it grants the specified permissions to any AWS principal unless additional conditions restrict the request. This may unintentionally allow access from users, roles, or services in any AWS account. Such broad access significantly increases the risk of unauthorized data access, resource abuse, or data exfiltration.
  "
  desc  'check', "
    1. Identify resources that support resource-based policies within the AWS account, such as S3 buckets, SQS queues, SNS topics, and Lambda functions

    2. Retrieve the resource policies for each resource. Example CLI commands:

    SQS Queue Policies

    ```
    aws sqs get-queue-attributes \\
    --queue-url https://sqs.region.amazonaws.com/account/QUEUE \\
    --attribute-names Policy
    ```

    S3 Bucket Policies

    ```
    aws s3api get-bucket-policy \\
    --bucket YOUR-BUCKET-NAME
    ```

    SNS Topic Policies

    ```
    aws sns get-topic-attributes \\
        --topic-arn TOPIC-ARN \\
        --query \"Attributes.Policy\" \\
        --output text
    ```

    3. Inspect the retrieved policies and identify statements containing:
    - \"Effect\": \"Allow\" AND \"Principal\": \"*\"
    OR
    - \"Principal\": {\"AWS\": \"*\"}

    4. Evaluate whether the statement includes restrictive conditions such as:
    - aws:SourceArn
    - aws:SourceAccount
    - aws:PrincipalArn
    - Other service-specific condition keys

    5. Determine audit status:
    - Compliant: Wildcard principals are present only when restrictive conditions limit access to trusted principals or services
    - Non-Compliant: Wildcard principals are used without sufficient restrictions
  "
  desc  'fix', "
    If a resource policy contains `\"Principal\": \"*\"` with `\"Effect\": \"Allow\"` and lacks sufficient restrictions, modify the policy to limit access.

    OPTION 1 - Restrict the Principal
    Replace the wildcard principal (\"Principal\": \"*\") with a specific account, role, user, or service.

    Example: Non-Compliant Policy

    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Sid\": \"AllowPublicAccess\",
          \"Effect\": \"Allow\",
          \"Principal\": \"*\",
          \"Action\": \"sqs:SendMessage\",
          \"Resource\": \"arn:aws:sqs:us-east-1:123456789012:my-queue\"
        }
      ]
    }
    ```

    Steps:

    1. Retrieve the current policy:

    ```
    aws sqs get-queue-attributes \\
      --queue-url https://sqs.us-east-1.amazonaws.com/123456789012/my-queue \\
      --attribute-names Policy \\
      --query 'Attributes.Policy'
    ```

    2. Update the policy with a specific principal:

    ```
    aws sqs set-queue-attributes \\
      --queue-url https://sqs.us-east-1.amazonaws.com/123456789012/my-queue \\
      --attributes '{
        \"Policy\": \"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Sid\\\":\\\"AllowSpecificAccount\\\",\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":{\\\"AWS\\\":\\\"arn:aws:iam::345678901234:root\\\"},\\\"Action\\\":\\\"sqs:SendMessage\\\",\\\"Resource\\\":\\\"arn:aws:sqs:us-east-1:123456789012:my-queue\\\"}]}\"
      }'
    ```

    Resulting Compliant Policy:
    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Sid\": \"AllowSpecificAccount\",
          \"Effect\": \"Allow\",
          \"Principal\": {
            \"AWS\": \"arn:aws:iam::345678901234:root\"
          },
          \"Action\": \"sqs:SendMessage\",
          \"Resource\": \"arn:aws:sqs:us-east-1:123456789012:my-queue\"
        }
      ]
    }
    ```

    OPTION 2 - Restrict Using Conditions
    If a wildcard principal is required, add restrictive conditions.

    Example compliant policy:

    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Sid\": \"AllowServiceIntegration\",
          \"Effect\": \"Allow\",
          \"Principal\": \"*\",
          \"Action\": \"sqs:SendMessage\",
          \"Resource\": \"arn:aws:sqs:us-east-1:123456789012:my-queue\",
          \"Condition\": {
            \"StringEquals\": {
              \"aws:SourceAccount\": \"345678901234\"
            }
          }
        }
      ]
    }
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-2 c']
  tag nist_r4:               ['AC-2 c', 'AC-3']
  tag cci:                   ['CCI-000213', 'CCI-002113']
  tag cis_number:            '2.21'
  tag cis_rid:               '2.21'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0221r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  scanner = aws_resource_policy_violations(
    excluded_arns:  input('c221_excluded_arns'),
    regions:        input('scan_regions'),
    aws_partition:  input('aws_partition'),
  )

  describe 'AWS resource policies must not allow Principal: "*" without a Condition' do
    subject { scanner.violations }
    it { should be_empty }
  end

  # Surface enumeration failures (AccessDenied on a service, transient
  # SDK errors) as a separate, non-failing describe so an auditor can
  # see the scanner's blind spots without masking real findings. Hard-
  # failing here would conflate "we couldn't scan" with "we found
  # violations" — the scope of this control is the latter.
  unless scanner.partial_failures.empty?
    describe "CIS 2.21 partial scan coverage (informational)" do
      it "completed with the following per-service errors (does not affect pass/fail)" do
        skip "partial-coverage: #{scanner.partial_failures.length} per-service errors logged; review with --log-level info"
      end
    end
  end
end
