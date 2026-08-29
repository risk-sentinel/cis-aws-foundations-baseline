# encoding: UTF-8

control 'C-2.15' do
  title 'Ensure a support role has been created to manage incidents with AWS Support'
  desc  "
    AWS provides a Support Center that can be used for incident notification and response, as well as technical support and customer service. Create an IAM role with the appropriate policy assigned to allow authorized users to manage incidents with AWS Support.

    Following the principle of least privilege, an IAM role should be used with a scoped policy to allow access to AWS Support. This ensures only authorized users can manage support cases without requiring broad administrative access.
  "
  desc  'rationale', "
    AWS provides a Support Center that can be used for incident notification and response, as well as technical support and customer service. Create an IAM role with the appropriate policy assigned to allow authorized users to manage incidents with AWS Support.

    Following the principle of least privilege, an IAM role should be used with a scoped policy to allow access to AWS Support. This ensures only authorized users can manage support cases without requiring broad administrative access.
  "
  desc  'check', "
    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. In the left navigation pane, under `Access management`, select `Policies`
    3. In the policy search field, enter `AWSSupportAccess`
    4. Select the policy
    5. Click the `Entities attached` tab
    6. Ensure at least one `IAM Role` is attached

    From Command Line:

    1. Identify the AWS managed support policy:
    ```
    aws iam list-policies --query \"Policies[?PolicyName=='AWSSupportAccess'].Arn\" --output text
    ```
    2. Check if it is attached to any roles:
    ```
    aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess
    ```
    3. Ensure that at least one role is listed under `PolicyRoles`
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and open the IAM console
    2. Navigate to `Roles`
    3. Click `Create role`
    4. Configure the trusted entity (e.g., your AWS account or identity provider)
    5. Attach the `AWSSupportAccess` policy
    6. Complete role creation
    7. Assign the role to appropriate users or groups

    From Command Line:

    1. Create a trust policy (example):

    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Effect\": \"Allow\",
          \"Principal\": {
            \"AWS\": \"arn:aws:iam:: :root\"
          },
          \"Action\": \"sts:AssumeRole\"
        }
      ]
    }
    ```
    2. Create the role:
    ```
    aws iam create-role --role-name --assume-role-policy-document file://trust-policy.json
    ```
    3. Attach the AWS Support policy:
    ```
    aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-8 a', 'IR-7']
  tag cci:                   ['CCI-000051', 'CCI-000839']
  tag cis_number:            '2.15'
  tag cis_rid:               '2.15'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0215r1_rule'
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

  # The AWSSupportAccess managed policy must be attached to at least
  # one IAM entity (role/user/group). aws_iam_policy takes policy_arn.
  describe aws_iam_policy(policy_arn: 'arn:aws:iam::aws:policy/AWSSupportAccess') do
    it { should exist }
    its('attachment_count') { should be > 0 }
  end
end
