# encoding: UTF-8

control 'C-2.9' do
  title 'Ensure IAM password policy prevents password reuse'
  desc  "
    IAM password policies can prevent the reuse of passwords by the same user. It is recommended that the password policy be configured to prevent password reuse.

    Preventing password reuse increases account resilience against brute force and credential reuse attacks.
  "
  desc  'rationale', "
    IAM password policies can prevent the reuse of passwords by the same user. It is recommended that the password policy be configured to prevent password reuse.

    Preventing password reuse increases account resilience against brute force and credential reuse attacks.
  "
  desc  'check', "
    Perform the following to ensure the password policy is configured as prescribed:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Click on `Account Settings` on the left Pane
    3. Ensure `Prevent password reuse` is checked
    4. Ensure `Remember XX password(s)` is set appropriately (e.g., 24 or greater)

    From Command Line:

    1. Run the following command:
    ```
    aws iam get-account-password-policy  
    ```
    2. Ensure the output includes:
    ```
    \"PasswordReusePrevention\": 24
    ```
  "
  desc  'fix', "
    Perform the following to set the password policy as prescribed:

    From Console:

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to `IAM Service`
    3. Select `Account Settings` on the left Pane
    4. Check `Prevent password reuse`
    5. Set `Remember XX password(s)` to 24 or greater

    From Command Line:
    1. Run the following command:
    ```
     aws iam update-account-password-policy --password-reuse-prevention 24
    ```
    Note: All commands starting with \"aws iam update-account-password-policy\" can be combined into a single command.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-APM', 'KSI-SVC-EIS']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '2.9'
  tag cis_rid:               '2.9'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0209r1_rule'
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

  describe aws_iam_password_policy do
    it                                    { should exist }
    it                                    { should prevent_password_reuse }
    its('number_of_passwords_to_remember') { should cmp >= 24 }
  end
end
