# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure IAM password policy requires minimum length of 14 or greater'
  desc  "
    Password policies are used, in part, to enforce password complexity requirements. IAM password policies can ensure that passwords meet a minimum length. It is recommended that the password policy require a minimum password length of 14 characters.

    Setting a password policy with sufficient length requirements increases account resilience against brute force login attempts.
  "
  desc  'rationale', "
    Password policies are used, in part, to enforce password complexity requirements. IAM password policies can ensure that passwords meet a minimum length. It is recommended that the password policy require a minimum password length of 14 characters.

    Setting a password policy with sufficient length requirements increases account resilience against brute force login attempts.
  "
  desc  'check', "
    Perform the following to ensure the password policy is configured as prescribed:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Select `Account Settings` on the left Pane
    3. Located the 'Password Policy' section
    4. Ensure \"Minimum password length\" is set to 14 or greater.

    From Command Line:

    1. Run the following command:
    ```
    aws iam get-account-password-policy
    ```
    2. Ensure the output includes:
    ```
    \"MinimumPasswordLength\": 14
    ```
    (or higher)
  "
  desc  'fix', "
    Perform the following to set the password policy as prescribed:

    From Console:

    1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
    2. Go to IAM Service
    3. Select `Account Settings` on the Left Pane
    4. Set \"Minimum password length\" to `14`  or greater
    5. Select \"Apply password policy\"

    From Command Line:

    1. Run the following command:
    ```
     aws iam update-account-password-policy --minimum-password-length 14
    ```
    Note: Note: All commands starting with \"aws iam update-account-password-policy\" can be combined into a single command.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'SA-3 a']
  tag cci:                   ['CCI-000200', 'CCI-000615']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0208r1_rule'
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
    it                              { should exist }
    its('minimum_password_length')  { should cmp >= 14 }
  end
end
