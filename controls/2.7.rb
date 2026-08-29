# encoding: UTF-8

control 'C-2.7' do
  title 'Eliminate use of the \'root\' user for administrative and daily tasks'
  desc  "
    With the creation of an AWS account, a 'root user' is created that cannot be disabled or deleted. This user has unrestricted access to and control over all resources in the AWS account. It is highly recommended that the use of this account be avoided for everyday tasks.

    The 'root user' has unrestricted access to and control over all account resources. Use of this account is inconsistent with the principles of least privilege and separation of duties and can lead to unnecessary harm due to user error or account compromise.
  "
  desc  'rationale', "
    With the creation of an AWS account, a 'root user' is created that cannot be disabled or deleted. This user has unrestricted access to and control over all resources in the AWS account. It is highly recommended that the use of this account be avoided for everyday tasks.

    The 'root user' has unrestricted access to and control over all account resources. Use of this account is inconsistent with the principles of least privilege and separation of duties and can lead to unnecessary harm due to user error or account compromise.
  "
  desc  'check', "
    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. In the left pane, click `Credential Report`
    3. Select `Download Report`
    4. Open or Save the file locally
    5. Locate the `root` user under the user column
    6. Review:
    - `password_last_used`
    - `access_key_1_last_used_date`
    - `access_key_2_last_used_date`
    7. Determine whether recent usage indicates frequent or inappropriate use of the root account
    8. Ensure the `mfa_active` field is set to `TRUE` or the `password_enabled` field is set to `FALSE`

    From Command Line:

    1. Run the following CLI commands to provide a credential report for determining the last time the 'root user' was used:
    ```
    aws iam generate-credential-report
    ```
    ```
    aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 ' '
    ```

    2. Review:
    - `password_last_used`
    - `access_key_1_last_used_date`
    - `access_key_2_last_used_date`

    3. Determine when the root user was last used

    Note: There are limited scenarios where use of the 'root' user is required. Refer to AWS documentation for a complete list.
  "
  desc  'fix', "
    If the 'root' user account is being used for daily activities or administrative tasks that do not require root access:

    1. Stop using the root account for routine operations
    2. Create and use IAM roles or users with least privilege instead
    3. Change the root user password
    4. Deactivate or delete any access keys associated with the root user

    From Command Line:

    1. Run the following command as the root user in the account to delete the root login profile:
    ```
    aws iam delete-login-profile
    ```
    This removes the password associated with the root account and prevents console authentication using the root user.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag nist_r4:               ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '2.7'
  tag cis_rid:               '2.7'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0207r1_rule'
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

  threshold = Integer(input('root_user_recent_use_threshold_days'))

  describe aws_iam_root_user do
    it "should not have been used in the last #{threshold} days" do
      expect(subject.used_recently?(within_days: threshold)).to eq(false)
    end
  end
end
