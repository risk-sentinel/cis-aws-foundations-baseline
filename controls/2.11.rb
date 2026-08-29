# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure credentials unused for 45 days or more are disabled'
  desc  "
    AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused for 45 days or more be deactivated or removed.

    Disabling or removing unused credentials reduces the window of opportunity for credentials associated with a compromised or abandoned account to be used.
  "
  desc  'rationale', "
    AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused for 45 days or more be deactivated or removed.

    Disabling or removing unused credentials reduces the window of opportunity for credentials associated with a compromised or abandoned account to be used.
  "
  desc  'check', "
    Perform the following to determine if unused credentials exist:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Click on `Users`
    3. Click the `Settings` (gear) icon
    4. Select `Console last sign-in`, `Access key last used`, and `Access Key Id`
    5. Click on `Confirm` 
    6. Check and ensure that `Console last sign-in` is less than 45 days ago.

    Note - `-` means the user has never logged in.

    7. If credentials have not been used within 45 days, refer to remediation


    From Command Line:

    Remove Access Key:

    1. Generate and review the credential report:
    ```
    aws iam generate-credential-report
    aws iam get-credential-report --query 'Content' --output text | base64 -d
    ```
    2. Review the following fields:
    - password_last_used
    - access_key_1_last_used_date
    - access_key_2_last_used_date

    3. Identify any credentials unused for 45 days or more
  "
  desc  'fix', "
    From Console:

    Perform the following to deactivate or remove unused credentials:

    1. Login to the AWS Management Console and open the IAM console
    2. Click on the `User` 
    3. Select the user 
    4. Click `Security Credentials`

    Disable Console Access:

    5. In the Console sign-in section, select Manage console access
    6. If Console last sign-in is greater than 45 days, select Disable access

    Deactivate or Delete Access Keys:

    7. In the Access keys section:
    - Deactivate unused keys, or
    - Delete keys that are no longer required

    From Command Line:

    1. Delete unused access keys:
    ```
    aws iam delete-access-key --access-key-id --user-name ```
    2. Remove console access:
    ```
    aws iam delete-login-profile --user-name ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'SA-8']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-PIY-RSD']
  tag nist_r4:               ['AC-2 f', 'SA-8']
  tag cci:                   ['CCI-000011', 'CCI-000664']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0211r1_rule'
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

  # CIS baseline — runs in all access models.
  # FilterTable .where blocks see registered column names verbatim — for
  # aws_iam_users that's `has_console_password` (no trailing ?), even
  # though the resource exposes a `has_console_password?` alias at the
  # class level. Using the column form here avoids NoMethodError on the
  # FilterTable row class.
  describe aws_iam_users.where { has_console_password && password_ever_used? && password_last_used_days_ago > 45 } do
    it { should_not exist }
  end

  describe aws_iam_access_keys.where(active: true).where { ever_used && last_used_days_ago > 45 } do
    it { should_not exist }
  end

  # pure_sso addition: no IAM users with console passwords at all.
  # Hybrid / legacy_iam skip this — baseline already covers stale-credential risk.
  if input('iam_access_model') == 'pure_sso'
    describe aws_iam_users.where { has_console_password } do
      it { should_not exist }
    end
  end
end
