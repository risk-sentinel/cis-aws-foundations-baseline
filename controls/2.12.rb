# encoding: UTF-8

control 'C-2.12' do
  title 'Ensure access keys are rotated every 90 days or less'
  desc  "
    Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests to AWS. IAM users require access keys to make programmatic calls via the AWS CLI, SDKs, or APIs. It is recommended that all access keys be rotated regularly and at least every 90 days.

    Rotating access keys reduces the window of opportunity for a compromised or exposed key to be used. Regular rotation also limits the risk associated with lost, stolen, or improperly stored credentials.
  "
  desc  'rationale', "
    Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests to AWS. IAM users require access keys to make programmatic calls via the AWS CLI, SDKs, or APIs. It is recommended that all access keys be rotated regularly and at least every 90 days.

    Rotating access keys reduces the window of opportunity for a compromised or exposed key to be used. Regular rotation also limits the risk associated with lost, stolen, or improperly stored credentials.
  "
  desc  'check', "
    Perform the following to determine if access keys are rotated as prescribed:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Click on `Users`
    3. For each user, go to `Security Credentials`
    4. Review each key under `Access Keys`
    5. For each key with `Status = Active`, ensure the `Created` date is within `90 days`

    From Command Line:

    1. Run the following commands:

    ```
    aws iam generate-credential-report
    aws iam get-credential-report --query 'Content' --output text | base64 -d
    ```

    2. Review the following fields:
    - access_key_1_last_rotated
    - access_key_2_last_rotated

    3. Ensure all active keys have been rotated within `90 days`
  "
  desc  'fix', "
    Perform the following to rotate access keys:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console (https://console.aws.amazon.com/iam)
    2. Click on `Users`
    3. Select the user
    4. Navigate to `Security credentials`

    Rotate Access Keys:

    5. Click `Create access` key
    6. Update all applications and tools to use the new access key
    7. After confirming successful use of the new key:
    - Deactivate the old key
    - Delete the old key when no longer needed

    From Command Line:

    1. Create a new access key:
    ```
    aws iam create-access-key --user-name ```
    2. Update all applications and tools to use the new access key
    3. Check usage of the old key:
    ```
    aws iam get-access-key-last-used --access-key-id ```
    4. Deactivate the old key:
    ```
    aws iam update-access-key --access-key-id --status Inactive --user-name ```
    5. After confirming no usage, delete the old key:
    ```
    aws iam delete-access-key --access-key-id --user-name ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a', 'SA-3 a']
  tag nist_r4:               ['AC-2 a', 'SA-3 a']
  tag cci:                   ['CCI-002110', 'CCI-000615']
  tag cis_number:            '2.12'
  tag cis_rid:               '2.12'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0212r1_rule'
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
  # Rotation in AWS = delete-and-create-new; an active key older than 90
  # days has not been rotated.
  describe aws_iam_access_keys.where(active: true).where { created_days_ago > 90 } do
    it { should_not exist }
  end

  # pure_sso addition: active long-lived access keys are only allowed for
  # declared service accounts. Hybrid / legacy_iam skip this.
  if input('iam_access_model') == 'pure_sso'
    allowed = Array(input('iam_service_account_usernames'))
    describe aws_iam_access_keys.where(active: true).where { !allowed.include?(username) } do
      it { should_not exist }
    end
  end
end
