# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure no \'root\' user account access key exists'
  desc  "
    The 'root' user account is the most privileged user in an AWS account. AWS access keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the 'root' user account be deleted.

    Deleting access keys associated with the 'root' user account limits the vectors by which the account can be compromised. Additionally, removing 'root' access keys encourages the use of role-based access with least privilege.
  "
  desc  'rationale', "
    The 'root' user account is the most privileged user in an AWS account. AWS access keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the 'root' user account be deleted.

    Deleting access keys associated with the 'root' user account limits the vectors by which the account can be compromised. Additionally, removing 'root' access keys encourages the use of role-based access with least privilege.
  "
  desc  'check', "
    Perform the following to determine if the 'root' user account has access keys:

    From Console:

    1. Login to the IAM Management Console (https://console.aws.amazon.com/iam)
    2. Click on `Credential Report`.
    3. Download the `.csv` file which contains credential usage for all IAM users within an AWS Account
    4. Open the file
    5. For the `root` user, ensure the `access_key_1_active` and `access_key_2_active` fields are set to `FALSE`.

    From Command Line:

    1. Run the following command:
    ```
    aws iam get-account-summary | grep \"AccountAccessKeysPresent\"  
    ```
    2. If no 'root' access keys exist the output will show `\"AccountAccessKeysPresent\": 0,`  

    3. If the output shows a \"1\", then 'root' keys exist and should be deleted
  "
  desc  'fix', "
    Perform the following to delete active 'root' user access keys.

    From Console:

    1. Sign in to the AWS Management Console as 'root' and open the IAM console at [https://console.aws.amazon.com/iam/](https://console.aws.amazon.com/iam/)
    2. Click on ` ` at the top right and select `Security Credentials` from the drop down list
    3. Click on `Access Keys` (Access Key ID and Secret Access Key)
    4. If there are active keys:
    - Deactivate the key under `Status`
    - Click `Delete` (Deleted keys cannot be recovered)

    Note: While a key can be made inactive, it will still appear in CLI audit output and may result in a false positive. Keys should be deleted to ensure compliance.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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

  describe aws_iam_root_user do
    it { should_not have_access_key }
  end
end
