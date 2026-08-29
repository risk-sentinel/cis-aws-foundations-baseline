# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure MFA is enabled for the \'root\' user account'
  desc  "
    The 'root' user account is the most privileged user in an AWS account. Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a username and password. With MFA enabled, when a user signs in to an AWS website, they are prompted for their username and password as well as an authentication code from their MFA device.

    Note: When virtual MFA is used for 'root' accounts, it is recommended that the device used is not a personal device, but rather a dedicated mobile device (tablet or phone) that is kept charged and secured, independent of any individual (\"non-personal virtual MFA\"). This reduces the risk of losing access to MFA due to device loss, device replacement, or employee turnover.

    Where an AWS Organization is using centralized root access, root credentials can be removed from member accounts. In that case, it is neither possible nor necessary to configure root MFA in the member account.

    Enabling MFA increases security for console access by requiring the authenticating principal to possess a device that generates a time-sensitive authentication code, in addition to their credentials.
  "
  desc  'rationale', "
    The 'root' user account is the most privileged user in an AWS account. Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a username and password. With MFA enabled, when a user signs in to an AWS website, they are prompted for their username and password as well as an authentication code from their MFA device.

    Note: When virtual MFA is used for 'root' accounts, it is recommended that the device used is not a personal device, but rather a dedicated mobile device (tablet or phone) that is kept charged and secured, independent of any individual (\"non-personal virtual MFA\"). This reduces the risk of losing access to MFA due to device loss, device replacement, or employee turnover.

    Where an AWS Organization is using centralized root access, root credentials can be removed from member accounts. In that case, it is neither possible nor necessary to configure root MFA in the member account.

    Enabling MFA increases security for console access by requiring the authenticating principal to possess a device that generates a time-sensitive authentication code, in addition to their credentials.
  "
  desc  'check', "
    Perform the following to determine if the 'root' user account has MFA configured:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Click on `Credential Report` 
    3. Download the `.csv` file containing credential usage for all IAM users within an AWS Account 
    4. Open this file
    5. For the `root` user, ensure:
    - `mfa_active` is set to `TRUE`, or
    - `password_enabled` is set to `FALSE`


    From Command Line:

    1. Run the following command:
    ```
      aws iam get-account-summary | grep \"AccountMFAEnabled\"
      aws iam get-account-summary | grep \"AccountPasswordPresent\"
    ```
    2. Ensure:
    - `AccountMFAEnabled` property is set to 1, or
    - `AccountPasswordPresent` property is set to 0
  "
  desc  'fix', "
    Note: To manage MFA devices for the 'root' AWS account, you must use root credentials. MFA cannot be managed for the root account using IAM users or roles.

    Perform the following to establish MFA for the 'root' user account:

    From Console:

    1. Sign in to the AWS Management Console using the root user email 
    2. In the top right corner, click the account name
    3. Choose `Security Credentials` 
    4. Under the `Multi-Factor authentication (MFA)`, locate the root user
    5. Choose `Assign MFA device` (or Activate MFA, depending on UI version)
    6. Select `Virtual MFA device`
    7. Choose one of the following:
    - Scan the QR code using your MFA app, or
    - Select Show secret key for manual configuration and enter it into your MFA app
    8. Enter the first authentication code in Authentication Code 1
    9. Wait for a new code, then enter it in Authentication Code 2
    10. Click `Assign Virtual MFA`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-2 (2)']
  tag cci:                   ['CCI-001097', 'CCI-000766']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0205r1_rule'
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
    it { should have_mfa_enabled }
  end
end
