# encoding: UTF-8

control 'C-2.10' do
  title 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password'
  desc  "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional credentials. With MFA enabled, when a user signs in to the AWS Console, they are prompted for their username and password as well as an authentication code from their physical or virtual MFA device. It is recommended that MFA be enabled for all IAM users that have a console password.

    Enabling MFA increases security for console access by requiring the authenticating principal to possess a device that generates a time-sensitive authentication code, in addition to their credentials.
  "
  desc  'rationale', "
    Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional credentials. With MFA enabled, when a user signs in to the AWS Console, they are prompted for their username and password as well as an authentication code from their physical or virtual MFA device. It is recommended that MFA be enabled for all IAM users that have a console password.

    Enabling MFA increases security for console access by requiring the authenticating principal to possess a device that generates a time-sensitive authentication code, in addition to their credentials.
  "
  desc  'check', "
    Perform the following to determine if a MFA device is enabled for all IAM users having a console password:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. In the left pane, select `Users` 
    3. If the `MFA`  or `Password age`  columns are not visible, click the gear icon in the upper right corner and enable them
    4. Ensure that for each user where the `Password age` column shows a value, the `MFA`  column shows `Virtual`, `U2F Security Key`, or `Hardware`.

    From Command Line:

    1. Run the following command:
    ```
      aws iam generate-credential-report
    ```
    ```
      aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,8 
    ```
    2. The output of this command will produce a table similar to the following:
    ```
      user,password_enabled,mfa_active
      elise,false,false
      brandon,true,true
      rakesh,false,false
      helene,false,false
      paras,true,true
      anitha,false,false   
    ```
    3. For any column having `password_enabled`  set to `true` , ensure `mfa_active`  is also set to `true.`
  "
  desc  'fix', "
    Perform the following to enable MFA:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at 'https://console.aws.amazon.com/iam/'
    2. In the left pane, select `Users`.
    3. Select the IAM user
    4. Choose the `Security credentials` tab
    5. Under `Multi-factor authentication (MFA)`, select `Assign MFA device`
    6. Select `Virtual MFA device` (or hardware/security key as applicable), then choose `Continue`
    7. Configure the MFA device by:
    - Scanning the QR code, or
    - Entering the secret key manually
    8. Enter two consecutive authentication codes
    9. Select `Assign MFA`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-2 (2)']
  tag nist_r4:               ['IA-2 (2)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000766']
  tag cis_number:            '2.10'
  tag cis_rid:               '2.10'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0210r1_rule'
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

  # Enforce MFA only on users who actually have a console password.
  # Use the named-argument form (`user_name:`) so inspec-aws resolves
  # the resource instead of InSpec core's removed stub.
  aws_iam_users.usernames.each do |username|
    user = aws_iam_user(user_name: username)
    next unless user.has_console_password

    describe user do
      it { should have_mfa_enabled }
    end
  end
end
