# encoding: UTF-8

control 'C-5.16' do
  title 'Ensure AWS Security Hub is enabled'
  desc  "
    Security Hub collects security data from various AWS accounts, services, and supported third-party partner products, helping you analyze your security trends and identify the highest-priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from the AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products.

    AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices, enabling you to quickly assess the security posture across your AWS accounts.
  "
  desc  'rationale', "
    Security Hub collects security data from various AWS accounts, services, and supported third-party partner products, helping you analyze your security trends and identify the highest-priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from the AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products.

    AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices, enabling you to quickly assess the security posture across your AWS accounts.
  "
  desc  'check', "
    Follow this process to evaluate AWS Security Hub configuration per region:

    From Console:

    1. Sign in to the AWS Management Console and open the AWS Security Hub console at https://console.aws.amazon.com/securityhub/.
    2. On the top right of the console, select the target Region.
    3. If the Security Hub > Summary page is displayed, then Security Hub is set up for the selected region.
    4. If presented with \"Setup Security Hub\" or \"Get Started With Security Hub,\" refer to the remediation steps.
    5. Repeat steps 2 to 4 for each region.

    From Command Line:

    Run the following command to verify the Security Hub status:

    ```
    aws securityhub describe-hub
    ```

    This will list the Security Hub status by region. Check for a 'SubscribedAt' value.

    Example output:

    ```
    {
        \"HubArn\": \" \",
        \"SubscribedAt\": \"2022-08-19T17:06:42.398Z\",
        \"AutoEnableControls\": true
    }
    ```

    An error will be returned if Security Hub is not enabled.

    Example error:

    ```
    An error occurred (InvalidAccessException) when calling the DescribeHub operation: Account is not subscribed to AWS Security Hub
    ```
  "
  desc  'fix', "
    To grant the permissions required to enable Security Hub, attach the Security Hub managed policy `AWSSecurityHubFullAccess` to an IAM user, group, or role.

    Enabling Security Hub:

    From Console:

    1. Use the credentials of the IAM identity to sign in to the Security Hub console.
    2. When you open the Security Hub console for the first time, choose `Go to Security Hub`.
    3. The `Security standards` section on the welcome page lists supported security standards. Check the box for a standard to enable it.
    3. Choose `Enable Security Hub`.

    From Command Line:

    1. Run the `enable-security-hub` command, including `--enable-default-standards` to enable the default standards:

    ```
    aws securityhub enable-security-hub --enable-default-standards
    ```

    2. To enable Security Hub without the default standards, include `--no-enable-default-standards`:
    ```
    aws securityhub enable-security-hub --no-enable-default-standards
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['RA-5 a', 'SC-28']
  tag ksi:                   ['KSI-SCR-MON', 'KSI-SVC-SIN']
  tag nist_r4:               ['RA-5 a', 'SC-28']
  tag cci:                   ['CCI-001055', 'CCI-001199']
  tag cis_number:            '5.16'
  tag cis_rid:               '5.16'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0516r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_role      = input('log_archive_account_id').to_s.empty? || in_log_archive_account?
  applicable_required  = input('security_hub_required') == true
  applicable           = applicable_partition && applicable_role && applicable_required

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, log_archive_account=#{input('log_archive_account_id')}, current_account=#{current_account_id}, security_hub_required=#{input('security_hub_required')})") do
    applicable
  end

  # Local override `aws_security_hub_subscription` (libraries/) catches
  # the not-subscribed case (InvalidAccessException) and exposes it as
  # `not_subscribed?` + `connection_error` instead of letting the SDK
  # error bubble up as an Inspec WARN. The vendored aws_securityhub_hub
  # produces the WARN; this wrapper produces a clean FAIL.
  describe aws_security_hub_subscription do
    it { should be_subscribed }
  end
end
