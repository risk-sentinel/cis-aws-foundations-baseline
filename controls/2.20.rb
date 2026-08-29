# encoding: UTF-8

control 'C-2.20' do
  title 'Ensure access to AWSCloudShellFullAccess is restricted'
  desc  "
    AWS CloudShell is a convenient way of running CLI commands against AWS services. The managed IAM policy `AWSCloudShellFullAccess` provides full access to CloudShell, including file upload and download capability between a user's local system and the CloudShell environment. Within the CloudShell environment, a user has sudo permissions and can access the internet. It is therefore possible to install software and transfer data to external systems.

    Access to this policy should be restricted, as it presents a potential channel for data exfiltration by privileged users. AWS documentation provides guidance on creating more restrictive policies that limit file transfer capabilities.
  "
  desc  'rationale', "
    AWS CloudShell is a convenient way of running CLI commands against AWS services. The managed IAM policy `AWSCloudShellFullAccess` provides full access to CloudShell, including file upload and download capability between a user's local system and the CloudShell environment. Within the CloudShell environment, a user has sudo permissions and can access the internet. It is therefore possible to install software and transfer data to external systems.

    Access to this policy should be restricted, as it presents a potential channel for data exfiltration by privileged users. AWS documentation provides guidance on creating more restrictive policies that limit file transfer capabilities.
  "
  desc  'check', "
    From Console

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. In the left pane, select `Policies`
    3. Search for and select `AWSCloudShellFullAccess`
    4. Select the `Entities attached` tab
    5. Ensure that no users, groups, or roles are attached

    From Command Line

    1. Run the following command:

    ```
    aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess
    ```

    2. In the output, ensure the following are empty:
    - PolicyUsers
    - PolicyRoles
    - PolicyGroups

    Example: 
    ```
    PolicyRoles: [ ]
    ```
  "
  desc  'fix', "
    From Console
    1. Open the IAM console at https://console.aws.amazon.com/iam/
    2. In the left pane, select `Policies`
    3. Search for and select `AWSCloudShellFullAccess`
    4. Select the `Entities attached` tab
    5. For each attached entity:
    - Select the entity
    - Choose Detach

    From Command Line (optional automation):

    ```
    POLICY_ARN=\"arn:aws:iam::aws:policy/AWSCloudShellFullAccess\"

    # Detach from users
    for u in $(aws iam list-entities-for-policy --policy-arn \"$POLICY_ARN\" --query \"PolicyUsers[].UserName\" --output text); do
      echo \"Detaching from user: $u\"
      aws iam detach-user-policy --user-name \"$u\" --policy-arn \"$POLICY_ARN\"
    done

    # Detach from roles
    for r in $(aws iam list-entities-for-policy --policy-arn \"$POLICY_ARN\" --query \"PolicyRoles[].RoleName\" --output text); do
      echo \"Detaching from role: $r\"
      aws iam detach-role-policy --role-name \"$r\" --policy-arn \"$POLICY_ARN\"
    done

    # Detach from groups
    for g in $(aws iam list-entities-for-policy --policy-arn \"$POLICY_ARN\" --query \"PolicyGroups[].GroupName\" --output text); do
      echo \"Detaching from group: $g\"
      aws iam detach-group-policy --group-name \"$g\" --policy-arn \"$POLICY_ARN\"
    done
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 i 1', 'AC-8 a']
  tag nist_r4:               ['AC-2 i 1']
  tag cci:                   ['CCI-002126', 'CCI-000051']
  tag cis_number:            '2.20'
  tag cis_rid:               '2.20'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0220r1_rule'
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

  # AWSCloudShellFullAccess is the overbroad managed policy. A best-
  # effort check: the managed policy should not be attached to any
  # entity (users, groups, roles).
  describe aws_iam_policy(policy_arn: 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess') do
    its('attachment_count') { should eq 0 }
  end
end
