# encoding: UTF-8

control 'C-6.5' do
  title 'Ensure the default security group of every VPC restricts all traffic'
  desc  "
    A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If a security group is not specified when an instance is launched, it is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic, both inbound and outbound.

    The default VPC in every region should have its default security group updated to comply with the following:

     - No inbound rules.
     - No outbound rules.

    Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation.


    Note: When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly, as it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering by discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups.

    Configuring all VPC default security groups to restrict all traffic will encourage the development of least privilege security groups and promote the mindful placement of AWS resources into security groups, which will, in turn, reduce the exposure of those resources.
  "
  desc  'rationale', "
    A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If a security group is not specified when an instance is launched, it is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic, both inbound and outbound.

    The default VPC in every region should have its default security group updated to comply with the following:

     - No inbound rules.
     - No outbound rules.

    Any newly created VPCs will automatically contain a default security group that will need remediation to comply with this recommendation.


    Note: When implementing this recommendation, VPC flow logging is invaluable in determining the least privilege port access required by systems to work properly, as it can log all packet acceptances and rejections occurring under the current security groups. This dramatically reduces the primary barrier to least privilege engineering by discovering the minimum ports required by systems in the environment. Even if the VPC flow logging recommendation in this benchmark is not adopted as a permanent security measure, it should be used during any period of discovery and engineering for least privileged security groups.

    Configuring all VPC default security groups to restrict all traffic will encourage the development of least privilege security groups and promote the mindful placement of AWS resources into security groups, which will, in turn, reduce the exposure of those resources.
  "
  desc  'check', "
    Perform the following to determine if the account is configured as prescribed:

    Security Group State

    1. Login to the AWS VPC Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home).
    2. Repeat the following steps for all VPCs, including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`.
    4. For each default security group, perform the following:
        - Select the `default` security group.
        - Click the `Inbound Rules` tab and ensure no rules exist.
        - Click the `Outbound Rules` tab and ensure no rules exist.


    Security Group Members

    1. Login to the AWS VPC Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home).
    2. Repeat the following steps for all default groups in all VPCs, including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`.
    4. Copy the ID of the default security group.
    5. Change to the EC2 Management Console at https://console.aws.amazon.com/ec2/v2/home.
    6. In the filter column type `Security Group ID : `.
  "
  desc  'fix', "
    Perform the following to implement the prescribed state:

    Security Group Members

    1. Identify AWS resources that exist within the default security group.
    2. Create a set of least-privilege security groups for those resources.
    3. Place the resources in those security groups, removing the resources noted in step 1 from the default security group.

    From Console:

    1. Login to the AWS VPC Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home).
    2. Repeat the following steps for all VPCs, including the default VPC in each AWS region:
    3. In the left pane, click `Security Groups`.
    4. For each default security group, perform the following:
        - Select the `default` security group.
        - Click the `Inbound Rules` tab.
        - Remove any inbound rules.
        - Click the `Outbound Rules` tab.
        - Remove any Outbound rules.

    From Command Line:

    1. List all default security groups in the specified region

    ```
    aws ec2 describe-security-groups --region --query 'SecurityGroups[?GroupName == `default`]'
    ```

    2. Check if the inbound rules (IpPermissions) and outbound rules (IpPermissionsEgress) of the default security group are empty. If the rules are not empty, proceed and note down the Security Group ID (GroupId) of the security group with non-empty rules.

    3. List the inbound security group rule IDs (SecurityGroupRuleId)

    ```
    aws ec2 describe-security-group-rules --region --query 'SecurityGroupRules[?GroupId == ` ` && IsEgress == `false`]'
    ```

    4. Delete the inbound security group rules based on their rule IDs

    ```
    aws ec2 revoke-security-group-ingress --group-id --security-group-rule-ids ```

    5. List the outbound security group rule IDs (SecurityGroupRuleId)

    ```
    aws ec2 describe-security-group-rules --region --query 'SecurityGroupRules[?GroupId == ` ` && IsEgress == `true`]'
    ```

    6. Delete the outbound security group rules based on their rule IDs

    ```
    aws ec2 revoke-security-group-egress --group-id --security-group-rule-ids ```

    Recommended

    IAM groups allow you to edit the \"name\" field. After remediating default group rules for all VPCs in all regions, edit this field to add text similar to \"DO NOT USE. DO NOT ADD RULES.\"
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'SC-7 a', 'SC-18 (4)', 'AC-8 a']
  tag nist_r4:               ['AC-3', 'SC-18 (4)', 'SC-7 a']
  tag cci:                   ['CCI-000213', 'CCI-001097', 'CCI-002460', 'CCI-000051']
  tag cis_number:            '6.5'
  tag cis_rid:               '6.5'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0605r1_rule'
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

  # Every VPC's "default" security group must have no inbound and no
  # outbound rules — AWS creates it pre-populated, so operators must
  # explicitly revoke the defaults.
  aws_security_groups.entries.select { |sg| sg.group_name == 'default' }.each do |sg|
    describe aws_security_group(group_id: sg.group_id) do
      its('inbound_rules')  { should be_empty }
      its('outbound_rules') { should be_empty }
    end
  end
end
