# encoding: UTF-8

control 'C-6.3' do
  title 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports'
  desc  "
    Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH on port `22` and RDP on port `3389`, using either the TCP (6), UDP (17), or ALL (-1) protocols.

    Public access to remote server administration ports, such as 22 (when used for SSH, not SFTP) and 3389, increases the attack surface of resources and unnecessarily raises the risk of resource compromise.
  "
  desc  'rationale', "
    Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports, such as SSH on port `22` and RDP on port `3389`, using either the TCP (6), UDP (17), or ALL (-1) protocols.

    Public access to remote server administration ports, such as 22 (when used for SSH, not SFTP) and 3389, increases the attack surface of resources and unnecessarily raises the risk of resource compromise.
  "
  desc  'check', "
    Perform the following to determine if the account is configured as prescribed:

    1. Login to the AWS VPC Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home).
    2. In the left pane, click `Security Groups`.
    3. For each security group, perform the following:
        - Select the security group.
        - Click the `Inbound Rules` tab.
        - Ensure that no rule exists which has a port range including port `22` or `3389`, uses the protocols TCP (6), UDP (17), or ALL (-1), or other remote server administration ports for your environment, and has a `Source` of `0.0.0.0/0`.


    Note

    A port value of ALL or a port range such as 0-3389 includes port 22, 3389, and potentially other remote server administration ports

    Security groups are stateful and do not support explicit DENY rules. Therefore, an \"effective ruleset\" approach (e.g., allowing ANY/ANY but denying specific ports) is not applicable. Any rule that allows 0.0.0.0/0 access to administrative ports is considered non-compliant and must be removed or restricted
  "
  desc  'fix', "
    From Console:

    Perform the following to implement the prescribed state:

    1. Login to the AWS VPC Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home).
    2. In the left pane, click `Security Groups`.
    3. For each security group, perform the following:
        - Select the security group.
        - Click the `Inbound Rules` tab.
        - Click the `Edit inbound rules` button.
    4. Identify the rules to be edited or removed.
    5. Either:
    A) update the Source field to a range other than 0.0.0.0/0, or 
    B) click `Delete` to remove the offending inbound rule.
        - Click `Save rules`.

    From Command Line:

    1. Check all security groups for insecure inbound rules allowing traffic from 0.0.0.0/0:

    ```
    aws ec2 describe-security-group-rules --query 'SecurityGroupRules[?CidrIpv4 == \"0.0.0.0/0\" && IsEgress == `false`]' --output json
    ```

    2. Delete the insecure rule(s) based on their rule ID:

    ```
    aws ec2 delete-security-group-rules --group-id --security-group-rule-ids ```

    3. Recreate necessary security group rules:

    ```
    aws ec2 authorize-security-group-ingress --group-id --protocol --port --cidr ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag nist_r4:               ['SC-18 (4)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_number:            '6.3'
  tag cis_rid:               '6.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0603r1_rule'
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

  # No SG may permit 22 (SSH) or 3389 (RDP) ingress from the public
  # internet. Check both admin ports per SG.
  aws_security_groups.entries.each do |sg|
    describe aws_security_group(group_id: sg.group_id) do
      it { should_not allow_in(port: 22,   ipv4_range: '0.0.0.0/0') }
      it { should_not allow_in(port: 3389, ipv4_range: '0.0.0.0/0') }
    end
  end
end
