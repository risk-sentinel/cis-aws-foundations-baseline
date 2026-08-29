# encoding: UTF-8

control 'C-6.2' do
  title 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports'
  desc  "
    The Network Access Control List (NACL) function provides stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH on port `22` and RDP on port `3389`, using either the TCP (6), UDP (17), or ALL (-1) protocols.

    Public access to remote server administration ports, such as 22 (when used for SSH, not SFTP) and 3389, increases the attack surface of resources and unnecessarily raises the risk of resource compromise.
  "
  desc  'rationale', "
    The Network Access Control List (NACL) function provides stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH on port `22` and RDP on port `3389`, using either the TCP (6), UDP (17), or ALL (-1) protocols.

    Public access to remote server administration ports, such as 22 (when used for SSH, not SFTP) and 3389, increases the attack surface of resources and unnecessarily raises the risk of resource compromise.
  "
  desc  'check', "
    From Console:

    Perform the following steps to determine if the account is configured as prescribed:

    1. Login to the AWS VPC Console at https://console.aws.amazon.com/vpc/home.
    2. In the left pane, click `Network ACLs`.
    3. For each network ACL, check whether it is associated with one or more subnets.
    4. If it is associated, proceed to Step 5
    5. If it is not associated, you may still review the rules, but note it has no effect until attached
    6. Select the network ACL
    7. Click the Inbound Rules tab
    8. Ensure that no rule exists which has a port range that includes port 22 or 3389, uses the protocols TCP (6), UDP (17), or ALL (-1), or other remote server administration ports for your environment, has a Source of 0.0.0.0/0, and shows ALLOW

    Note:
    - A port value of ALL or a port range such as 0-3389 includes port 22, 3389, and potentially other remote server administration ports
    - An effective ruleset that explicitly DENIES access to these ports (e.g., a DENY rule for ports 22 and 3389 from 0.0.0.0/0 placed before a broader ALLOW rule such as ANY/ANY) is considered acceptable, as NACLs are evaluated in order and the DENY rule will take precedence
  "
  desc  'fix', "
    From Console:

    Perform the following steps to remediate a network ACL:

    1. Login to the AWS VPC Console at https://console.aws.amazon.com/vpc/home.
    2. In the left pane, click `Network ACLs`.
    3. For each network ACL that needs remediation, perform the following:
    4. Select the network ACL.
    5. Click the `Inbound Rules` tab.
    6. Click `Edit inbound rules`.
    7. Either 
    A) update the Source field to a range other than 0.0.0.0/0
    B) click `Delete` to remove the offending inbound rule or
    C) Add an explicit DENY rule for the affected ports (e.g., 22, 3389) from 0.0.0.0/0 with a lower rule number than any broader ALLOW rule
    8. Click `Save`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (11)', 'PM-5']
  tag nist_r4:               ['PM-5', 'SI-4 (11)']
  tag cci:                   ['CCI-002668', 'CCI-000207']
  tag cis_number:            '6.2'
  tag cis_rid:               '6.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0602r1_rule'
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

  describe aws_network_acls_admin_ingress(admin_ports: [22, 3389]) do
    its('violations') { should be_empty }
  end
end
