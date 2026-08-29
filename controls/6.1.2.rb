# encoding: UTF-8

control 'C-6.1.2' do
  title 'Ensure CIFS access is restricted to trusted networks to prevent unauthorized access'
  desc  "
    Common Internet File System (CIFS) is a network file-sharing protocol that allows systems to share files over a network. However, unrestricted CIFS access can expose your data to unauthorized users, leading to potential security risks. It is important to restrict CIFS access to only trusted networks and users to prevent unauthorized access and data breaches.

    Allowing unrestricted CIFS access can lead to significant security vulnerabilities, as it may allow unauthorized users to access sensitive files and data. By restricting CIFS access to known and trusted networks, you can minimize the risk of unauthorized access and protect sensitive data from exposure to potential attackers. Implementing proper network access controls and permissions is essential for maintaining the security and integrity of your file-sharing systems.
  "
  desc  'rationale', "
    Common Internet File System (CIFS) is a network file-sharing protocol that allows systems to share files over a network. However, unrestricted CIFS access can expose your data to unauthorized users, leading to potential security risks. It is important to restrict CIFS access to only trusted networks and users to prevent unauthorized access and data breaches.

    Allowing unrestricted CIFS access can lead to significant security vulnerabilities, as it may allow unauthorized users to access sensitive files and data. By restricting CIFS access to known and trusted networks, you can minimize the risk of unauthorized access and protect sensitive data from exposure to potential attackers. Implementing proper network access controls and permissions is essential for maintaining the security and integrity of your file-sharing systems.
  "
  desc  'check', "
    From Console:

    1. Login to the AWS Management Console.
    2. Navigate to the EC2 Dashboard and select the Security Groups section under `Network & Security`.
    3. Identify the security groups associated with instances or resources that may be using CIFS.
    4. Review the inbound rules of each security group to check for rules that allow unrestricted access on port 445 (the port used by CIFS).
       - Specifically, look for inbound rules that allow access from `0.0.0.0/0` or `::/0` on port 445.
    5. Document any instances where unrestricted access is allowed and verify whether it is necessary for the specific use case.

    From Command Line:

    1. Run the following command to list all security groups and identify those associated with CIFS:
       ```
       aws ec2 describe-security-groups --region --query 'SecurityGroups[*].GroupId'
       ```
    2. Check for any inbound rules that allow unrestricted access on port 445 using the following command:
       ```
       aws ec2 describe-security-groups --region < region-name > --group-ids < security-group-id > --query \"SecurityGroups[*].IpPermissions[?((IpProtocol=='-1') || (FromPort<=\\`445\\` && ToPort>=\\`445\\`))].{IpProtocol:IpProtocol,FromPort:FromPort,ToPort:ToPort,CIDRv4:IpRanges[*].CidrIp,CIDRv6:Ipv6Ranges[*].CidrIpv6}\"
       ```
       - Look for `0.0.0.0/0` or `::/0` in the output, which indicates unrestricted access.

    3. Repeat the audit for other regions and security groups as necessary.
  "
  desc  'fix', "
    From Console:

    1. Login to the AWS Management Console.
    2. Navigate to the EC2 Dashboard and select the Security Groups section under `Network & Security`.
    3. Identify the security group that allows unrestricted ingress on port 445.
    4. Select the security group and click the `Edit Inbound Rules` button.
    5. Locate the rule allowing unrestricted access on port 445 (typically listed as `0.0.0.0/0` or `::/0`).
    6. Modify the rule to restrict access to specific IP ranges or trusted networks only.
    7. Save the changes to the security group.

    From Command Line:

    1. Run the following command to remove or modify the unrestricted rule for CIFS access:
       ```
       aws ec2 revoke-security-group-ingress --region --group-id --protocol tcp --port 445 --cidr 0.0.0.0/0
       ```
       - Optionally, run the `authorise-security-group-ingress` command to create a new rule, specifying a trusted CIDR range instead of `0.0.0.0/0`.

    2. Confirm the changes by describing the security group again and ensuring the unrestricted access rule has been removed or appropriately restricted:
       ```
       aws ec2 describe-security-groups --region --group-ids --query \"SecurityGroups[*].IpPermissions[?((IpProtocol=='-1') || (FromPort<=\\`445\\` && ToPort>=\\`445\\`))].{IpProtocol:IpProtocol,FromPort:FromPort,ToPort:ToPort,CIDRv4:IpRanges[*].CidrIp,CIDRv6:Ipv6Ranges[*].CidrIpv6}\"
       ```

    3. Repeat the remediation for other security groups and regions as necessary.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_number:            '6.1.2'
  tag cis_rid:               '6.1.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-060102r1_rule'
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

  # CIFS = TCP/445. No security group should permit 445 from the
  # public internet. Iterate every SG and assert it doesn't allow
  # inbound 445 from 0.0.0.0/0 (or ::/0).
  aws_security_groups.entries.each do |sg|
    describe aws_security_group(group_id: sg.group_id) do
      it { should_not allow_in(port: 445, ipv4_range: '0.0.0.0/0') }
      it { should_not allow_in(port: 445, ipv6_range: '::/0') }
    end
  end
end
