# encoding: UTF-8

control 'C-6.6' do
  title 'Ensure routing tables for VPC peering are "least access"'
  desc  "
    Once a VPC peering connection is established, routing tables must be updated to enable any connections between the peered VPCs. These routes can be as specific as desired, even allowing for the peering of a VPC to only a single host on the other side of the connection.

    Being highly selective in peering routing tables is a very effective way to minimize the impact of a breach, as resources outside of these routes are inaccessible to the peered VPC.
  "
  desc  'rationale', "
    Once a VPC peering connection is established, routing tables must be updated to enable any connections between the peered VPCs. These routes can be as specific as desired, even allowing for the peering of a VPC to only a single host on the other side of the connection.

    Being highly selective in peering routing tables is a very effective way to minimize the impact of a breach, as resources outside of these routes are inaccessible to the peered VPC.
  "
  desc  'check', "
    Review the routing tables of peered VPCs to determine whether they route all subnets of each VPC and whether this is necessary to accomplish the intended purposes of peering the VPCs.

    From Command Line:

    1. List all the route tables from a VPC and check if the \"GatewayId\" is pointing to a ` ` (e.g., pcx-1a2b3c4d) and if the \"DestinationCidrBlock\" is as specific as desired:

    ```
    aws ec2 describe-route-tables --filter \"Name=vpc-id,Values= \" --query \"RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes, AssociatedSubnets:Associations[*].SubnetId}\"
    ```
    2. Alternatively, the following command can be used for improved readability:
    ```
    aws ec2 describe-route-tables --query \"RouteTables[].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes, AssociatedSubnets:Associations[].SubnetId}\" --output table
    ```
  "
  desc  'fix', "
    Remove and add route table entries to ensure that the least number of subnets or hosts required to accomplish the purpose of peering are routable.

    From Command Line:

    1. For each ` ` that contains routes that are non-compliant with your routing policy (granting more access than desired), delete the non-compliant route:

    ```
    aws ec2 delete-route --route-table-id --destination-cidr-block ```

    2. Create a new compliant route:

    ```
    aws ec2 create-route --route-table-id --destination-cidr-block --vpc-peering-connection-id ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (11)', 'SI-4 (5)']
  tag nist_r4:               ['SI-4 (11)', 'SI-4 (5)']
  tag cci:                   ['CCI-002668', 'CCI-002663']
  tag cis_number:            '6.6'
  tag cis_rid:               '6.6'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0606r1_rule'
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

  # Always run the route-violation scan. The custom resource produces
  # two violation kinds:
  #   - :unmanaged_peering — peering exists in route tables but is NOT
  #     in vpc_peering_allowed_cidrs. Empty allowlist + any peering
  #     route lands here → control FAILS (consumer must document).
  #   - :unauthorized_route — peering is in the allowlist but the
  #     route's destination CIDR is not in the per-peering allowed list.
  # If the account has no peering connections at all, violations is
  # empty → control passes vacuously.
  allowed_cidrs = input('vpc_peering_allowed_cidrs') || {}
  describe aws_vpc_peering_route_violations(allowed_cidrs: allowed_cidrs) do
    its('violations') { should be_empty }
  end
end
