# encoding: UTF-8

control 'C-6.8' do
  title 'Ensure VPC Endpoints are used for access to AWS Services'
  desc  "
    Ensure that Amazon VPCs use VPC endpoints (gateway or interface endpoints) for access to AWS services such as Amazon S3 and DynamoDB, so that traffic from workloads to AWS services stays on the Amazon private network instead of traversing the public internet. VPC endpoints provide private connectivity between VPCs and supported AWS services without requiring an internet gateway, NAT gateway, or public IP addresses.

    Accessing AWS services over the public internet increases exposure to network‑level threats, relies on internet routing, and makes it harder to tightly control egress paths. Using VPC endpoints allows workloads to reach AWS services over the Amazon private network, which reduces reliance on internet gateways and NAT gateways, simplifies egress filtering, and helps enforce data‑perimeter and \"private‑only\" patterns for sensitive workloads.
  "
  desc  'rationale', "
    Ensure that Amazon VPCs use VPC endpoints (gateway or interface endpoints) for access to AWS services such as Amazon S3 and DynamoDB, so that traffic from workloads to AWS services stays on the Amazon private network instead of traversing the public internet. VPC endpoints provide private connectivity between VPCs and supported AWS services without requiring an internet gateway, NAT gateway, or public IP addresses.

    Accessing AWS services over the public internet increases exposure to network‑level threats, relies on internet routing, and makes it harder to tightly control egress paths. Using VPC endpoints allows workloads to reach AWS services over the Amazon private network, which reduces reliance on internet gateways and NAT gateways, simplifies egress filtering, and helps enforce data‑perimeter and \"private‑only\" patterns for sensitive workloads.
  "
  desc  'check', "
    1. Identify in‑scope VPCs and services.
    - Determine which VPCs host production or sensitive workloads that should access AWS services securely via endpoints. 
    - For those VPCs, identify the AWS services they depend on (for example, S3 for data storage, DynamoDB for database, etc.).

    2. For each in‑scope VPC, check for existing VPC endpoints.

    ```
    aws ec2 describe-vpc-endpoints \\
      --region REGION \\
      --filters \"Name=vpc-id,Values=VPC_ID\" \\
      --query \"VpcEndpoints[*].[VpcEndpointId,VpcEndpointType,ServiceName,State]\" \\
      --output table
    ```
    - Provide the REGION and VPC_ID
    - VpcEndpointType tells you whether the endpoint is Gateway or Interface.
    - ServiceName shows which AWS service the endpoint is for (for example, com.amazonaws.us-east-1.s3, com.amazonaws.us-east-1.dynamodb, com.amazonaws.us-east-1.ssm).

    3. For each interface endpoint, verify subnet attachment across relevant AZs/subnets.

    ```
    aws ec2 describe-vpc-endpoints \\
      --region REGION \\
      --vpc-endpoint-ids INTERFACE_ENDPOINT_ID \\
      --query \"VpcEndpoints[*].[VpcEndpointId,ServiceName,SubnetIds,State]\" \\
      --output json
    ```
    - Provide the REGION and INTERFACE_ENDPOINT_ID

    4. For each gateway endpoint, verify that the route tables for the relevant subnets send traffic to the endpoint (via the AWS‑managed prefix list), not via internet/NAT gateways.

    - Identify relevant subnets in the VPC that need to have a route to gateway endpoint: 
    ```
    aws ec2 describe-subnets \\
      --region REGION \\
      --filters \"Name=vpc-id,Values=,VPC_ID\" \\
      --query \"Subnets[*].[SubnetId,AvailabilityZone,MapPublicIpOnLaunch,CidrBlock]\" \\
      --output table
    ```
    - Provide the REGION and VPC_ID

    - For each relevant subnet, identify the route table associated with it: 
    ```
    aws ec2 describe-route-tables \\
      --region REGION \\
      --filters \"Name=association.subnet-id,Values=SUBNET_ID\" \\
      --query \"RouteTables[*].RouteTableId\" \\
      --output text
    ```
    - Provide the REGION and SUBNET_ID

    - For each route table associated with relevant subnets, inspect routes:

    ```
    aws ec2 describe-route-tables \\
      --region REGION \\
      --route-table-ids ROUTE_TABLE_ID \\
      --query \"RouteTables[0].Routes[*].[DestinationPrefixListId,GatewayId,NatGatewayId,State]\" \\
      --output table
    ```
    - Provide the REGION and ROUTE_TABLE_ID

    For S3/DynamoDB gateway endpoints, you should see a DestinationPrefixListId (for example, pl-xxxxxxxx) with GatewayId equal to the endpoint (vpce-xxxx). If S3/DynamoDB are used by workloads in those subnets but traffic is only routed via igw-xxxx or nat-xxxx (and no prefix‑list/endpoint route exists), then VPC endpoints are not being used for securing network traffic for these services.
  "
  desc  'fix', "
    In this example, we are going to add S3 gateway endpoint and SQS interface endpoint to a VPC. You can follow similar remediation instructions for other services.

    1. Create S3 Gateway Endpoint 
    ```
    aws ec2 create-vpc-endpoint \\
      --region REGION \\
      --route-table-ids ROUTE_TABLE_ID \\
      --vpc-id VPC_ID  \\
      --service-name com.amazonaws.REGION.s3 \\
      --vpc-endpoint-type Gateway \\
      --query \"VpcEndpoint.VpcEndpointId\" \\
      --output text
    ```
    - Provide values for REGION, ROUTE_TABLE_ID, VPC_ID 
    - AWS automatically creates the routes for the AWS service in the route table provided as part of above command. 

    2. Verify that the gateway routes have been adequately created

    ```
    aws ec2 describe-route-tables \\
      --region REGION --route-table-ids ROUTE_TABLE_ID \\
      --query \"RouteTables[0].Routes[?DestinationPrefixListId=='pl-xxxxxxxx']\"
    ```
    - Provide values for REGION, ROUTE_TABLE_ID
    - pl-xxxxxxxx : replace with the specific prefix list for S3 in that region

    3. Create an SQS Interface Endpoint

    ```
    aws ec2 create-vpc-endpoint \\
      --vpc-id VPC_ID \\
      --service-name com.amazonaws.REGION.sqs \\
      --vpc-endpoint-type Interface \\
      --subnet-ids PRIVATE_SUBNET_1_ID PRIVATE_SUBNET_2_ID \\
      --security-group-ids SECURITY_GROUP_ID \\
      --vpc-endpoint-policy VPC_ENDPOINT_POLICY \\
      --query \"VpcEndpoint.VpcEndpointId\" \\
      --output text
    ```
    - SECURITY_GROUP_ID: Update security groups for interface endpoint. Ensure the interface endpoint security group allows inbound traffic from your workloads. 
    - VPC_ENDPOINT_POLICY: Create a restrictive Endpoint policy to ensure only certain AWS services could be reached and only specific actions can be performed. 
    - AWS automatically creates Elastic Network Interfaces (ENIs) for the interface endpoint which allows any traffic from intended for SQS to be routed through the Interface Gateway. 

    4. Test and validate endpoint connectivity from an EC2 instance in a private subnet:

    - Test S3 (gateway endpoint)
    ```
    aws s3 ls s3://your-test-bucket --region REGION
    ```

    - Test SQS (interface endpoint)
    ```
    aws sqs list-queues --region REGION
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag ksi:                   ['KSI-PIY-RSD']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '6.8'
  tag cis_rid:               '6.8'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0608r1_rule'
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

  required_endpoints = Array(input('required_vpc_endpoints'))
  vpc_ids            = aws_vpcs.vpc_ids

  # Empty required_vpc_endpoints + any VPC present = FAIL. The consumer
  # has not documented which AWS services require private connectivity
  # in this account; that's itself a finding. Populate the input to
  # enforce per-VPC, or attest separately if genuinely no required
  # services apply (e.g., a workload-free meta-account).
  if vpc_ids.any? && required_endpoints.empty?
    describe 'required_vpc_endpoints input' do
      it 'must be populated when the account has VPCs (consumer must declare required AWS-service endpoints)' do
        expect(required_endpoints).not_to be_empty
      end
    end
  else
    # When required_endpoints is non-empty OR no VPCs exist, run the
    # coverage scan. With no VPCs the scan is vacuously empty → passes.
    describe aws_vpc_endpoint_coverage(required_endpoints: required_endpoints) do
      its('violations') { should be_empty }
    end
  end
end
