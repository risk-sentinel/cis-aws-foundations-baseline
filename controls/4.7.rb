# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure VPC flow logging is enabled in all VPCs'
  desc  "
    VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet \"Rejects\" for VPCs.

    VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or gain insights during security workflows.
  "
  desc  'rationale', "
    VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet \"Rejects\" for VPCs.

    VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or gain insights during security workflows.
  "
  desc  'check', "
    Perform the following to determine if VPC Flow logs are enabled:

    From Console:

    1. Sign into the management console.
    2. Select `Services`, then select `VPC`.
    3. In the left navigation pane, select `Your VPCs`.
    4. Select a VPC.
    5. In the right pane, select the `Flow Logs` tab.
    6. Ensure a Log Flow exists that has `Active` in the `Status` column.

    From Command Line:

    1. Run the `describe-vpcs` command (OSX/Linux/UNIX) to list the VPC networks available in the current AWS region:
    ```
    aws ec2 describe-vpcs --region --query Vpcs[].VpcId
    ```
    The command output returns the `VpcId` of VPCs available in the selected region.

    2. Run the `describe-flow-logs` command (OSX/Linux/UNIX) using the VPC ID to determine if the selected virtual network has the Flow Logs feature enabled:
    ```
    aws ec2 describe-flow-logs --filter \"Name=resource-id,Values= \"
    ```
    If there are no Flow Logs created for the selected VPC, the command output will return an empty list `[]`.
    3. Repeat step 2 for other VPCs in the same region.
    4. Change the region by updating `--region`, and repeat steps 1-4 for each region.
    5. Alternatively, the following command can be used to identify VPCs with and without Flow Logs:
    ```
    VPCS=$(aws ec2 describe-vpcs --query \"Vpcs[].VpcId\" --output text)

    for VPC in $VPCS; do
      COUNT=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values=$VPC --query \"length(FlowLogs)\" --output text)

      if [ \"$COUNT\" -gt 0 ]; then
        echo \"$VPC True\"
      else
        echo \"$VPC False\"
      fi
    done
    ```
  "
  desc  'fix', "
    Perform the following to enable VPC Flow Logs:

    From Console:

    1. Sign into the management console.
    2. Select `Services`, then select `VPC`.
    3. In the left navigation pane, select `Your VPCs`.
    4. Select a VPC.
    5. In the right pane, select the `Flow Logs` tab.
    6. If no Flow Log exists, click `Create Flow Log`.
    7. For Filter, select `Reject`.
    8. Enter a `Role` and `Destination Log Group`.
    9. Click `Create Log Flow`.
    10. Click on `CloudWatch Logs Group`.

    Note: Setting the filter to \"Reject\" will dramatically reduce the accumulation of logging data for this recommendation and provide sufficient information for the purposes of breach detection, research, and remediation. However, during periods of least privilege security group engineering, setting the filter to \"All\" can be very helpful in discovering existing traffic flows required for the proper operation of an already running environment.

    From Command Line:

    1. Create a policy document, name it `role_policy_document.json`, and paste the following content:
    ```
    {
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Sid\": \"test\",
                \"Effect\": \"Allow\",
                \"Principal\": {
                    \"Service\": \"vpc-flow-logs.amazonaws.com\"
                },
                \"Action\": \"sts:AssumeRole\"
            }
        ]
    }
    ```
    2. Create another policy document, name it `iam_policy.json`, and paste the following content:
    ```
    {
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\":[
                    \"logs:CreateLogGroup\",
                    \"logs:CreateLogStream\",
                    \"logs:DescribeLogGroups\",
                    \"logs:DescribeLogStreams\",
                    \"logs:PutLogEvents\",
                    \"logs:GetLogEvents\",
                    \"logs:FilterLogEvents\"
                ],
                \"Resource\": \"*\"
            }
        ]
    }
    ```
    3. Run the following command to create an IAM role:
    ```
    aws iam create-role --role-name --assume-role-policy-document file:// role_policy_document.json 
    ```
    4. Run the following command to create an IAM policy:
    ```
    aws iam create-policy --policy-name --policy-document file:// iam-policy.json
    ```
    5. Run the `attach-group-policy` command, using the IAM policy ARN returned from the previous step to attach the policy to the IAM role:
    ```
    aws iam attach-group-policy --policy-arn arn:aws:iam:: :policy/ --group-name ```
    - If the command succeeds, no output is returned.
    6. Run the `describe-vpcs` command to get a list of VPCs in the selected region:
    ```
    aws ec2 describe-vpcs --region ```
    - The command output should return a list of VPCs in the selected region.
    7. Run the `create-flow-logs` command to create a flow log for a VPC:
    ```
    aws ec2 create-flow-logs --resource-type VPC --resource-ids --traffic-type REJECT --log-group-name --deliver-logs-permission-arn ```
    8. Repeat step 7 for other VPCs in the selected region.
    9. Change the region by updating --region, and repeat the remediation procedure for each region.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a', 'AC-2 a', 'SI-4 a 1']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL', 'KSI-SVC-EIS']
  tag nist_r4:               ['AC-2 a', 'AC-2 f', 'AU-2 a', 'SI-4 a 1']
  tag cci:                   ['CCI-000011', 'CCI-000123', 'CCI-002110', 'CCI-001253']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0407r1_rule'
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

  expected = Array(input('expected_vpc_flow_log_destinations'))
  vpc_ids  = aws_vpcs.vpc_ids
  flow_logs = aws_vpc_flow_log_destinations

  # Every VPC must have at least one flow log attached. First pass
  # covers the scanner's current region only — full all-regions
  # iteration deferred.
  vpc_ids.each do |vpc_id|
    vpc_flow_logs = flow_logs.where(resource_id: vpc_id).entries

    describe "VPC #{vpc_id} must have at least one flow log attached" do
      subject { vpc_flow_logs }
      it { should_not be_empty }
    end

    next if vpc_flow_logs.empty?

    # Allowlist validation — each VPC's flow log destination must match
    # an expected_vpc_flow_log_destinations entry on
    # (destination_type, destination, traffic_type).
    if expected.empty?
      describe "expected_vpc_flow_log_destinations input (VPC #{vpc_id} has flow logs but allowlist is empty)" do
        it 'must be populated when VPC flow logs are present (consumer must declare destinations)' do
          expect(expected).not_to be_empty
        end
      end
    else
      matches_allowlist = vpc_flow_logs.any? do |fl|
        expected.any? do |e|
          e.is_a?(Hash) &&
            e['destination_type'] == fl[:log_destination_type] &&
            e['destination']      == fl[:log_destination] &&
            e['traffic_type']     == fl[:traffic_type]
        end
      end
      describe "VPC #{vpc_id} flow log destination must match expected_vpc_flow_log_destinations" do
        subject { matches_allowlist }
        it { should eq true }
      end
    end
  end
end
