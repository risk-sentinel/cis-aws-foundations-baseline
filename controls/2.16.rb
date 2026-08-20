# encoding: UTF-8

control 'C-2.16' do
  title 'Ensure IAM instance roles are used for AWS resource access from instances'
  desc  "
    AWS access from within EC2 instances can be achieved either by embedding AWS access keys into applications or by assigning an IAM role to the instance with the appropriate permissions. \"AWS access\" refers to making API calls to AWS services to access or manage resources.

    IAM roles reduce the risks associated with storing, sharing, and rotating long-term credentials. Compromised credentials can be used outside of AWS, whereas IAM role credentials are temporary and tied to the instance.

    Additionally, credentials embedded in applications or configuration files are more difficult to rotate and are more likely to be exposed over time, increasing the risk of unauthorized access.
  "
  desc  'rationale', "
    AWS access from within EC2 instances can be achieved either by embedding AWS access keys into applications or by assigning an IAM role to the instance with the appropriate permissions. \"AWS access\" refers to making API calls to AWS services to access or manage resources.

    IAM roles reduce the risks associated with storing, sharing, and rotating long-term credentials. Compromised credentials can be used outside of AWS, whereas IAM role credentials are temporary and tied to the instance.

    Additionally, credentials embedded in applications or configuration files are more difficult to rotate and are more likely to be exposed over time, increasing the risk of unauthorized access.
  "
  desc  'check', "
    Perform the following to determine if IAM roles are used:

    From Console:

    1. Sign in to the AWS Management Console and navigate to the EC2 dashboard at https://console.aws.amazon.com/ec2/
    2. In the left navigation panel, choose `Instances`
    3. Select the EC2 instance you want to examine
    4. Select `Actions`
    5. Select `View details`
    6. Review the following:
    - If `IAM Role` contains a role, it is compliant
    - If `IAM Role` is blank, it is non-compliant
    - If an `Instance profile ARN` exists but no role is attached, it is non-compliant
    7. Repeat for all EC2 instances

    From Command Line:

    1. List all EC2 instances:

    ```
    aws ec2 describe-instances --region --query 'Reservations[*].Instances[*].InstanceId'
    ```

    2. Check for IAM instance profiles:

    ```
    aws ec2 describe-instances --region --instance-id --query 'Reservations[*].Instances[*].IamInstanceProfile'
    ```

    3. If no IAM instance profile is returned, the instance does not have a role attached
    4. Repeat for all instances and regions
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and navigate to the EC2 dashboard at `https://console.aws.amazon.com/ec2/`
    2. In the left navigation panel, choose `Instances`
    3. Select the EC2 instance you want to modify
    4. Click `Actions`
    5. Click `Security`
    6. Click `Modify IAM role`
    7. Select an existing IAM role or create a new one
    8. Click `Update IAM role`
    9. Repeat for all applicable instances

    From Command Line:

    1. Identify instances without roles (all regions):

    ```
    for r in $(aws ec2 describe-regions --query \"Regions[].RegionName\" --output text); do aws ec2 describe-instances --region \"$r\" --query \"Reservations[].Instances[?IamInstanceProfile==null].[InstanceId, '$r']\" --output text done
    ```

    2. Attach an instance profile:

    ```
    aws ec2 associate-iam-instance-profile --region --instance-id --iam-instance-profile Name=\"Instance-Profile-Name\"
    ```

    3. Verify the role is attached:

    ```
    aws ec2 describe-instances --region --instance-id --query 'Reservations[*].Instances[*].IamInstanceProfile'
    ```

    4. Repeat steps 2 and 3 for each EC2 instance in your AWS account that requires an IAM role to be attached.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-002113', 'CCI-000051']
  tag cis_number:            '2.16'
  tag cis_rid:               '2.16'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0216r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  # Empty collection => Not Applicable, never silence. See README, "Empty collections".
  instance_ids = aws_ec2_instances.instance_ids
  applicable           = applicable_partition && !instance_ids.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}) or no EC2 instances in this account") do
    applicable
  end

  instance_ids.each do |id|
    describe aws_ec2_instance(id) do
      its('iam_instance_profile') { should_not be_nil }
    end
  end
end
