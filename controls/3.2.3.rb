# encoding: UTF-8

control 'C-3.2.3' do
  title 'Ensure that RDS instances are not publicly accessible'
  desc  "
    Ensure and verify that the RDS database instances provisioned in your AWS account restrict unauthorized access in order to minimize security risks. To restrict access to any RDS database instance, you must disable the Publicly Accessible flag for the database and update the VPC security group associated with the instance.

    Ensure that no public-facing RDS database instances are provisioned in your AWS account, and restrict unauthorized access in order to minimize security risks. When the RDS instance allows unrestricted access (0.0.0.0/0), anyone and anything on the Internet can establish a connection to your database, which can increase the opportunity for malicious activities such as brute force attacks, PostgreSQL injections, or DoS/DDoS attacks.
  "
  desc  'rationale', "
    Ensure and verify that the RDS database instances provisioned in your AWS account restrict unauthorized access in order to minimize security risks. To restrict access to any RDS database instance, you must disable the Publicly Accessible flag for the database and update the VPC security group associated with the instance.

    Ensure that no public-facing RDS database instances are provisioned in your AWS account, and restrict unauthorized access in order to minimize security risks. When the RDS instance allows unrestricted access (0.0.0.0/0), anyone and anything on the Internet can establish a connection to your database, which can increase the opportunity for malicious activities such as brute force attacks, PostgreSQL injections, or DoS/DDoS attacks.
  "
  desc  'check', "
    From Console:

    1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. Under the navigation panel, on the RDS dashboard, click `Databases`.
    3. Select the RDS instance that you want to examine.
    4. Click `Instance Name` from the dashboard, under `Connectivity and Security`.
    5. In the `Security` section, check if the Publicly Accessible flag status is set to `No`.
    6. Follow the steps below to check database subnet access:
    - In the `networking` section, click the subnet link under `Subnets`.
    - The link will redirect you to the VPC Subnets page.
    - Select the subnet listed on the page and click the `Route Table` tab from the dashboard bottom panel.
    - If the route table contains any entries with the destination CIDR block set to `0.0.0.0/0` and an `Internet Gateway` attached, the selected RDS database instance was provisioned inside a public subnet; therefore, it is not running within a logically isolated environment and can be accessed from the Internet.
    7. Repeat steps 3-6 to determine the configuration of other RDS database instances provisioned in the current region.
    8. Change the AWS region from the navigation bar and repeat the audit process for other regions.

    From Command Line:

    1. Run the `describe-db-instances` command to list all available RDS database names in the selected AWS region:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].DBInstanceIdentifier'
    ```
    2. The command output should return each database instance `identifier`.
    3. Run the `describe-db-instances` command again, using the `PubliclyAccessible` parameter as a query filter to reveal the status of the database instance's Publicly Accessible flag:
    ```
    aws rds describe-db-instances --region us-east-1 --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible]' --output table
    ```
    4. Check the Publicly Accessible parameter status. If the Publicly Accessible flag is set to `Yes`, then the selected RDS database instance is publicly accessible and insecure. Follow the steps mentioned below to check database subnet access.
    5. Run the `describe-db-instances` command again using the RDS database instance identifier that you want to check, along with the appropriate filtering to describe the VPC subnet(s) associated with the selected instance:
    ```
    aws ec2 describe-route-tables --filters \"Name=association.subnet-id,Values=\" --query \"RouteTables[].Routes[?GatewayId!='null']\"
    ```
    - The command output should list the subnets available in the selected database subnet group.
    6. Run the `describe-route-tables` command using the ID of the subnet returned in the previous step to describe the routes of the VPC route table associated with the selected subnet:
    ```
    aws ec2 describe-route-tables --region --filters \"Name=association.subnet-id,Values= \" --query 'RouteTables[*].Routes[]'
    ```
    - If the command returns the route table associated with the database instance subnet ID, check the values of the `GatewayId` and `DestinationCidrBlock` attributes returned in the output. If the route table contains any entries with the `GatewayId` value set to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the selected RDS database instance was provisioned within a public subnet.
    - Or, if the command returns empty results, the route table is implicitly associated with the subnet; therefore, the audit process continues with the next step.
    7. Run the `describe-db-instances` command again using the RDS database instance identifier that you want to check, along with the appropriate filtering to describe the VPC ID associated with the selected instance:
    ```
    aws rds describe-db-instances --region --db-instance-identifier --query 'DBInstances[*].DBSubnetGroup.VpcId'
    ```
    - The command output should show the VPC ID in the selected database subnet group.
    8. Now run the `describe-route-tables` command using the ID of the VPC returned in the previous step to describe the routes of the VPC's main route table that is implicitly associated with the selected subnet:
    ```
    aws ec2 describe-route-tables --region --filters \"Name=vpc-id,Values= \" \"Name=association.main,Values=true\" --query 'RouteTables[*].Routes[]'
    ```
    - The command output returns the VPC main route table implicitly associated with the database instance subnet ID. Check the values of the `GatewayId` and `DestinationCidrBlock` attributes returned in the output. If the route table contains any entries with the `GatewayId` value set to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the selected RDS database instance was provisioned inside a public subnet; therefore, it is not running within a logically isolated environment and does not adhere to AWS security best practices.
  "
  desc  'fix', "
    From Console:

    1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. Under the navigation panel, on the RDS dashboard, click `Databases`.
    3. Select the RDS instance that you want to update.
    4. Click `Modify` from the dashboard top menu.
    5. On the Modify DB Instance panel, under the `Connectivity` section, click on `Additional connectivity configuration` and update the value for `Publicly Accessible` to `Not publicly accessible` to restrict public access.
    6. Follow the below steps to update subnet configurations:
    - Select the `Connectivity and security` tab, and click the VPC attribute value inside the `Networking` section.
    - Select the `Details` tab from the VPC dashboard's bottom panel and click the Route table configuration attribute value.
    - On the Route table details page, select the Routes tab from the dashboard's bottom panel and click `Edit routes`.
    - On the Edit routes page, update the Destination of Target which is set to `igw-xxxxx` and click `Save` routes.
    7. On the Modify DB Instance panel, click `Continue`, and in the Scheduling of modifications section, perform one of the following actions based on your requirements:
    - Select `Apply during the next scheduled maintenance window` to apply the changes automatically during the next scheduled maintenance window.
    - Select `Apply immediately` to apply the changes right away. With this option, any pending modifications will be asynchronously applied as soon as possible, regardless of the maintenance window setting for this RDS database instance. Note that any changes available in the pending modifications queue are also applied. If any of the pending modifications require downtime, choosing this option can cause unexpected downtime for the application.
    8. Repeat steps 3-7 for each RDS instance in the current region.
    9. Change the AWS region from the navigation bar to repeat the process for other regions.

    From Command Line:

    1. Run the `describe-db-instances` command to list all available RDS database identifiers in the selected AWS region:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].DBInstanceIdentifier'
    ```
    2. The command output should return each database instance identifier.
    3. Run the `modify-db-instance` command to modify the configuration of a selected RDS instance, disabling the `Publicly Accessible` flag for that instance. This command uses the `apply-immediately` flag. If you want to avoid any downtime, the `--no-apply-immediately` flag can be used:
    ```
    aws rds modify-db-instance --region --db-instance-identifier --no-publicly-accessible --apply-immediately
    ```
    4. The command output should reveal the `PubliclyAccessible` configuration under pending values, to be applied at the specified time.
    5. Updating the Internet Gateway destination via the AWS CLI is not currently supported. To update information about the Internet Gateway, please use the AWS Console procedure.
    6. Repeat steps 1-5 for each RDS instance provisioned in the current region.
    7. Change the AWS region by using the --region filter to repeat the process for other regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.2.3'
  tag cis_rid:               '3.2.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030203r1_rule'
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

  aws_rds_instances.db_instance_identifiers.each do |id|
    describe aws_rds_instance(id) do
      its('publicly_accessible') { should eq false }
    end
  end
end
