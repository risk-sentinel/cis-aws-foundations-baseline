# encoding: UTF-8

control 'C-3.3.1' do
  title 'Ensure that encryption is enabled for EFS file systems'
  desc  "
    EFS data should be encrypted at rest using AWS KMS (Key Management Service).

    Data should be encrypted at rest to reduce the risk of a data breach via direct access to the storage device.
  "
  desc  'rationale', "
    EFS data should be encrypted at rest using AWS KMS (Key Management Service).

    Data should be encrypted at rest to reduce the risk of a data breach via direct access to the storage device.
  "
  desc  'check', "
    From Console:
    1. Login to the AWS Management Console and Navigate to the Elastic File System (EFS) dashboard.
    2. Select `File Systems` from the left navigation panel.
    3. Each item on the list has a visible Encrypted field that displays data at rest encryption status.
    4. Validate that this field reads `Encrypted` for all EFS file systems in all AWS regions.

    From CLI:
    1. Run the `describe-file-systems` command using custom query filters to list the identifiers of all AWS EFS file systems currently available within the selected region:
    ```
    aws efs describe-file-systems --region --output table --query 'FileSystems[*].[FileSystemId,Encrypted]' --output table
    ```
    2. The command output should return a table with the requested file system IDs.
    3. Run the `describe-file-systems` command using the ID of the file system that you want to examine as `file-system-id` and the necessary query filters:
    ```
    aws efs describe-file-systems --region --file-system-id --query 'FileSystems[*].Encrypted'
    ```
    4. The command output should return the file system encryption status as `true` or `false`. If the returned value is `false`, the selected AWS EFS file system is not encrypted and if the returned value is `true`, the selected AWS EFS file system is encrypted.
  "
  desc  'fix', "
    It is important to note that EFS file system data-at-rest encryption must be turned on when creating the file system. If an EFS file system has been created without data-at-rest encryption enabled, then you must create another EFS file system with the correct configuration and transfer the data.

    Steps to create an EFS file system with data encrypted at rest:

    From Console:
    1. Login to the AWS Management Console and Navigate to the `Elastic File System (EFS)` dashboard.
    2. Select `File Systems` from the left navigation panel.
    3. Click the `Create File System` button from the dashboard top menu to start the file system setup process.
    4. On the `Configure file system access` configuration page, perform the following actions:
    - Choose an appropriate VPC from the VPC dropdown list.
    - Within the `Create mount targets` section, check the boxes for all of the Availability Zones (AZs) within the selected VPC. These will be your mount targets.
    - Click `Next step` to continue.
    5. Perform the following on the `Configure optional settings` page:
    - Create `tags` to describe your new file system.
    - Choose `performance mode` based on your requirements.
    - Check the `Enable encryption` box and choose `aws/elasticfilesystem` from the `Select KMS master key` dropdown list to enable encryption for the new file system, using the default master key provided and managed by AWS KMS.
    - Click `Next step` to continue.
    6. Review the file system configuration details on the `review and create` page and then click `Create File System` to create your new AWS EFS file system.
    7. Copy the data from the old unencrypted EFS file system onto the newly created encrypted file system.
    8. Remove the unencrypted file system as soon as your data migration to the newly created encrypted file system is completed.
    9. Change the AWS region from the navigation bar and repeat the entire process for the other AWS regions.

    From CLI:
    1. Run the `describe-file-systems` command to view the configuration information for the selected unencrypted file system identified in the Audit steps:
    ```
    aws efs describe-file-systems --region --file-system-id ```
    2. The command output should return the configuration information.
    3. To provision a new AWS EFS file system, you need to generate a universally unique identifier (UUID) to create the token required by the `create-file-system` command. To create the required token, you can use a randomly generated UUID from \"https://www.uuidgenerator.net\".
    4. Run the `create-file-system` command using the unique token created at the previous step:
    ```
    aws efs create-file-system --region --creation-token --performance-mode generalPurpose --encrypted
    ```
    5. The command output should return the new file system configuration metadata.
    6. Run the `create-mount-target` command using the EFS file system ID returned from step 4 as the identifier and the ID of the Availability Zone (AZ) that will represent the mount target:
    ```
    aws efs create-mount-target --region --file-system-id --subnet-id ```
    7. The command output should return the new mount target metadata.
    8. Now you can mount your file system from an EC2 instance.
    9. Copy the data from the old unencrypted EFS file system to the newly created encrypted file system.
    10. Remove the unencrypted file system as soon as your data migration to the newly created encrypted file system is completed:
    ```
    aws efs delete-file-system --region --file-system-id ```
    11. Change the AWS region by updating the --region and repeat the entire process for the other AWS regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag ksi:                   ['KSI-SVC-SIN']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '3.3.1'
  tag cis_rid:               '3.3.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030301r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  impact 0.5
  fs_ids = scoped_or_na(aws_efs_file_systems.file_system_ids,
                           in_scope: applicable_partition,
                           reason:   "Control out of scope (partition=#{input('aws_partition')}) or no EFS file systems in this account")

  fs_ids.each do |id|
    describe aws_efs_file_system(id) do
      it { should be_encrypted }
    end
  end
end
