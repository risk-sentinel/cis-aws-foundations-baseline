# encoding: UTF-8

control 'C-3.2.1' do
  title 'Ensure that encryption-at-rest is enabled for RDS instances'
  desc  "
    Amazon RDS encrypted DB instances use the industry-standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles the authentication of access and the decryption of your data transparently, with minimal impact on performance.

    Databases are likely to hold sensitive and critical data; therefore, it is highly recommended to implement encryption to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance's underlying storage, the automated backups, read replicas, and snapshots are all encrypted.
  "
  desc  'rationale', "
    Amazon RDS encrypted DB instances use the industry-standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles the authentication of access and the decryption of your data transparently, with minimal impact on performance.

    Databases are likely to hold sensitive and critical data; therefore, it is highly recommended to implement encryption to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance's underlying storage, the automated backups, read replicas, and snapshots are all encrypted.
  "
  desc  'check', "
    From Console:

    1. Login to the AWS Management Console and open the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. In the navigation pane, under RDS dashboard, click `Databases`.
    3. Select the RDS instance that you want to examine.
    4. Click `Instance Name` to see details, then select the `Configuration` tab.
    5. Under Configuration Details, in the Primary Storage pane, search for the `Encryption Enabled` status.
    6. If the current status is set to `Disabled`, encryption is not enabled for the selected RDS database instance.
    7. Repeat steps 2 to 6 to verify the encryption status of other RDS instances in the same region.
    8. Change the region from the top of the navigation bar, and repeat the audit steps for other regions.

    From Command Line:

    1. Run the `describe-db-instances` command to list all the RDS database instance names available in the selected AWS region. The output will return each database instance identifier (name):
     ```
    aws rds describe-db-instances --region --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted]' --output table
    ```
    2. Run the `describe-db-instances` command again, using an RDS instance identifier returned from step 1, to determine if the selected database instance is encrypted. The output should return the encryption status `True` or `False`:
    ```
    aws rds describe-db-instances --region --db-instance-identifier --query 'DBInstances[*].StorageEncrypted'
    ```
    3. If the StorageEncrypted parameter value is `False`, encryption is not enabled for the selected RDS database instance.
    4. Repeat steps 1 to 3 to audit each RDS instance, and change the region to verify RDS instances in other regions.
  "
  desc  'fix', "
    From Console:

    1. Login to the AWS Management Console and open the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. In the left navigation panel, click on `Databases`.
    3. Select the Database instance that needs to be encrypted.
    4. Click the `Actions` button placed at the top right and select `Take Snapshot`.
    5. On the Take Snapshot page, enter the name of the database for which you want to take a snapshot in the `Snapshot Name` field and click on `Take Snapshot`.
    6. Select the newly created snapshot, click the `Action` button placed at the top right, and select `Copy snapshot` from the Action menu.
    7. On the Make Copy of DB Snapshot page, perform the following:
    - In the `New DB Snapshot Identifier` field, enter a name for the new snapshot.
    - Check `Copy Tags`. The new snapshot must have the same tags as the source snapshot.
    - Select `Yes` from the `Enable Encryption` dropdown list to enable encryption. You can choose to use the AWS default encryption key or a custom key from the Master Key dropdown list.
    8. Click `Copy Snapshot` to create an encrypted copy of the selected instance's snapshot.
    9. Select the new Snapshot Encrypted Copy and click the `Action` button located at the top right. Then, select the `Restore Snapshot` option from the Action menu. This will restore the encrypted snapshot to a new database instance.
    10. On the Restore DB Instance page, enter a unique name for the new database instance in the DB Instance Identifier field.
    11. Review the instance configuration details and click `Restore DB Instance`.
    12. After the new instance is provisioned:
    - Update application configuration to use the new encrypted database endpoint
    - Remove the unencrypted instance once migration is complete

    Note: This remediation procedure assumes that the database has been taken offline (or operating in read-only mode) and is static when the snapshot is taken. If the database is still in use, any changes made between the time the snapshot is made and the new encrypted database is brought online will be lost.

    For production databases, consider implementing replication or planned downtime to ensure data consistency during migration.

    From Command Line:

    1. List all RDS database instances:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].DBInstanceIdentifier'
    ```
    2. Check if the instance is encrypted:
    ```
    aws rds describe-db-instances --region --db-instance-identifier --query 'DBInstances[*].StorageEncrypted'
    ```
    3. Create a snapshot:
    ```
    aws rds create-db-snapshot --region --db-snapshot-identifier --db-instance-identifier ```
    4. List KMS key aliases:
    ```
    aws kms list-aliases --region ```
    5. Create an encrypted copy of the snapshot:
    ```
    aws rds copy-db-snapshot --region \\
      --source-db-snapshot-identifier \\
      --target-db-snapshot-identifier \\
      --copy-tags \\
      --kms-key-id ```
    6. Restore the encrypted snapshot (default VPC):
    ```
    aws rds restore-db-instance-from-db-snapshot --region \\
      --db-instance-identifier \\
      --db-snapshot-identifier ```
    7. (Optional) Create a DB subnet group (if using custom VPC):
    ```
    aws rds create-db-subnet-group \\
      --db-subnet-group-name \\
      --db-subnet-group-description \\
      --subnet-ids '[\"subnet-1\",\"subnet-2\",\"subnet-3\"]'
    ```
    8. Restore using the subnet group:
    ```
    aws rds restore-db-instance-from-db-snapshot --region \\
      --db-subnet-group-name \\
      --db-instance-identifier \\
      --db-snapshot-identifier ```
    9. Verify the new database instance:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].DBInstanceIdentifier'
    ```
    10. Confirm encryption is enabled:
    ```
    aws rds describe-db-instances --region \\
      --db-instance-identifier \\
      --query 'DBInstances[*].StorageEncrypted'
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '3.2.1'
  tag cis_rid:               '3.2.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030201r1_rule'
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
      it { should be_encrypted }
    end
  end
end
