# encoding: UTF-8

control 'C-3.2.2' do
  title 'Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances'
  desc  "
    Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled to automatically receive minor engine upgrades during the specified maintenance window. This way, RDS instances can obtain new features, bug fixes, and security patches for their database engines.

    AWS RDS will occasionally deprecate minor engine versions and provide new ones for upgrades. When the last version number within a release is replaced, the changed version is considered minor. With the Auto Minor Version Upgrade feature enabled, version upgrades will occur automatically during the specified maintenance window, allowing your RDS instances to receive new features, bug fixes, and security patches for their database engines.
  "
  desc  'rationale', "
    Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled to automatically receive minor engine upgrades during the specified maintenance window. This way, RDS instances can obtain new features, bug fixes, and security patches for their database engines.

    AWS RDS will occasionally deprecate minor engine versions and provide new ones for upgrades. When the last version number within a release is replaced, the changed version is considered minor. With the Auto Minor Version Upgrade feature enabled, version upgrades will occur automatically during the specified maintenance window, allowing your RDS instances to receive new features, bug fixes, and security patches for their database engines.
  "
  desc  'check', "
    From Console:

    1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. In the left navigation panel, click `Databases`.
    3. Select the RDS instance that you want to examine.
    4. Click on the `Maintenance and backups` panel.
    5. Under the `Maintenance` section, search for the Auto Minor Version Upgrade status.
    - If the current status is `Disabled`, it means that the feature is not enabled, and the minor engine upgrades released will not be applied to the selected RDS instance.

    From Command Line:

    1. Run the `describe-db-instances` command to list all RDS database names available in the selected AWS region:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].[DBInstanceIdentifier,AutoMinorVersionUpgrade]' --output table
    ```
    2. The command output should return each database instance identifier.
    3. Run the `describe-db-instances` command again using a RDS instance identifier returned earlier to determine the Auto Minor Version Upgrade status for the selected instance:
    ```
    aws rds describe-db-instances --region --db-instance-identifier --query 'DBInstances[*].AutoMinorVersionUpgrade'
    ```
    4. The command output should return the current status of the feature. If the current status is set to `true`, the feature is enabled and the minor engine upgrades will be applied to the selected RDS instance.
  "
  desc  'fix', "
    From Console:

    1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
    2. In the left navigation panel, click `Databases`.
    3. Select the RDS instance that you want to update.
    4. Click on the `Modify` button located at the top right side.
    5. On the `Modify DB Instance: ` page, In the `Maintenance` section, select `Auto minor version upgrade` and click the `Yes` radio button.
    6. At the bottom of the page, click `Continue`, and check `Apply Immediately` to apply the changes immediately, or select `Apply during the next scheduled maintenance window` to avoid any downtime.
    7. Review the changes and click `Modify DB Instance`. The instance status should change from available to modifying and back to available. Once the feature is enabled, the `Auto Minor Version Upgrade` status should change to `Yes`.

    From Command Line:

    1. Run the `describe-db-instances` command to list all RDS database instance names available in the selected AWS region:
    ```
    aws rds describe-db-instances --region --query 'DBInstances[*].DBInstanceIdentifier'
    ```
    2. The command output should return each database instance identifier.
    3. Run the `modify-db-instance` command to modify the configuration of a selected RDS instance. This command will apply the changes immediately. Remove `--apply-immediately` to apply changes during the next scheduled maintenance window and avoid any downtime:
    ```
    aws rds modify-db-instance --region --db-instance-identifier --auto-minor-version-upgrade --apply-immediately
    ```
    4. The command output should reveal the new configuration metadata for the RDS instance, including the `AutoMinorVersionUpgrade` parameter value.
    5. Run the `describe-db-instances` command to check if the Auto Minor Version Upgrade feature has been successfully enabled:
    ```
    aws rds describe-db-instances --region --db-instance-identifier --query 'DBInstances[*].AutoMinorVersionUpgrade'
    ```
    6. The command output should return the feature's current status set to `true`, indicating that the feature is `enabled`, and that the minor engine upgrades will be applied to the selected RDS instance.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a', 'SI-2 a']
  tag nist_r4:               ['MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001028', 'CCI-001225']
  tag cis_number:            '3.2.2'
  tag cis_rid:               '3.2.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030202r1_rule'
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
      its('auto_minor_version_upgrade') { should eq true }
    end
  end
end
