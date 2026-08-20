# encoding: UTF-8

control 'C-6.1.1' do
  title 'Ensure EBS volume encryption is enabled in all regions'
  desc  "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.

    Encrypting data at rest reduces the likelihood of unintentional exposure and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'rationale', "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.

    Encrypting data at rest reduces the likelihood of unintentional exposure and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'check', "
    From Console:

    1. Login to the AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/.
    2. Under `Account attributes`, click `Data Protection and Security`.
    3. Under `EBS encryption`, verify that `Always encrypt new EBS volumes` displays `Enabled`.
    4. Repeat for each region in use.

    Note: EBS volume encryption is configured per region.

    From Command Line:

    1. Run the following command:

      ```
      aws --region ec2 get-ebs-encryption-by-default
      ```

    2. Verify that `\"EbsEncryptionByDefault\": true` is displayed.
    3. Repeat for each region in use.

    Note: EBS volume encryption is configured per region.
  "
  desc  'fix', "
    From Console:

    1. Login to the AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/.
    2. Under `Account attributes`, click `Data protection and security`.
    3. Under `EBS encryption`, Click `Manage`.
    4. Check the `Enable` box to default encryption.
    5. Click `Update EBS encryption`.
    6. Repeat for each region in which EBS volume encryption is not enabled by default.

    Note: EBS volume encryption is configured per region.

    From Command Line:

    1. Run the following command:

      ```
      aws --region ec2 enable-ebs-encryption-by-default
      ```

    2. Verify that `\"EbsEncryptionByDefault\": true` is displayed.
    3. Repeat for each region in which EBS volume encryption is not enabled by default.

    Note: EBS volume encryption is configured per region.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '6.1.1'
  tag cis_rid:               '6.1.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-060101r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  # Hoisted so an EMPTY collection is a declared state rather than an absent
  # one. Previously the loop below simply did not execute on an account with
  # no EBS volumes, so the control registered no describe blocks and emitted ZERO
  # results — neither passed nor Not Applicable, just absent. A control that
  # asserts nothing while reporting not-red is the failure this profile
  # exists to catch, and it also fails `hdf convert`, whose schema requires
  # at least one result per requirement.
  volume_ids = aws_ebs_volumes.volume_ids
  applicable           = applicable_partition && !volume_ids.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}) or no EBS volumes in this account") do
    applicable
  end

  # Check every EBS volume in the scanner's region. Full "all regions"
  # scope (iterating every AWS region) is a follow-up tracked with
  # #13's target metadata once inventory/targets.yml names the consumer's
  # active regions.
  volume_ids.each do |id|
    describe aws_ebs_volume(id) do
      it { should be_encrypted }
    end
  end
end
