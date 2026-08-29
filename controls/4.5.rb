# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
  desc  "
    AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer-created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.

    Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data, as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.
  "
  desc  'rationale', "
    AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer-created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.

    Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data, as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.
  "
  desc  'check', "
    Perform the following to determine if CloudTrail is configured to use SSE-KMS:

    From Console:

    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail).
    2. In the left navigation pane, choose `Trails`.
    3. Select a trail.
    4. In the `General details` section, select `Edit` to edit the trail configuration.
    5. Ensure the box at `Log file SSE-KMS encryption` is checked and that a valid `AWS KMS alias` of a KMS key is entered in the respective text box.

    From Command Line:

    1. Run the following command:
    ```
      aws cloudtrail describe-trails  
    ```
    2. For each trail listed, SSE-KMS is enabled if the trail has a `KmsKeyId` property defined.
  "
  desc  'fix', "
    Perform the following to configure CloudTrail to use SSE-KMS:

    From Console:

    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail).
    2. In the left navigation pane, choose `Trails`.
    3. Click on a trail.
    4. Under the `S3` section, click the edit button (pencil icon).
    5. Click `Advanced`.
    6. Select an existing CMK from the `KMS key Id` drop-down menu.
      - Note: Ensure the CMK is located in the same region as the S3 bucket.
      - Note: You will need to apply a KMS key policy on the selected CMK in order for CloudTrail, as a service, to encrypt and decrypt log files using the CMK provided. View the AWS documentation for [editing the selected CMK Key policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html).
    7. Click `Save`.
    8. You will see a notification message stating that you need to have decryption permissions on the specified KMS key to decrypt log files.
    9. Click `Yes`.

    From Command Line:

    Run the following command to specify a KMS key ID to use with a trail:
    ```
    aws cloudtrail update-trail --name --kms-key-id ```
    Run the following command to attach a key policy to a specified KMS key:
    ```
    aws kms put-key-policy --key-id --policy ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AU-1 a 1 (a)', 'AC-8 a']
  tag nist_r4:               ['AU-1 a 1', 'SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000117', 'CCI-000051']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0405r1_rule'
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

  # Every trail must have at-rest KMS CMK encryption. Validate kms_key_id
  # is set AND (when expected_cloudtrail_destinations declares per-bucket
  # KMS keys) that the key matches the consumer-declared allowlist.
  expected     = Array(input('expected_cloudtrail_destinations'))
  trail_names  = aws_cloudtrail_trails.names

  trail_names.each do |trail_name|
    trail = aws_cloudtrail_trail(trail_name: trail_name)
    describe "Trail #{trail.trail_name} KMS at-rest encryption" do
      subject { trail }
      it               { should be_encrypted }
      its('kms_key_id') { should_not be_nil }
    end

    # If the consumer declared an expected KMS key for this trail's bucket,
    # enforce that the trail's kms_key_id matches.
    if expected.any?
      entry = expected.find { |e| e.is_a?(Hash) && e['bucket'] == trail.s3_bucket_name }
      expected_kms = entry && entry['kms_key']
      next unless expected_kms && !expected_kms.to_s.empty?
      describe "Trail #{trail.trail_name} KMS key must match expected_cloudtrail_destinations[].kms_key for bucket #{trail.s3_bucket_name}" do
        subject { trail.kms_key_id }
        it { should eq expected_kms }
      end
    end
  end
end
