# encoding: UTF-8

control 'C-3.1.2' do
  title 'Ensure MFA Delete is enabled on S3 buckets'
  desc  "
    Once MFA Delete is enabled on your sensitive and classified S3 bucket, it requires the user to provide two forms of authentication.

    Adding MFA delete to an S3 bucket requires additional authentication when you change the version state of your bucket or delete an object version, adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.
  "
  desc  'rationale', "
    Once MFA Delete is enabled on your sensitive and classified S3 bucket, it requires the user to provide two forms of authentication.

    Adding MFA delete to an S3 bucket requires additional authentication when you change the version state of your bucket or delete an object version, adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.
  "
  desc  'check', "
    Perform the steps below to confirm that MFA delete is configured on an S3 bucket:

    From Console:

    1. Login to the S3 console at `https://console.aws.amazon.com/s3/`.

    2. Click the `check` box next to the name of the bucket you want to confirm.

    3. In the window under `Properties`:
    - Confirm that Versioning is `Enabled`
    - Confirm that MFA Delete is `Enabled`

    From Command Line:

    1. Run the `get-bucket-versioning` command:
    ```
    aws s3api get-bucket-versioning --bucket my-bucket | grep MfaDelete
    ```

    Example output:
    ``` Enabled Enabled ```

    If the console or CLI output does not show that Versioning and MFA Delete are `enabled`, please refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to enable MFA delete on an S3 bucket:

    Note:

    - You cannot enable MFA Delete using the AWS Management Console; you must use the AWS CLI or API.

    - You must use your 'root' account to enable MFA Delete on S3 buckets.

    From Command line:

    1. Run the s3api `put-bucket-versioning` command:

    ```
    aws s3api put-bucket-versioning \\
      --bucket my-bucket \\
      --versioning-configuration Status=Enabled,MFADelete=Enabled \\
      --mfa \"arn:aws:iam:: :mfa/root-account-mfa-device \"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'IA-2 (2)', 'AC-8 a']
  tag nist_r4:               ['AC-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000213', 'CCI-000766', 'CCI-000051']
  tag cis_number:            '3.1.2'
  tag cis_rid:               '3.1.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030102r1_rule'
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

  # Auto-detect all S3 buckets in the account and assert MFA Delete +
  # Versioning are enabled on each, excluding consumer-declared
  # exceptions. When s3_mfa_delete_protection is false, mark N/A.
  protection_enabled = input('s3_mfa_delete_protection') == true
  excluded_buckets   = Array(input('s3_mfa_delete_excluded_buckets')).map(&:to_s)

  if !protection_enabled
    # impact already set to 0.0 by the protection_enabled-aware
    # canonical pattern would go here, but C-3.1.2 currently uses only
    # the partition gate. Inline the additional gate:
    impact 0.0
    describe 'S3 MFA Delete (s3_mfa_delete_protection=false)' do
      skip 'Consumer has disabled MFA Delete enforcement via s3_mfa_delete_protection: false.'
    end
  else
    all_buckets = aws_s3_buckets.bucket_names
    in_scope    = all_buckets.reject { |b| excluded_buckets.include?(b) }

    if in_scope.empty?
      # Every bucket in this account is excluded, OR there are no
      # buckets. Either way, vacuous pass: no buckets to enforce against.
      describe 'S3 MFA Delete scope' do
        it 'has no in-scope buckets to enforce against (every bucket excluded or no buckets in account)' do
          expect(in_scope).to eq([])
        end
      end
    else
      in_scope.each do |bucket_name|
        describe aws_s3_bucket_versioning(bucket_name: bucket_name) do
          it { should exist }
          its('status')     { should cmp 'Enabled' }
          its('mfa_delete') { should cmp 'Enabled' }
        end
      end
    end
  end
end
