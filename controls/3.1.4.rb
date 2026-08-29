# encoding: UTF-8

control 'C-3.1.4' do
  title 'Ensure that S3 is configured with \'Block Public Access\' enabled'
  desc  "
    Amazon S3 provides `Block public access (bucket settings)` and `Block public access (account settings)` to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, `Block public access (bucket settings)` prevents an individual bucket and its contained objects from becoming publicly accessible. Similarly, `Block public access (account settings)` prevents all buckets and their contained objects from becoming publicly accessible across the entire account.

    Amazon S3 `Block public access (bucket settings)` prevents the accidental or malicious public exposure of data contained within the respective bucket(s).  

    Amazon S3 `Block public access (account settings)` prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account.

    Whether to block public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.
  "
  desc  'rationale', "
    Amazon S3 provides `Block public access (bucket settings)` and `Block public access (account settings)` to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, `Block public access (bucket settings)` prevents an individual bucket and its contained objects from becoming publicly accessible. Similarly, `Block public access (account settings)` prevents all buckets and their contained objects from becoming publicly accessible across the entire account.

    Amazon S3 `Block public access (bucket settings)` prevents the accidental or malicious public exposure of data contained within the respective bucket(s).  

    Amazon S3 `Block public access (account settings)` prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account.

    Whether to block public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.
  "
  desc  'check', "
    If utilizing Block Public Access (bucket settings)

    From Console:

    1. Login to the AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/.
    2. Click Bucket name.
    3. Click on Permissions tab and check \"Block public access (bucket settings)\".
    4. Ensure that the block public access settings are configured appropriately for this bucket.
    5. Repeat for all the buckets in your AWS account.

    From Command Line:

    1. List all of the S3 buckets:
    ```
    aws s3 ls
    ```
    2. Find the public access settings for a specific bucket:
    ```
    aws s3api get-public-access-block --bucket ```
    Output if Block Public Access is enabled:

    ```
    {
        \"PublicAccessBlockConfiguration\": {
            \"BlockPublicAcls\": true,
            \"IgnorePublicAcls\": true,
            \"BlockPublicPolicy\": true,
            \"RestrictPublicBuckets\": true
        }
    }
    ```

    If the output reads `false` for the separate configuration settings, then proceed with the remediation.

    If utilizing Block Public Access (account settings)

    From Console:

    1. Login to the AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/.
    2. Choose `Block public access (account settings)`.
    3. Ensure that the block public access settings are configured appropriately for your AWS account.

    From Command Line:

    To check the block public access settings for this account, run the following command:
    `aws s3control get-public-access-block --account-id --region `

    Output if Block Public Access is enabled:

    ```
    {
        \"PublicAccessBlockConfiguration\": {
            \"IgnorePublicAcls\": true, 
            \"BlockPublicPolicy\": true, 
            \"BlockPublicAcls\": true, 
            \"RestrictPublicBuckets\": true
        }
    }
    ```

    If the output reads `false` for the separate configuration settings, then proceed with the remediation.
  "
  desc  'fix', "
    If utilizing Block Public Access (bucket settings)

    From Console:

    1. Login to the AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/. 
    2. Select the check box next to a bucket.
    3. Click 'Edit public access settings'.
    4. Click 'Block all public access'
    5. Repeat for all the buckets in your AWS account that contain sensitive data.

    From Command Line:

    1. List all of the S3 buckets:
    ```
    aws s3 ls
    ```
    2. Enable Block Public Access on a specific bucket:
    ```
    aws s3api put-public-access-block --bucket --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"
    ```

    If utilizing Block Public Access (account settings)

    From Console:

    If the output reads `true` for the separate configuration settings, then Block Public Access is enabled on the account.

    1. Login to the AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/.
    2. Click `Block Public Access (account settings)`.
    3. Click `Edit` to change the block public access settings for all the buckets in your AWS account.
    4. Update the settings and click `Save`. 
    5. When you're asked for confirmation, enter `confirm`. Then click `Confirm` to save your changes.

    From Command Line:

    To enable Block Public Access for this account, run the following command:
    ```
    aws s3control put-public-access-block
    --public-access-block-configuration BlockPublicAcls=true, IgnorePublicAcls=true, BlockPublicPolicy=true, RestrictPublicBuckets=true
    --account-id ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.1.4'
  tag cis_rid:               '3.1.4'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030104r1_rule'
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

  # Bucket-level Block Public Access must be on for every bucket.
  # Account-level BPA (a separate setting) is not exposed by
  # inspec-aws 1.83.63 — check bucket-level here and track
  # account-level as a follow-up.
  aws_s3_buckets.bucket_names.each do |name|
    describe aws_s3_bucket(bucket_name: name) do
      its('prevent_public_access?') { should eq true }
    end
  end
end
