# encoding: UTF-8

control 'C-3.1.1' do
  title 'Ensure S3 Bucket Policy is set to deny HTTP requests'
  desc  "
    At the Amazon S3 bucket level, permissions can be configured through a bucket policy to ensure objects are accessible only through HTTPS.

    By default, Amazon S3 allows both HTTP and HTTPS requests. To ensure that access to S3 objects is only permitted through HTTPS, you must explicitly deny HTTP requests. Bucket policies that allow HTTPS requests without explicitly denying HTTP requests do not meet this requirement.
  "
  desc  'rationale', "
    At the Amazon S3 bucket level, permissions can be configured through a bucket policy to ensure objects are accessible only through HTTPS.

    By default, Amazon S3 allows both HTTP and HTTPS requests. To ensure that access to S3 objects is only permitted through HTTPS, you must explicitly deny HTTP requests. Bucket policies that allow HTTPS requests without explicitly denying HTTP requests do not meet this requirement.
  "
  desc  'check', "
    From Console:

    1. Login to the AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
    2. Select the target bucket
    3. Select the 'Permissions' tab
    4. Select `Bucket policy`
    5. Ensure a policy exists that explicitly denies HTTP requests using one of the following conditions:

    Option 1: Deny non-HTTPS requests

    ```
    {
        \"Sid\": ,
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": \"arn:aws:s3::: /*\",
        \"Condition\": {
            \"Bool\": {
                \"aws:SecureTransport\": \"false\"
            }
        }
    }
    ```
    Option 2: Enforce minimum TLS version

    ```
    {
        \"Sid\": \" \",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": [
            \"arn:aws:s3::: \",
            \"arn:aws:s3::: /*\"
        ],
        \"Condition\": {
            \"NumericLessThan\": {
                \"s3:TlsVersion\": \"1.2\"
            }
        }
    }
    ```

    6. Repeat for all S3 buckets


    From Command Line:

    1. List all of the S3 Buckets:

    ```
    aws s3 ls
    ```

    2. For each bucket, run:

    ```
    aws s3api get-bucket-policy --bucket | grep aws:SecureTransport
    ```
    or
    ```
    aws s3api get-bucket-policy --bucket | grep s3:TlsVersion
    ```
    3. Verify the policy includes either:
    - `\"aws:SecureTransport\": \"false\"` with `\"Effect\": \"Deny\"`
    - or a TLS version restriction using \"s3:TlsVersion\"
    4. If no policy is returned, the bucket allows both HTTP and HTTPS requests by default
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and open the Amazon S3 console
    2. Select the bucket
    3. Select the `Permissions` tab
    4. Select `Bucket policy`
    5. Add one of the following statements to the policy

    Deny HTTP requests:

    ```
    {
        \"Sid\": ,
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": \"arn:aws:s3::: /*\",
        \"Condition\": {
            \"Bool\": {
                \"aws:SecureTransport\": \"false\"
            }
        }
    }
    ```
    Enforce TLS version:

    ```
    {
        \"Sid\": \" \",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": [
            \"arn:aws:s3::: \",
            \"arn:aws:s3::: /*\"
        ],
        \"Condition\": {
            \"NumericLessThan\": {
                \"s3:TlsVersion\": \"1.2\"
            }
        }
    }
    ```
    6. Save the policy
    7. Repeat for all relevant buckets

    From Console 

    Using AWS Policy Generator:

    1. Repeat steps 1-4 above
    2. Click on `Policy Generator` at the bottom of the Bucket Policy editor
    3. Select `S3 Bucket Policy` as the policy type
    4. Configure the statement:
    - `Effect` = Deny
    - `Principal` = *
    - `AWS Service` = Amazon S3
    - `Actions` = *
    - `Amazon Resource Name` = 5. Select `Generate Policy`
    6. Copy the generated policy and add it to the bucket policy

    From Command Line:

    1. Export the existing policy, if one exists:

    ```
    aws s3api get-bucket-policy --bucket --query Policy --output text > policy.json
    ```
    If the bucket does not already have a policy, create a new `policy.json` file containing a valid bucket policy document.

    2. Modify `policy.json` to include one of the following deny statements within the `Statement` array.

    Option 1: Deny HTTP requests

    ```
    {
        \"Sid\": ,
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": \"arn:aws:s3::: /*\",
        \"Condition\": {
            \"Bool\": {
                \"aws:SecureTransport\": \"false\"
            }
        }
    }
    ```
    Option 2: Enforce minimum TLS version

    ```
    {
        \"Sid\": \" \",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": [
            \"arn:aws:s3::: \",
            \"arn:aws:s3::: /*\"
        ],
        \"Condition\": {
            \"NumericLessThan\": {
                \"s3:TlsVersion\": \"1.2\"
            }
        }
    }
    ```
    3. Apply the modified policy back to the S3 bucket:

    ```
    aws s3api put-bucket-policy --bucket --policy file://policy.json
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag nist_r4:               ['SC-8']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '3.1.1'
  tag cis_rid:               '3.1.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030101r1_rule'
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

  # Every bucket must reject non-TLS (HTTP) requests. inspec-aws
  # checks this via the bucket policy's aws:SecureTransport condition.
  aws_s3_buckets.bucket_names.each do |name|
    describe aws_s3_bucket(bucket_name: name) do
      it { should have_secure_transport_enabled }
    end
  end
end
