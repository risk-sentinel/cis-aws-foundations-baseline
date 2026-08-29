# encoding: UTF-8

control 'C-4.4' do
  title 'Ensure that server access logging is enabled on the CloudTrail S3 bucket'
  desc  "
    Server access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that server access logging be enabled on the CloudTrail S3 bucket.

    By enabling server access logging on target S3 buckets, it is possible to capture all events that may affect objects within any target bucket. Configuring the logs to be placed in a separate bucket allows access to log information that can be useful in security and incident response workflows. In some environments (e.g., AWS Control Tower), logs may be delivered to the same bucket with appropriate prefixes, which is also an acceptable configuration.
  "
  desc  'rationale', "
    Server access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that server access logging be enabled on the CloudTrail S3 bucket.

    By enabling server access logging on target S3 buckets, it is possible to capture all events that may affect objects within any target bucket. Configuring the logs to be placed in a separate bucket allows access to log information that can be useful in security and incident response workflows. In some environments (e.g., AWS Control Tower), logs may be delivered to the same bucket with appropriate prefixes, which is also an acceptable configuration.
  "
  desc  'check', "
    Perform the following ensure that the CloudTrail S3 bucket has access logging is enabled:

    From Console:

    1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home).
    2. In the API activity history pane on the left, click `Trails`.
    3. In the Trails pane, note the bucket names in the S3 bucket column.
    4. Sign in to the AWS Management Console and open the S3 console at [https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
    5. Under `All Buckets`  click on a target S3 bucket.
    6. Click on `Properties` in the top right of the console.
    7. Scroll down to `Server access logging`.
    8. Ensure `Server access logging` is `Enabled`.
    9. Verify the `Target bucket` where logs are delivered.

    From Command Line:

    1. Get the name of the S3 bucket that CloudTrail is logging to:
    ```  
    aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'  
    ```
    2. Ensure logging is enabled on the bucket:
    ```
    aws s3api get-bucket-logging --bucket ```
    Ensure the command does not return an empty output.

    Sample output for a bucket with logging enabled:

    ```
    {
        \"LoggingEnabled\": {
            \"TargetPrefix\": \" \",
            \"TargetBucket\": \" \"
        }
    }
    ```
  "
  desc  'fix', "
    Perform the following to enable server access logging:

    From Console:

    1. Sign in to the AWS Management Console and open the S3 console at [https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
    2. Under `All Buckets` click on the target S3 bucket.
    3. Click on `Properties` in the top right of the console.
    4. Under `Server access logging`, click `Edit`. 
    5. Configure bucket logging:
        - Check the `Enabled` box.
        - Select a Target Bucket from the list.
        - Enter a Target Prefix.
    6. Click `Save`.

    From Command Line:

    1. Get the name of the S3 bucket that CloudTrail is logging to:
    ```
    aws cloudtrail describe-trails --region --query trailList[*].S3BucketName
    ```
    2. Create a logging configuration file and populate the following values:
    ```
    {
    	\"LoggingEnabled\": {
    		\"TargetBucket\": \" \",
    		\"TargetPrefix\": \" \",
    		\"TargetGrants\": [
    			{
    			\"Grantee\": {
    				\"Type\": \"AmazonCustomerByEmail\",
    				\"EmailAddress\": \"\"
    				},
    			\"Permission\": \"FULL_CONTROL\"
    			}
    		]
    	}	
    }
    ```
    3. Save the file as ` .json`
    4. Apply the logging configuration:
    ```
    aws s3api put-bucket-logging --bucket --bucket-logging-status file:// .json
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-2 a', 'AC-2 f', 'SC-12 (3)']
  tag cci:                   ['CCI-000123', 'CCI-000011', 'CCI-002447']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0404r1_rule'
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

  # For every trail reaching this account, confirm its destination S3
  # bucket has server access logging enabled. When the bucket lives in
  # a different account (org-trail to log-archive), the AWS S3 API may
  # not return access-logging state — that case is handled by skipping
  # the assertion only when aws_s3_bucket reports the bucket as
  # non-existent or inaccessible. Trail-coverage itself is in C-4.1.
  trail_names = aws_cloudtrail_trails.names
  trail_names.each do |trail_name|
    trail  = aws_cloudtrail_trail(trail_name: trail_name)
    bucket = aws_s3_bucket(bucket_name: trail.s3_bucket_name)
    if bucket.exists?
      describe "Trail #{trail.trail_name} S3 bucket #{trail.s3_bucket_name} server access logging" do
        subject { bucket }
        it { should have_access_logging_enabled }
      end
    else
      describe "Trail #{trail.trail_name} S3 bucket #{trail.s3_bucket_name}" do
        skip "Bucket lives in another account (cross-account trail destination); access-logging cannot be queried from this account. Validate in the log-archive account scan."
      end
    end
  end
end
