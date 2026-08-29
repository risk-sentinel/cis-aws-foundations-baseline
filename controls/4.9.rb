# encoding: UTF-8

control 'C-4.9' do
  title 'Ensure that object-level logging for read events is enabled for S3 buckets'
  desc  "
    S3 object-level API operations, such as GetObject, DeleteObject, and PutObject, are referred to as data events. By default, CloudTrail trails do not log data events, so it is recommended to enable object-level logging for S3 buckets.

    Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analyses, monitor specific patterns of user behavior in your AWS account, or take immediate actions on any object-level API activity within your S3 buckets using Amazon CloudWatch Events.
  "
  desc  'rationale', "
    S3 object-level API operations, such as GetObject, DeleteObject, and PutObject, are referred to as data events. By default, CloudTrail trails do not log data events, so it is recommended to enable object-level logging for S3 buckets.

    Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analyses, monitor specific patterns of user behavior in your AWS account, or take immediate actions on any object-level API activity within your S3 buckets using Amazon CloudWatch Events.
  "
  desc  'check', "
    From Console:

    1. Login to the AWS Management Console and navigate to the CloudTrail dashboard at `https://console.aws.amazon.com/cloudtrail/`.
    2. In the left panel, click `Trails`, and then click the name of the trail that you want to examine.
    3. Review `General details`.
    4. Confirm that `Multi-region trail` is set to `Yes`
    5. Scroll down to `Data events`
    5. Scroll down to `Data events` and confirm the configuration:
    - If `advanced event selectors` is being used, it should read:
    ```
    Data Events: S3
    Log selector template
    Log all events
    ```
    - If `basic event selectors` is being used, it should read:
    ```
    Data events: S3
    Bucket Name: All current and future S3 buckets
    Read: Enabled
    ```
    6. Repeat steps 2-5 to verify that each trail has multi-region enabled and is configured to log data events. If a trail does not have multi-region enabled and data event logging configured, refer to the remediation steps.

    From Command Line:

    1. Run the `describe-trails` command to list all trail names:
    ```
    aws cloudtrail describe-trails --region --output table --query trailList[*].Name
    ```
    2. The command output will be table of the trail names.
    3. For each trail, run the `get-trail` command to verify it is a multi-regional trail:
    ```
    aws cloudtrail get-trail --region --name \\ --query 'Trail.IsMultiRegionTrail'
    ```
    4. Run the `get-event-selectors` command using the name of a trail returned at the previous step and custom query filters to determine if data event logging is configured:
    ```
    aws cloudtrail get-event-selectors --region --trail-name --query EventSelectors[*].DataResources[]
    ```
    5. The command output should be an array that includes the S3 bucket defined for data event logging.
    6. If the `get-event-selectors` command returns an empty array, data events are not included in the trail's logging configuration; therefore, object-level API operations performed on S3 buckets within your AWS account are not being recorded.
    7. Repeat steps 1-5 to verify the configuration of each trail.
    8. Change the AWS region by updating the `--region` command parameter, and perform the audit process for other regions.
  "
  desc  'fix', "
    From Console:

    1. Login to the AWS Management Console and navigate to S3 dashboard at `https://console.aws.amazon.com/s3/`.
    2. In the left navigation panel, click `buckets` and then click the name of the S3 bucket that you want to examine.
    3. Click the `Properties` tab to see the bucket configuration in detail.
    4. In the `AWS Cloud Trail data events` section, select the trail name for recording activity. You can choose an existing trail or create a new one by clicking the `Configure in CloudTrail` button or navigating to the [CloudTrail console](https://console.aws.amazon.com/cloudtrail/).
    5. Once the trail is selected, select the `Data Events` check box.
    6. Select `S3` from the `Data event type` drop-down.
    7. Select `Log all events` from the `Log selector template` drop-down.
    8. Repeat steps 2-7 to enable object-level logging of read events for other S3 buckets.

    From Command Line:

    1. To enable `object-level` data events logging for S3 buckets within your AWS account, run the `put-event-selectors` command using the name of the trail that you want to reconfigure as identifier:
    ```
    aws cloudtrail put-event-selectors --region --trail-name --event-selectors '[{ \"ReadWriteType\": \"ReadOnly\", \"IncludeManagementEvents\":true, \"DataResources\": [{ \"Type\": \"AWS::S3::Object\", \"Values\": [\"arn:aws:s3::: /\"] }] }]'
    ```
    2. The command output will be `object-level` event trail configuration.
    3. If you want to enable it for all buckets at once, change the Values parameter to `[\"arn:aws:s3\"]` in the previous command.
    4. Repeat step 1 for each s3 bucket to update `object-level` logging of read events.
    5. Change the AWS region by updating the `--region` command parameter, and perform the process for the other regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag nist_r4:               ['AU-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '4.9'
  tag cis_rid:               '4.9'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0409r1_rule'
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

  rid = '4.9'
  describe aws_cloudtrail_event_selectors(regions: Array(input('scan_regions'))) do
    it { should exist }
    its('logs_s3_object_reads?') { should eq true }
  end
end
