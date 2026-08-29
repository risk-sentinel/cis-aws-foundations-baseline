# encoding: UTF-8

control 'C-4.2' do
  title 'Ensure CloudTrail log file validation is enabled'
  desc  "
    CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or remained unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled for all CloudTrails.

    Enabling log file validation will provide additional integrity checks for CloudTrail logs.
  "
  desc  'rationale', "
    CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or remained unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled for all CloudTrails.

    Enabling log file validation will provide additional integrity checks for CloudTrail logs.
  "
  desc  'check', "
    Perform the following on each trail to determine if log file validation is enabled:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail).
    2. Click on `Trails` in the left navigation pane.
    3. For every trail:
    - Click on a trail via the link in the `Name` column.
    - Under the `General details`  section, ensure `Log file validation` is set to `Enabled`.

    From Command Line:

    List all trails:
    ```
    aws cloudtrail describe-trails
    ```
    Ensure `LogFileValidationEnabled` is set to `true` for each trail.
  "
  desc  'fix', "
    Perform the following to enable log file validation on a given trail:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail).
    2. Click on `Trails` in the left navigation pane.
    3. Click on the target trail.
    4. Within the `General details` section, click `edit`.
    5. Under `Advanced settings`, check the `enable` box under `Log file validation`.
    6. Click `Save changes`. 

    From Command Line:

    Enable log file validation on a trail:

    ```
    aws cloudtrail update-trail --name --enable-log-file-validation
    ```

    Note that periodic validation of logs using these digests can be carried out by running the following command:

    ```
    aws cloudtrail validate-logs --trail-arn --start-time --end-time ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 i 1', 'AU-3 d']
  tag nist_r4:               ['AC-2 i 1', 'AU-3']
  tag cci:                   ['CCI-002126', 'CCI-000133']
  tag cis_number:            '4.2'
  tag cis_rid:               '4.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0402r1_rule'
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

  # Every trail reaching this account (shadow trails included) must have
  # log file validation enabled. The trail-coverage assertion lives in
  # C-4.1; this control narrows to the per-trail integrity flag.
  trail_names = aws_cloudtrail_trails.names
  trails      = trail_names.map { |n| aws_cloudtrail_trail(trail_name: n) }

  trails.each do |trail|
    describe "Trail #{trail.trail_name} log file validation" do
      subject { trail }
      it { should have_log_file_validation_enabled }
    end
  end
end
