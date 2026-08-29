# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure AWS Config is enabled in all regions'
  desc  "
    AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration items (AWS resources), relationships between configuration items (AWS resources), and any configuration changes between resources. It is recommended that AWS Config be enabled in all regions. In environments using AWS Control Tower or Landing Zone Accelerator (LZA), AWS Config may be centrally managed and automatically enabled across regions.

    The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.
  "
  desc  'rationale', "
    AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration items (AWS resources), relationships between configuration items (AWS resources), and any configuration changes between resources. It is recommended that AWS Config be enabled in all regions. In environments using AWS Control Tower or Landing Zone Accelerator (LZA), AWS Config may be centrally managed and automatically enabled across regions.

    The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.
  "
  desc  'check', "
    Process to evaluate AWS Config configuration per region:

    From Console:

    1. Sign in to the AWS Management Console and open the AWS Config console at [https://console.aws.amazon.com/config/](https://console.aws.amazon.com/config/).
    2. On the top right of the console select the target region.
    3. If a Config Recorder is enabled in this region, you should navigate to the Settings page from the navigation menu on the left-hand side. If a Config Recorder is not yet enabled in this region, proceed to the remediation steps.
    4. Ensure \"Record all resources supported in this region\" is checked.
    5. Ensure \"Include global resources (e.g., AWS IAM resources)\" is checked, unless it is enabled in another region (this is only required in one region).
    6. Ensure the correct S3 bucket has been defined.
    7. Ensure the correct SNS topic has been defined.
    8. Repeat steps 2 to 7 for each region.

    Note: In environments using AWS Control Tower or Landing Zone Accelerator (LZA), AWS Config configuration may be managed centrally. Verify that AWS Config is enabled and recording through the centralized governance solution.

    From Command Line:

    1. Run this command to show all AWS Config Recorders and their properties:
    ```
    aws configservice describe-configuration-recorders
    ```
    2. Evaluate the output to ensure that all recorders have a `recordingGroup` object which includes `\"allSupported\": true`. Additionally, ensure that at least one recorder has `\"includeGlobalResourceTypes\": true`.

    Note: There is one more parameter, \"ResourceTypes,\" in the recordingGroup object. We don't need to check it, as whenever we set \"allSupported\" to true, AWS enforces the resource types to be empty (\"ResourceTypes\": []).

    Sample output:

    ```
    {
        \"ConfigurationRecorders\": [
            {
                \"recordingGroup\": {
                    \"allSupported\": true,
                    \"resourceTypes\": [],
                    \"includeGlobalResourceTypes\": true
                },
                \"roleARN\": \"arn:aws:iam:: :role/service-role/ \",
                \"name\": \"default\"
            }
        ]
    }
    ```

    3. Run this command to show the status for all AWS Config Recorders:
    ```
    aws configservice describe-configuration-recorder-status
    ```
    4. In the output, find recorders with `name` key matching the recorders that were evaluated in step 2. Ensure that they include `\"recording\": true` and `\"lastStatus\": \"SUCCESS\"`.
  "
  desc  'fix', "
    To implement AWS Config configuration:

    From Console:

    1. Select the region you want to focus on in the top right of the console.
    2. Click `Services`.
    3. Click `Config`.
    4. If a Config Recorder is enabled in this region, navigate to the Settings page from the navigation menu on the left-hand side. If a Config Recorder is not yet enabled in this region, select \"Get Started\".
    5. Select \"Record all resources supported in this region\".
    6. Choose to include global resources (IAM resources).
    7. Specify an S3 bucket in the same account or in another managed AWS account.
    8. Create an SNS Topic from the same AWS account or another managed AWS account.

    Note: In AWS Control Tower or Landing Zone Accelerator (LZA) environments, AWS Config setup and recording may be deployed and managed automatically. Configuration changes should be performed through the centralized governance framework rather than directly in individual accounts.

    From Command Line:

    1. Ensure there is an appropriate S3 bucket, SNS topic, and IAM role per the [AWS Config Service prerequisites](http://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html).
    2. Run this command to create a new configuration recorder:
    ```
    aws configservice put-configuration-recorder --configuration-recorder name= ,roleARN=arn:aws:iam:: :role/ --recording-group allSupported=true,includeGlobalResourceTypes=true
    ```
    3. Create a delivery channel configuration file locally which specifies the channel attributes, populated from the prerequisites set up previously:
    ```
    {
      \"name\": \" \",
      \"s3BucketName\": \" \",
      \"snsTopicARN\": \"arn:aws:sns: : : \",
      \"configSnapshotDeliveryProperties\": {
        \"deliveryFrequency\": \"Twelve_Hours\"
      }
    }
    ```
    4. Run this command to create a new delivery channel, referencing the json configuration file made in the previous step:
    ```
    aws configservice put-delivery-channel --delivery-channel file:// .json
    ```
    5. Start the configuration recorder by running the following command:
    ```
    aws configservice start-configuration-recorder --configuration-recorder-name ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0403r1_rule'
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

  mode     = input('aws_config_mode').to_s
  expected = Array(input('expected_config_destinations'))

  # Recorder must exist + be actively recording in this account's
  # current region. (Full all-regions iteration is deferred — see
  # comment block above.)
  describe 'AWS Config recorder' do
    subject { aws_config_recorder }
    it { should exist }
    it { should be_recording }
  end

  # Delivery channel describes where Config snapshots/changes go.
  delivery = aws_config_delivery_channel

  # Destination allowlist — delivery channel's S3 bucket must be in
  # expected_config_destinations[].bucket. Empty allowlist + recorder
  # present = FAIL (consumer must document the architecture).
  if delivery.exists? && expected.empty?
    describe 'expected_config_destinations input' do
      it 'must be populated when an AWS Config delivery channel is present (consumer must declare destinations)' do
        expect(expected).not_to be_empty
      end
    end
  elsif delivery.exists?
    allowed_buckets = expected.map { |e| e.is_a?(Hash) ? e['bucket'] : nil }.compact
    describe "AWS Config delivery channel S3 bucket" do
      subject { delivery.s3_bucket_name }
      it { should be_in allowed_buckets }
    end

    # If consumer declared a per-bucket SNS topic, enforce it matches
    # the delivery channel's actual SNS configuration.
    entry = expected.find { |e| e.is_a?(Hash) && e['bucket'] == delivery.s3_bucket_name }
    expected_sns = entry && entry['sns_topic']
    if expected_sns && !expected_sns.to_s.empty?
      describe "AWS Config delivery channel SNS topic must match expected_config_destinations[].sns_topic" do
        subject { delivery.sns_topic_arn }
        it { should eq expected_sns }
      end
    end
  end

  # Mode-specific assertion — organizational requires the destination
  # to be an aggregator-fed bucket (is_aggregator: true on the matching
  # entry); individual requires a local-account destination.
  if delivery.exists? && expected.any?
    entry = expected.find { |e| e.is_a?(Hash) && e['bucket'] == delivery.s3_bucket_name }
    case mode
    when 'organizational'
      describe "AWS Config mode=organizational: delivery destination must be an aggregator-fed bucket" do
        subject { entry && entry['is_aggregator'] == true }
        it { should eq true }
      end
    when 'individual'
      this_account = current_account_id.to_s
      describe "AWS Config mode=individual: delivery destination must be owned by this account #{this_account}" do
        subject { entry && entry['account_id'].to_s == this_account }
        it { should eq true }
      end
    when 'hybrid'
      # Hybrid mode accepts either local or aggregator destination —
      # any allowlist entry is fine, no extra assertion needed beyond
      # the destination allowlist match above.
    end
  end
end
