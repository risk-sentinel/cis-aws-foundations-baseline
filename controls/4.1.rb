# encoding: UTF-8

control 'C-4.1' do
  title 'Ensure CloudTrail is enabled in all regions'
  desc  "
    AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation).

    The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally, 

    - ensuring that a multi-region trail exists will help detect unexpected activity occurring in otherwise unused regions 

    - ensuring that a multi-region trail exists will ensure that `Global Service Logging` is enabled for a trail by default to capture recordings of events generated on AWS global services

    - for a multi-region trail, ensuring that management events are configured for all types of Read/Writes ensures the recording of management operations that are performed on all resources in an AWS account
  "
  desc  'rationale', "
    AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation).

    The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally, 

    - ensuring that a multi-region trail exists will help detect unexpected activity occurring in otherwise unused regions 

    - ensuring that a multi-region trail exists will ensure that `Global Service Logging` is enabled for a trail by default to capture recordings of events generated on AWS global services

    - for a multi-region trail, ensuring that management events are configured for all types of Read/Writes ensures the recording of management operations that are performed on all resources in an AWS account
  "
  desc  'check', "
    Perform the following to determine if CloudTrail is enabled for all regions:

    From Console:

    1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
    2. Click on `Trails` in the left navigation pane
      - You will be presented with a list of trails across all regions
    3. Ensure that at least one Trail has `Yes` specified in the `Multi-region trail` column
    4. Click on a trail via the link in the `Name` column
    5. Ensure `Logging` is set to `ON` 
    6. Ensure `Multi-region trail` is set to `Yes`
    7. In the section `Management Events`, ensure that `API activity` set to `ALL`

    From Command Line:
    1. List all trails:
    ```
     aws cloudtrail describe-trails
    ```
    2. Ensure `IsMultiRegionTrail` is set to `true`:
    ```
    aws cloudtrail get-trail-status --name ```
    3. Ensure `IsLogging` is set to `true`:
    ```
    aws cloudtrail get-event-selectors --trail-name ```
    4. Ensure there is at least one `fieldSelector` for a trail that equals `Management`:

    - This should NOT output any results for Field: \"readOnly\". If either `true` or `false` is returned, one of the checkboxes (`read` or `write`) is not selected.

    Example of correct output:
    ```
    \"TrailARN\": \" \",
        \"AdvancedEventSelectors\": [
            {
                \"Name\": \"Management events selector\",
                \"FieldSelectors\": [
                    {
                        \"Field\": \"eventCategory\",
                        \"Equals\": [
                            \"Management\"
                        ]
     ```
  "
  desc  'fix', "
    Perform the following to enable global (Multi-region) CloudTrail logging:

    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail).
    2. Click on `Trails` in the left navigation pane.
    3. Click `Get Started Now` if it is presented, then:
      - Click `Add new trail`.
      - Enter a trail name in the `Trail name` box.
        - A trail created in the console is a multi-region trail by default.
      - Specify an S3 bucket name in the `S3 bucket` box.
      - Specify the AWS KMS alias under the `Log file SSE-KMS encryption` section, or create a new key.
      - Click `Next`.
    4. Ensure the `Management events` check box is selected.
    5. Ensure both `Read` and `Write` are checked under API activity.
    6. Click `Next`.
    7. Review your trail settings and click `Create trail`.

    From Command Line:

    Create a multi-region trail:
    ```
    aws cloudtrail create-trail --name --bucket-name --is-multi-region-trail 
    ```
    Enable multi-region on an existing trail:
    ```
    aws cloudtrail update-trail --name --is-multi-region-trail
    ```

    Note: Creating a CloudTrail trail via the CLI without providing any overriding options configures all `read` and `write` `Management Events` to be logged by default.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-3 a']
  tag nist_r4:               ['AC-2 f', 'AU-3']
  tag cci:                   ['CCI-000011', 'CCI-000130']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0401r1_rule'
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

  mode     = input('cloudtrail_mode').to_s
  expected = Array(input('expected_cloudtrail_destinations'))

  # Enumerate every trail reaching this account (shadow trails included
  # by AWS SDK default — an org-trail owned by the management account
  # appears in describe_trails when called from a member account).
  trail_names = aws_cloudtrail_trails.names
  trails      = trail_names.map { |n| aws_cloudtrail_trail(trail_name: n) }
  covering    = trails.select { |t| t.exists? && t.logging? }

  # Coverage assertion — at least one multi-region trail must be
  # actively logging mgmt events R/W. This is the CIS 4.1 literal.
  describe 'At least one active multi-region CloudTrail must cover this account' do
    subject { covering.select(&:multi_region_trail?).any? { |t| t.has_event_selector_mgmt_events_rw_type_all? } }
    it { should eq true }
  end

  # Destination allowlist — every covering trail's S3 destination must
  # appear in the consumer-declared `expected_cloudtrail_destinations`.
  # Empty allowlist + any covering trail = FAIL (consumer must document).
  # When covering.empty? the coverage assertion above already fails the
  # control; we skip destination validation in that case.
  if covering.any? && expected.empty?
    describe 'expected_cloudtrail_destinations input' do
      it 'must be populated when CloudTrail trails are present (consumer must declare destinations)' do
        expect(expected).not_to be_empty
      end
    end
  elsif covering.any?
    allowed_buckets = expected.map { |e| e.is_a?(Hash) ? e['bucket'] : nil }.compact
    covering.each do |trail|
      describe "Trail #{trail.trail_name} S3 destination bucket" do
        subject { trail.s3_bucket_name }
        it { should be_in allowed_buckets }
      end
    end
  end

  # Mode-specific assertion — validates the consumer-declared
  # architecture matches actual trail configuration.
  case mode
  when 'organizational'
    describe "CloudTrail mode=organizational: an organization trail must cover this account" do
      subject { covering.any?(&:organization_trail?) }
      it { should eq true }
    end
  when 'individual'
    this_account = current_account_id.to_s
    describe "CloudTrail mode=individual: a local (non-org) trail must exist in this account #{this_account}" do
      subject do
        covering.any? do |t|
          !t.organization_trail? && t.trail_arn.to_s.include?(":#{this_account}:")
        end
      end
      it { should eq true }
    end
  when 'hybrid'
    this_account = current_account_id.to_s
    describe "CloudTrail mode=hybrid: organization trail must cover this account" do
      subject { covering.any?(&:organization_trail?) }
      it { should eq true }
    end
    describe "CloudTrail mode=hybrid: local trail must exist in this account #{this_account}" do
      subject do
        covering.any? do |t|
          !t.organization_trail? && t.trail_arn.to_s.include?(":#{this_account}:")
        end
      end
      it { should eq true }
    end
  end
end
