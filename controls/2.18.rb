# encoding: UTF-8

control 'C-2.18' do
  title 'Ensure that IAM External Access Analyzer is enabled for all regions'
  desc  "
    Enable IAM External Access Analyzer for all resources in each active AWS region.

    IAM Access Analyzer is a service that analyzes resource policies to identify resources that can be accessed from outside the account. After the analyzer is enabled, scan results are displayed in the console showing accessible resources. These results help determine whether unintended access is permitted, making it easier for administrators to monitor least privilege access. Access Analyzer analyzes only policies applied to resources within the same AWS region.

    IAM External Access Analyzer helps identify resources in your account or organization that are shared with external entities. This allows detection of unintended access to resources and data. It continuously monitors policies for services such as S3 buckets, IAM roles, KMS keys, Lambda functions, and SQS queues.
  "
  desc  'rationale', "
    Enable IAM External Access Analyzer for all resources in each active AWS region.

    IAM Access Analyzer is a service that analyzes resource policies to identify resources that can be accessed from outside the account. After the analyzer is enabled, scan results are displayed in the console showing accessible resources. These results help determine whether unintended access is permitted, making it easier for administrators to monitor least privilege access. Access Analyzer analyzes only policies applied to resources within the same AWS region.

    IAM External Access Analyzer helps identify resources in your account or organization that are shared with external entities. This allows detection of unintended access to resources and data. It continuously monitors policies for services such as S3 buckets, IAM roles, KMS keys, Lambda functions, and SQS queues.
  "
  desc  'check', "
    From Console:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam
    2. Under `Access analyzer` choose `Analyzer Settings`
    3. On the `Analyzer Settings` page, review the list of analyzers
    4. Identify analyzers where the `Finding type` is `External Access`
    5. Repeat these steps for each active region, as analyzers are region-specific

    From Command Line:

    1. Run the following command:
    ```
    aws accessanalyzer list-analyzers --type --region | grep status
    ```
    2. Ensure that at least one Analyzer's `status` is set to `ACTIVE`

    3. To check all regions:
    ```
    for r in $(aws ec2 describe-regions --query \"Regions[].RegionName\" --output text); do
      echo \"=== $r ===\"
      aws accessanalyzer list-analyzers --region \"$r\" --type ACCOUNT --query \"analyzers[].status\" --output text
    done
    ```
    4. Ensure each region returns at least one `ACTIVE` analyzer
  "
  desc  'fix', "
    From Console:

    Perform the following to enable IAM Access Analyzer for IAM policies:

    1. Open the IAM console at `https://console.aws.amazon.com/iam/`
    2. Choose `Access analyzer`
    3. Select `Create analyzer`
    4. Select `External access` analyzer
    5. Confirm the region
    6. Optionally provide a name and tags
    7. Select `Create analyzer`
    8. Repeat for each active region

    From Command Line:

    1. Create an analyzer in a region:
    ```
    aws accessanalyzer list-analyzers --type --region | grep status
    ```
    2. Repeat for each region as required
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.18'
  tag cis_rid:               '2.18'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0218r1_rule'
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

  analyzers = aws_iam_access_analyzers(regions: Array(input('scan_regions')))
  if analyzers.respond_to?(:connection_error) && analyzers.connection_error
    describe 'IAM Access Analyzer enumeration' do
      skip "pending-resource: #{analyzers.connection_error}"
    end
  else
    describe analyzers do
      it { should exist }
      its('regions_without_active_analyzer') { should be_empty }
    end
  end
end
