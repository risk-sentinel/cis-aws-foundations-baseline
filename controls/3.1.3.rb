# encoding: UTF-8

control 'C-3.1.3' do
  title 'Ensure all data in Amazon S3 has been discovered, classified, and secured when necessary'
  desc  "
    Amazon S3 buckets can contain sensitive data that, for security purposes, should be discovered, monitored, classified, and protected. Macie, along with other third-party tools, can automatically provide an inventory of Amazon S3 buckets.

    Using a cloud service or third-party software to continuously monitor and automate the process of data discovery and classification for S3 buckets through machine learning and pattern matching is a strong defense in protecting that information.

    Amazon Macie is a fully managed data security and privacy service that uses machine learning and pattern matching to discover and protect your sensitive data in AWS.
  "
  desc  'rationale', "
    Amazon S3 buckets can contain sensitive data that, for security purposes, should be discovered, monitored, classified, and protected. Macie, along with other third-party tools, can automatically provide an inventory of Amazon S3 buckets.

    Using a cloud service or third-party software to continuously monitor and automate the process of data discovery and classification for S3 buckets through machine learning and pattern matching is a strong defense in protecting that information.

    Amazon Macie is a fully managed data security and privacy service that uses machine learning and pattern matching to discover and protect your sensitive data in AWS.
  "
  desc  'check', "
    Perform the following steps to determine if Macie is running:

    From Console:

    1. Login to the Macie console at https://console.aws.amazon.com/macie/.

    2. In the left hand pane, click on `By job` under findings.

    3. Confirm that you have a job set up for your S3 buckets.

    When you log into the Macie console, if you are not taken to the summary page and do not have a job set up and running, then refer to the remediation procedure below.

    If you are using a third-party tool to manage and protect your S3 data, you meet this recommendation.
  "
  desc  'fix', "
    Perform the steps below to enable and configure Amazon Macie:

    From Console:

    1. Log on to the Macie console at `https://console.aws.amazon.com/macie/`.

    2. Click `Get started`.

    3. Click `Enable Macie`.

    Set up a repository for sensitive data discovery results:

    1. In the left pane, under Settings, click `Discovery results`.

    2. Make sure `Create bucket` is selected.

    3. Create a bucket and enter a name for it. The name must be unique across all S3 buckets, and it must start with a lowercase letter or a number.

    4. Click `Advanced`.

    5. For block all public access, make sure `Yes` is selected.

    6. For KMS encryption, specify the AWS KMS key that you want to use to encrypt the results. The key must be a symmetric customer master key (CMK) that is in the same region as the S3 bucket.

    7. Click `Save`.

    Create a job to discover sensitive data:

    1. In the left pane, click `S3 buckets`. Macie displays a list of all the S3 buckets for your account.

    2. Check the box for each bucket that you want Macie to analyze as part of the job.

    3. Click `Create job`.

    4. Click `Quick create`.

    5. For the Name and Description step, enter a name and, optionally, a description of the job.

    6. Click `Next`.

    7. For the Review and create step, click `Submit`.

    Review your findings:

    1. In the left pane, click `Findings`.

    2. To view the details of a specific finding, choose any field other than the check box for the finding.

    If you are using a third-party tool to manage and protect your S3 data, follow the vendor documentation for implementing and configuring that tool.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'AC-2 a']
  tag cci:                   ['CCI-001315', 'CCI-002110']
  tag cis_number:            '3.1.3'
  tag cis_rid:               '3.1.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-030103r1_rule'
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

  # Per-region check — Macie sessions and classification jobs are
  # regional. The scanner's home region is checked here; for full
  # coverage the profile should be exec'd per region (or scan_regions
  # iteration added later if cross-region Macie aggregation lands).
  session = aws_macie_session

  if session.connection_error
    describe "Macie classification coverage (#{ENV['AWS_REGION'] || 'home region'})" do
      it 'is reachable' do
        expect(session.connection_error).to be_nil, session.connection_error
      end
    end
  else
    describe session do
      it { should be_enabled }
    end

    describe aws_macie_classification_jobs do
      its('active_count') { should be > 0 }
    end
  end
end
