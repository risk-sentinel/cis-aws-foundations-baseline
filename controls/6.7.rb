# encoding: UTF-8

control 'C-6.7' do
  title 'Ensure that the EC2 Metadata Service only allows IMDSv2'
  desc  "
    When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method).

    Instance metadata is data about your instance that you can use to configure or manage the running instance. Instance metadata is divided into [categories](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html), such as host name, events, and security groups.

    When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method). With IMDSv2, every request is now protected by session authentication. A session begins and ends a series of requests that software running on an EC2 instance uses to access the locally stored EC2 instance metadata and credentials.

    Allowing Version 1 of the service may open EC2 instances to Server-Side Request Forgery (SSRF) attacks, so Amazon recommends utilizing Version 2 for better instance security.
  "
  desc  'rationale', "
    When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method).

    Instance metadata is data about your instance that you can use to configure or manage the running instance. Instance metadata is divided into [categories](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html), such as host name, events, and security groups.

    When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method). With IMDSv2, every request is now protected by session authentication. A session begins and ends a series of requests that software running on an EC2 instance uses to access the locally stored EC2 instance metadata and credentials.

    Allowing Version 1 of the service may open EC2 instances to Server-Side Request Forgery (SSRF) attacks, so Amazon recommends utilizing Version 2 for better instance security.
  "
  desc  'check', "
    From Console:

    1. Sign in to the AWS Management Console and navigate to the EC2 dashboard at https://console.aws.amazon.com/ec2/.
    2. In the left navigation panel, under the `Instances` section, choose `Instances`.
    3. Select the EC2 instance that you want to examine.
    4. Check the `IMDSv2` status, and ensure that it is set to `Required`.

    From Command Line:

    1. Run the `describe-instances` command using appropriate filters to list the IDs of all existing EC2 instances currently available in the selected region:
 
        ```
       aws ec2 describe-instances --region --output table --query \"Reservations[*].Instances[*].InstanceId\"
        ```
    The command output should return a table with the requested instance IDs.

    2. Run the `describe-instances` command using the instance ID returned in the previous step and apply custom filtering to determine whether the selected instance is using IMDSv2:

        ```
        aws ec2 describe-instances --region --instance-ids --query \"Reservations[*].Instances[*].MetadataOptions\" --output table
        ```

    3. Ensure that for all EC2 instances, `HttpTokens` is set to `required` and `State` is set to `applied`.
    4. Repeat steps 2 and 3 to verify the other EC2 instances provisioned within the current region.
    5. Repeat steps 1-4 to perform the audit process for other AWS regions
    6. Alternatively, the following command can be used to identify instances still using IMDSv1:
    ```
    aws ec2 describe-instances --region --query \"Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'][] | [].{ID: InstanceId, Tokens: MetadataOptions.HttpTokens, State: MetadataOptions.State}\" --output table
    ```
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and navigate to the EC2 dashboard at [https://console.aws.amazon.com/ec2/](https://console.aws.amazon.com/ec2/).
    2. In the left navigation panel, under the `INSTANCES` section, choose `Instances`.
    3. Select the EC2 instance that you want to examine.
    4. Choose `Actions > Instance Settings > Modify instance metadata options`.
    5. Set `Instance metadata service` to `Enable`.
    6. Set `IMDSv2` to `Required`.
    7. Repeat steps 1-6 to perform the remediation process for other EC2 instances in all applicable AWS region(s).

    From Command Line:

    1. Run the `describe-instances` command, applying the appropriate filters to list the IDs of all existing EC2 instances currently available in the selected region:

        ```    
        aws ec2 describe-instances --region --output table --query \"Reservations[*].Instances[*].InstanceId\"
        ```

    2. The command output should return a table with the requested instance IDs.
    3. Run the `modify-instance-metadata-options` command with an instance ID obtained from the previous step to update the Instance Metadata Version:

        ```
        aws ec2 modify-instance-metadata-options --instance-id --http-tokens required --region ```

    4. Repeat steps 1-3 to perform the remediation process for other EC2 instances in the same AWS region.
    5. Change the region by updating `--region` and repeat the process for other regions.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-000381', 'CCI-000200']
  tag cis_number:            '6.7'
  tag cis_rid:               '6.7'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0607r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  # Empty collection => Not Applicable, never silence. See README, "Empty collections".
  instance_ids = aws_ec2_instances.instance_ids
  applicable           = applicable_partition && !instance_ids.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}) or no EC2 instances in this account") do
    applicable
  end

  # Every EC2 instance must require IMDSv2 (http_tokens=required).
  # aws_ec2_instance is built via create_resource_methods, which exposes
  # the metadata_options struct as a method returning the AWS SDK
  # InstanceMetadataOptionsResponse struct directly. Use string-chain
  # form `its('metadata_options.http_tokens')` — RSpec/InSpec interprets
  # this as `subject.metadata_options.http_tokens` (sequential method
  # calls). The earlier array form `its(%w(metadata_options http_tokens))`
  # was interpreted as a single Hash#[] key access and returned
  # NullResponse against the SDK struct — see CI run 25582602482.
  instance_ids.each do |id|
    describe aws_ec2_instance(id) do
      its('metadata_options.http_tokens') { should eq 'required' }
    end
  end
end
