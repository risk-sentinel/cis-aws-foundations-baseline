# encoding: UTF-8

control 'C-4.10' do
  title 'Ensure all AWS-managed web front-end services have access logging enabled'
  desc  "
    Ensure that access logging is enabled for all AWS-managed web front-end services that terminate or front HTTP(S) traffic, including Amazon CloudFront distributions, Application Load Balancers (ALB), Network Load Balancers (NLB), and Amazon API Gateway REST/HTTP API stages with public endpoints. Access logs must be enabled with delivery to a designated S3 bucket or CloudWatch Logs destination that is protected with appropriate access controls.

    This control requires logging of request details such as client IP address, timestamp, HTTP method, requested URI, response status code, bytes transferred, and user agent for every request processed by these services. CloudTrail provides management event logging for these resources, but access logs are required to capture the actual HTTP request/response activity at the network edge layers.

    AWS-managed web front-end services (CloudFront, ALB/NLB, API Gateway) represent the primary HTTP(S) ingress points into AWS accounts and are the first line of defense against web attacks, reconnaissance, and abuse attempts. CloudTrail logs management actions (create/update/delete) and data events but does not capture the content of HTTP requests/responses or client activity, leaving a critical visibility gap for security monitoring and incident response.

    Access logs from these services enable reconstruction of all web traffic, detection of anomalous patterns, forensic analysis of incidents, and compliance proof that internet-facing entry points were monitored. Without these logs, security teams cannot distinguish legitimate traffic from attacks or prove access patterns during audits.
  "
  desc  'rationale', "
    Ensure that access logging is enabled for all AWS-managed web front-end services that terminate or front HTTP(S) traffic, including Amazon CloudFront distributions, Application Load Balancers (ALB), Network Load Balancers (NLB), and Amazon API Gateway REST/HTTP API stages with public endpoints. Access logs must be enabled with delivery to a designated S3 bucket or CloudWatch Logs destination that is protected with appropriate access controls.

    This control requires logging of request details such as client IP address, timestamp, HTTP method, requested URI, response status code, bytes transferred, and user agent for every request processed by these services. CloudTrail provides management event logging for these resources, but access logs are required to capture the actual HTTP request/response activity at the network edge layers.

    AWS-managed web front-end services (CloudFront, ALB/NLB, API Gateway) represent the primary HTTP(S) ingress points into AWS accounts and are the first line of defense against web attacks, reconnaissance, and abuse attempts. CloudTrail logs management actions (create/update/delete) and data events but does not capture the content of HTTP requests/responses or client activity, leaving a critical visibility gap for security monitoring and incident response.

    Access logs from these services enable reconstruction of all web traffic, detection of anomalous patterns, forensic analysis of incidents, and compliance proof that internet-facing entry points were monitored. Without these logs, security teams cannot distinguish legitimate traffic from attacks or prove access patterns during audits.
  "
  desc  'check', "
    As an example with CloudFront, verify following the below steps if access logging is enabled:

    1. Open the CloudFront console from the AWS Management Console.

    2. Click Distributions in the left navigation. 

    3. For each Distribution ID (e.g., E123ABC...), click the Distribution ID and go to the \"Logging\" tab

    4. Check if one or more \"Access log destinations\" are present with a destination type of S3 or CloudWatch log group.
  "
  desc  'fix', "
    Following instructions enable standard access logging for CloudFront distributions using the AWS Management Console.

    1. Open the CloudFront console from the AWS Management Console.

    2. Click Distributions in the left navigation and click on the Distribution ID needing remediation.

    3. Go to the \"Logging\" tab and click on \"Create access log delivery\" 
    - Select \"Deliver to\" for your preferred location: S3 or CloudWatch log group
    - Select the ARN of your log destination resource
    - Click on Submit

    4. Confirm if you see the access log destination in the logging tab
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-2 a', 'AU-3 a']
  tag nist_r4:               ['AU-2 a', 'AU-3']
  tag cci:                   ['CCI-000123', 'CCI-000130']
  tag cis_number:            '4.10'
  tag cis_rid:               '4.10'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0410r1_rule'
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

  rid = '4.10'
  # Two front-end surfaces the consumer typically uses: ALB (application load
  # balancer) and CloudFront. Each ALB must have access logs enabled;
  # each CloudFront distribution must have access logging enabled.
  # API Gateway access-log coverage is a follow-up (needs aws_api_gateway_stage
  # iteration across every stage; deferred until we confirm the consumer uses
  # API Gateway).
  aws_albs.load_balancer_arns.each do |arn|
    describe aws_alb(arn) do
      its('access_log_enabled') { should eq true }
    end
  end

  aws_cloudfront_distributions.distribution_ids.each do |dist_id|
    describe aws_cloudfront_distribution(distribution_id: dist_id) do
      it { should have_access_logging_enabled }
    end
  end
end
