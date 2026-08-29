# encoding: UTF-8

control 'C-5.12' do
  title 'Ensure changes to network gateways are monitored'
  desc  "
    Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs or an external Security Information and Event Management (SIEM) environment, and establishing corresponding metric filters and alarms. 

    Network gateways are required to send and receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways.

    CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail logs can also be sent to an external Security Information and Event Management (SIEM) environment for monitoring and alerting.

    Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.
  "
  desc  'rationale', "
    Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs or an external Security Information and Event Management (SIEM) environment, and establishing corresponding metric filters and alarms. 

    Network gateways are required to send and receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways.

    CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail logs can also be sent to an external Security Information and Event Management (SIEM) environment for monitoring and alerting.

    Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.
  "
  desc  'check', "
    If you are using CloudTrail trails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail trail with the prescribed metric filters and alarms configured:

    1. Identify the log group name that is configured for use with the active multi-region CloudTrail trail:

    - List all CloudTrail trails: `aws cloudtrail describe-trails`

    - Identify multi-region CloudTrail trails: `Trails with \"IsMultiRegionTrail\" set to true`

    - Note the value associated with \"Name\":` `

    - Note the ` ` within the value associated with \"CloudWatchLogsLogGroupArn\"

      - Example: `arn:aws:logs: : :log-group: :*`

    - Ensure the identified multi-region CloudTrail trail is active:

      - `aws cloudtrail get-trail-status --name `

        - Ensure `IsLogging` is set to `TRUE`

    - Ensure the identified multi-region CloudTrail trail captures all management events:

      - `aws cloudtrail get-event-selectors --trail-name `

        - Ensure there is at least one `event selector` for a trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`

    2. Get a list of all associated metric filters for the ` ` captured in step 1:

        ```
        aws logs describe-metric-filters --log-group-name ```

    3. Ensure the output from the above command contains the following:

        ```
        \"filterPattern\": \"{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }\"
        ```

    4. Note the ` ` value associated with the `filterPattern` from step 3.

    5. Get a list of CloudWatch alarms, and filter on the ` ` captured in step 4:

        ```
        aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== ]'
        ```

    6. Note the `AlarmActions` value; this will provide the SNS topic ARN value.

    7. Ensure there is at least one active subscriber to the SNS topic:

        ```
        aws sns list-subscriptions-by-topic --topic-arn ```

    - At least one subscription should have \"SubscriptionArn\" with a valid AWS ARN.

      - Example of valid \"SubscriptionArn\": `arn:aws:sns: : : : `

    8. Ensure automated monitoring is enabled:

        ```
        aws cloudwatch put-metric-alarm --alarm-name NetworkGatewayChanges --metric-name GatewayChanges --namespace AWS/EC2 --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions ```
  "
  desc  'fix', "
    If you are using CloudTrail trails and CloudWatch, perform the following steps to set up the metric filter, alarm, SNS topic, and subscription:

    1. Create a metric filter based on the provided filter pattern that checks for network gateways changes and uses the ` ` taken from audit step 1:

        ```
        aws logs put-metric-filter --log-group-name --filter-name --metric-transformations metricName= ,metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
       ```

        Note: You can choose your own `metricName` and `metricNamespace` strings. Using the same `metricNamespace` for all Foundations Benchmark metrics will group them together.

    2. Create an SNS topic that the alarm will notify:

        ```
        aws sns create-topic --name ```

        Note: You can execute this command once and then reuse the same topic for all monitoring alarms.

        Note: Capture the `TopicArn` that is displayed when creating the SNS topic in step 2.

    3. Create an SNS subscription for the topic created in step 2:

        ```
        aws sns subscribe --topic-arn --protocol --notification-endpoint ```

        Note: You can execute this command once and then reuse the same subscription for all monitoring alarms.

    4. Create an alarm that is associated with the CloudWatch Logs metric filter created in step 1 and the SNS topic created in step 2:

        ```
        aws cloudwatch put-metric-alarm --alarm-name --metric-name --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions ```

    5. Implement logging and alerting mechanisms:

        ```
        aws sns create-topic --name NetworkGatewayChangesAlerts
        ```

        ```
        aws sns subscribe --topic-arn --protocol email --notification-endpoint ```

        ```
        aws cloudwatch put-metric-alarm --alarm-name NetworkGatewayChangesAlarm --metric-name GatewayChanges --namespace AWS/EC2 --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-3 a', 'AU-3 d']
  tag nist_r4:               ['AC-2 f', 'AU-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000130', 'CCI-000133']
  tag cis_number:            '5.12'
  tag cis_rid:               '5.12'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0512r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_role      = input('log_archive_account_id').to_s.empty? || in_log_archive_account?
  applicable           = applicable_partition && applicable_role

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')}, log_archive_account=#{input('log_archive_account_id')}, current_account=#{current_account_id})") do
    applicable
  end

  rid = '5.12'
  # Resolve the CloudTrail-integrated CloudWatch Logs group from the
  # first multi-region active mgmt-RW-all trail. Returns nil if no such
  # trail exists — control 4.1 flags that separately.
  log_group = aws_cloudtrail_trails.names.map { |t|
    aws_cloudtrail_trail(trail_name: t).get_log_group_for_multi_region_active_mgmt_rw_all
  }.compact.first

  pattern = %q{{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }}

  describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: log_group) do
    it { should exist }
  end

  filter = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: log_group)
  if filter.exists?
    describe aws_cloudwatch_alarm(metric_name: filter.metric_name, metric_namespace: filter.metric_namespace) do
      it                 { should exist }
      its('alarm_actions') { should_not be_empty }
    end
  end

end
