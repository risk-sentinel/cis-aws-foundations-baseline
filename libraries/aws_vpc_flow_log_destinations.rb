# VPC Flow Log enumeration with full destination data.
#
# The stock inspec-aws `aws_flow_log` resource only exposes
# `log_group_name` (the CloudWatch Logs name). For CIS 4.7 +
# expected_vpc_flow_log_destinations validation we also need:
#   - log_destination_type ('s3' | 'cloud-watch-logs' | 'kinesis-data-firehose')
#   - log_destination (full ARN)
#   - traffic_type ('ALL' | 'ACCEPT' | 'REJECT')
#   - resource_id (the VPC/subnet/ENI)
#
# Filter columns let controls query e.g.
#   aws_vpc_flow_log_destinations.where(resource_id: 'vpc-abc').entries
# to find every flow log attached to a given VPC across destination types.
#
# Region: this resource enumerates flow logs in the current region only.
# CIS 4.7 is per-region today (the same scope-deferral noted in the
# control body covers all §4 controls).
#
# Depends on `_aws_backend_bootstrap.rb` for the AwsResourceBase / @aws
# accessor pattern.

class AwsVpcFlowLogDestinations < AwsResourceBase
  include RegionEnumeration
  name "aws_vpc_flow_log_destinations"
  desc "VPC Flow Log enumeration with destination_type / destination / traffic_type."
  example "
    describe aws_vpc_flow_log_destinations.where(resource_id: 'vpc-0123abcd') do
      it { should exist }
    end
  "

  attr_reader :table

  FilterTable.create
    .register_column(:flow_log_ids,         field: :flow_log_id)
    .register_column(:resource_ids,         field: :resource_id)
    .register_column(:log_destination_types, field: :log_destination_type)
    .register_column(:log_destinations,     field: :log_destination)
    .register_column(:traffic_types,        field: :traffic_type)
    .register_column(:log_group_names,      field: :log_group_name)
    .register_column(:flow_log_statuses,    field: :flow_log_status)
    .install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    opts = opts.dup
    # Must be removed BEFORE super — AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @all_regions = resolve_regions(region_override)
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  def to_s
    "VPC Flow Log Destinations"
  end

  private

  def fetch_data
    rows = []
    each_region_client(::Aws::EC2::Client) do |client, region|
      next_token = nil
      loop do
        args = { max_results: 1000 }
        args[:next_token] = next_token if next_token
        resp = client.describe_flow_logs(args)
        Array(resp.flow_logs).each do |fl|
          rows << {
            region:               region,
            flow_log_id:          fl.flow_log_id,
            resource_id:          fl.resource_id,
            log_destination_type: fl.log_destination_type,
            log_destination:      fl.log_destination,
            traffic_type:         fl.traffic_type,
            log_group_name:       fl.log_group_name,
            flow_log_status:      fl.flow_log_status,
          }
        end
        next_token = resp.next_token
        break unless next_token
      end
    end
    rows
  end
end
