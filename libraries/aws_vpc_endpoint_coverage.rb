# Account-wide scanner for CIS 6.8 — VPC Endpoints used for AWS service
# access. Asserts that every active VPC has an Available endpoint for
# each service in the consumer-supplied required_endpoints list.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.
#
# Why this exists: vendored aws_vpc_endpoints exposes service_name,
# vpc_id, state via FilterTable but cannot express "for every VPC, the
# set of required services is a subset of the per-VPC available
# service_names" — the join is across two enumerations.
#
# Service names are full AWS-service-name strings, e.g.
# 'com.amazonaws.us-east-1.s3'. Consumer scopes by region by listing the
# region-qualified names. State must be 'Available' (Pending /
# Deleting / Failed are not accepted as coverage).
#
# Context: docs/dev/Vendored_Resource_Gaps.md.

class AwsVpcEndpointCoverage < AwsResourceBase
  include RegionScope
  name "aws_vpc_endpoint_coverage"
  desc "Per-VPC coverage of required AWS-service VPC endpoints (CIS 6.8)."
  example "
    describe aws_vpc_endpoint_coverage(required_endpoints: input('required_vpc_endpoints')) do
      its('violations') { should be_empty }
    end
  "

  AVAILABLE = "Available".freeze

  attr_reader :violations, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    # Must be removed BEFORE super — AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters(allow: [:required_endpoints])
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @required = Array(opts[:required_endpoints]).map(&:to_s)
    @violations = []
    fetch_data
  end

  def exists?
    @fetched == true
  end

  def to_s
    "AWS VPC Endpoint coverage scan"
  end

  private

  def fetch_data
    @fetched = false
    each_region_client(::Aws::EC2::Client) do |client, region|
      vpcs = client.describe_vpcs.vpcs || []
      endpoints = client.describe_vpc_endpoints.vpc_endpoints || []
      @fetched = true

      available_per_vpc = endpoints.each_with_object({}) do |ep, h|
        next unless ep.state == AVAILABLE
        h[ep.vpc_id] ||= []
        h[ep.vpc_id] << ep.service_name
      end

      vpcs.each do |vpc|
        present = available_per_vpc[vpc.vpc_id] || []
        @required.each do |service|
          next if present.include?(service)
          @violations << { region: region, vpc_id: vpc.vpc_id, missing_service: service }
        end
      end
    end
  end
end
