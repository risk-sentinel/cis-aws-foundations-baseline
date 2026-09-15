#!/usr/bin/env ruby
# frozen_string_literal: true
#
# aws_vpc_endpoint_coverage — required endpoints must be matched PER REGION.
#
# An endpoint service name is region-qualified (com.amazonaws.us-east-1.s3) and
# the documented contract is that the consumer scopes by region by listing the
# region-qualified names. That contract was unsatisfiable: every VPC in every
# region was checked against the WHOLE required list, so a us-east-1 VPC was
# reported missing com.amazonaws.us-west-2.s3 — something it can never have.
#
# A single-region scan hid it, because the list and the scan named the same
# region. Sweeping two regions makes it fire on every VPC, which is how it was
# found: C-6.8 failing against a real account on the first multi-region run.
#
# Tested in BOTH directions. A matcher hardwired to ignore the region would
# satisfy "no cross-region false violation" while also failing to report a
# genuinely missing endpoint, so the real gap is asserted too.

PRIMARY   = "us-east-1"
SECONDARY = "us-west-2"
STUB_CREDENTIAL = "stubbed"

ENV["AWS_REGION"]            ||= PRIMARY
ENV["AWS_ACCESS_KEY_ID"]     ||= STUB_CREDENTIAL
ENV["AWS_SECRET_ACCESS_KEY"] ||= STUB_CREDENTIAL

require "inspec"
require "aws-sdk-core"
require "aws-sdk-ec2"

VENDOR = Dir.glob("vendor/*/libraries").find { |d| File.exist?(File.join(d, "aws_backend.rb")) }
abort "FATAL: no vendored inspec-aws — run `cinc-auditor vendor . --overwrite` first." if VENDOR.nil?
$LOAD_PATH.unshift(VENDOR)
require "aws_backend"
eval(File.read("libraries/_region_scope_helpers.rb"), TOPLEVEL_BINDING, "libraries/_region_scope_helpers.rb") # rubocop:disable Security/Eval
eval(File.read("libraries/aws_vpc_endpoint_coverage.rb"), TOPLEVEL_BINDING, "libraries/aws_vpc_endpoint_coverage.rb") # rubocop:disable Security/Eval

FAILURES = []

def check(desc, actual, expected)
  if actual == expected
    puts "  PASS  #{desc}"
  else
    puts "  FAIL  #{desc}\n        expected #{expected.inspect}\n        got      #{actual.inspect}"
    FAILURES << desc
  end
end

# One VPC per region. Each holds ONLY its own region's S3 endpoint, which is the
# correct state for a consumer who listed both regions' names.
VPC_BY_REGION = { PRIMARY => "vpc-aaaa", SECONDARY => "vpc-bbbb" }.freeze

def stub_for(region, endpoints)
  {
    describe_regions: { regions: [{ region_name: region }] },
    describe_vpcs:    { vpcs: [{ vpc_id: VPC_BY_REGION[region] }] },
    describe_vpc_endpoints: { vpc_endpoints: endpoints.map { |svc|
      { vpc_id: VPC_BY_REGION[region], service_name: svc, state: "Available" }
    } },
  }
end

# The SDK is stubbed per region by keying off the client's configured region, so
# one resource construction sees a different account in each region.
def run_coverage(required, per_region_endpoints)
  Aws.config[:stub_responses] = true
  Aws.config[:ec2] = {
    stub_responses: {
      describe_regions: ->(ctx) { stub_for(ctx.client.config.region.to_s, [])[:describe_regions] },
      describe_vpcs:    ->(ctx) { stub_for(ctx.client.config.region.to_s, [])[:describe_vpcs] },
      describe_vpc_endpoints: lambda { |ctx|
        r = ctx.client.config.region.to_s
        stub_for(r, per_region_endpoints.fetch(r, []))[:describe_vpc_endpoints]
      },
    },
  }
  AwsVpcEndpointCoverage.new(
    required_endpoints: required,
    regions: [PRIMARY, SECONDARY],
    client_args: {},
  )
end

S3_PRIMARY   = "com.amazonaws.#{PRIMARY}.s3"
S3_SECONDARY = "com.amazonaws.#{SECONDARY}.s3"
KMS_PRIMARY  = "com.amazonaws.#{PRIMARY}.kms"

# --- the bug: each region has its own S3 endpoint, both names required.
# Correct answer is NO violations. The old code reported two — each VPC missing
# the other region's name.
res = run_coverage([S3_PRIMARY, S3_SECONDARY],
                   { PRIMARY => [S3_PRIMARY], SECONDARY => [S3_SECONDARY] })
check("both regions covered -> no violations", res.violations, [])

# --- the failing direction: KMS required in the primary region and absent.
# Must be reported, and only against the primary region's VPC.
res = run_coverage([S3_PRIMARY, S3_SECONDARY, KMS_PRIMARY],
                   { PRIMARY => [S3_PRIMARY], SECONDARY => [S3_SECONDARY] })
missing = res.violations.map { |v| [v[:region], v[:missing_service]] }
check("a genuinely missing endpoint IS reported", missing, [[PRIMARY, KMS_PRIMARY]])

# --- a requirement naming no region applies everywhere, so an absent one is a
# violation in BOTH regions.
res = run_coverage(["some.partner.service"],
                   { PRIMARY => [S3_PRIMARY], SECONDARY => [S3_SECONDARY] })
check("region-agnostic requirement applies to every region",
      res.violations.map { |v| v[:region] }.sort, [PRIMARY, SECONDARY].sort)

# --- PrivateLink names carry their region in a different position.
probe = AwsVpcEndpointCoverage.allocate
check("region parsed from a PrivateLink name",
      probe.send(:region_in_service_name, "com.amazonaws.vpce.#{PRIMARY}.vpce-svc-0abc123"), PRIMARY)
check("region parsed from a GovCloud name",
      probe.send(:region_in_service_name, "com.amazonaws.us-gov-west-1.s3"), "us-gov-west-1")
check("no region named -> nil",
      probe.send(:region_in_service_name, "some.partner.service"), nil)

puts
if FAILURES.empty?
  puts "vpc endpoint coverage: OK (per-region matching, both directions)"
  exit 0
end
warn "vpc endpoint coverage: #{FAILURES.size} FAILURE(S): #{FAILURES.join(', ')}"
exit 1
