# Shared region enumeration for account-wide custom resources.
#
# The problem this exists for (#28): a resource that talks to a single
# `@aws.<service>_client` only ever sees the region named by `aws_region`. A
# workload in any other region is not assessed — and the result is not an error,
# it is a clean report. Controls pass having found nothing, or route to Not
# Applicable, which HDF renders as "does not apply here" rather than "we did not
# look". An assessor reading the evidence cannot tell those apart.
#
# Usage in a resource:
#
#   class AwsThing < AwsResourceBase
#     include RegionEnumeration
#
#     def initialize(opts = {})
#       opts = opts.dup
#       region_override = Array(opts.delete(:regions))   # BEFORE super
#       super(opts)
#       validate_parameters(allow: [:your_opts])
#       @all_regions = resolve_regions(region_override)
#       fetch_data
#     end
#
# and the control passes `regions: Array(input('scan_regions'))`, so one input
# governs every per-region resource consistently.
#
# Three details that are not obvious:
#
# 1. `opts.delete(:regions)` MUST happen before `super(opts)`. AwsResourceBase
#    hands unrecognised keys to validate_parameters, which raises on anything not
#    in its allow-list.
#
# 2. Per-region clients are instantiated DIRECTLY rather than via
#    `@aws.aws_client(klass)`. That accessor caches by class with no region in
#    the key, so every region's call would be serialised through one client
#    bound to one region — which is the bug, reintroduced. This mirrors the
#    comment already in aws_iam_access_analyzers.
#
# 3. `describe_regions` is partition-scoped, so it narrows to GovCloud
#    automatically and no partition switch is needed here.
#
# Extracted from the three resources that already did this correctly
# (aws_iam_access_analyzers, aws_cloudtrail_event_selectors,
# aws_resource_policy_violations) rather than invented. Those predate this
# module and are its reference behaviour. Keeping one copy also keeps Sonar's
# duplication rule quiet: `sonar.cpd.exclusions` covers `controls/**`, not
# `libraries/**`, so ten hand-copies of `fetch_default_regions` would trip it.
#
# Verified by tests/unit/region_coverage_test.rb, which stubs the AWS SDK and
# asserts each declared resource actually queries every enabled region.

module RegionEnumeration
  # An explicit, non-empty override wins; otherwise discover the partition's
  # enabled regions. Empty strings are dropped so an unset InSpec input — which
  # arrives as "" rather than nil — does not become a region named "".
  def resolve_regions(region_override)
    explicit = Array(region_override).map(&:to_s).map(&:strip).reject(&:empty?)
    return explicit unless explicit.empty?
    fetch_default_regions
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  # Yields a freshly constructed, region-bound client per region. A region that
  # raises (opted out, service unavailable there, denied) is recorded and
  # skipped rather than aborting the whole sweep — but it is recorded, so a
  # partial sweep can never be mistaken for a complete one.
  def each_region_client(klass)
    @region_errors ||= {}
    Array(@all_regions).each do |region|
      begin
        yield(klass.new(region: region), region)
      rescue StandardError => e
        @region_errors[region] = "#{e.class}: #{e.message}"
      end
    end
  end

  # Regions that could not be assessed. A control that cares about completeness
  # should assert this is empty rather than assuming the sweep was total.
  def region_errors
    @region_errors ||= {}
  end

  def regions_scanned
    Array(@all_regions) - region_errors.keys
  end
end
