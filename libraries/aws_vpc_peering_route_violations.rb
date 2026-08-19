# Account-wide scanner for CIS 6.6 — VPC peering route-table least
# access. Walks describe_route_tables, for each route whose target is a
# vpc-peering-connection-id, asserts that the route's destination CIDR
# is on the consumer's allowlist for that peering.
#
# Two violation kinds:
#   - kind: :unmanaged_peering — a peering id appears in routes but has
#     no entry in vpc_peering_allowed_cidrs. Consumer either adds it
#     (with the justified CIDRs) or removes the peering.
#   - kind: :unauthorized_route — peering is allowlisted but the route's
#     destination CIDR is not in the allowlist for that peering.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.
#
# Why this exists: vendored inspec-aws 1.83.63 has aws_route_table /
# aws_route_tables but the plural cannot be filtered by route target
# (vpc_peering_connection_id) without the consumer first knowing every
# route-table id. Account-wide scan is the natural shape.
# Context: docs/dev/Vendored_Resource_Gaps.md.

class AwsVpcPeeringRouteViolations < AwsResourceBase
  name "aws_vpc_peering_route_violations"
  desc "VPC-peering route-table CIDR allowlist enforcement (CIS 6.6)."
  example "
    describe aws_vpc_peering_route_violations(allowed_cidrs: input('vpc_peering_allowed_cidrs')) do
      its('violations') { should be_empty }
    end
  "

  attr_reader :violations

  def initialize(opts = {})
    # An EMPTY allowlist is a legitimate state — "no peering is approved yet" —
    # and it is also the input's default. AwsResourceBase#validate_parameters
    # rejects an empty parameter VALUE with "Provided parameter should not be
    # empty", so passing `allowed_cidrs: {}` errored the control on every
    # account, including ones with no peering connections at all where the
    # control is documented to pass vacuously. Drop empty values before
    # validation rather than making every caller branch on it; @allowed_cidrs
    # below already defaults correctly when the key is absent.
    opts = opts.reject { |_k, v| v.respond_to?(:empty?) && v.empty? }
    super(opts)
    validate_parameters(allow: [:allowed_cidrs])
    @allowed_cidrs = (opts[:allowed_cidrs] || {}).each_with_object({}) do |(k, v), h|
      h[k.to_s] = Array(v).map(&:to_s)
    end
    @violations = []
    fetch_data
  end

  def exists?
    @fetched == true
  end

  def to_s
    "AWS VPC peering route-table least-access scan"
  end

  private

  def fetch_data
    @fetched = false
    catch_aws_errors do
      route_tables = @aws.compute_client.describe_route_tables.route_tables || []
      @fetched = true
      route_tables.each do |rt|
        (rt.routes || []).each do |route|
          peering_id = route.vpc_peering_connection_id
          next if peering_id.nil? || peering_id.empty?

          cidr = route.destination_cidr_block || route.destination_ipv_6_cidr_block
          allow = @allowed_cidrs[peering_id]

          if allow.nil?
            @violations << {
              kind:           :unmanaged_peering,
              peering_id:     peering_id,
              route_table_id: rt.route_table_id,
              vpc_id:         rt.vpc_id,
              cidr:           cidr,
            }
          elsif !allow.include?(cidr)
            @violations << {
              kind:           :unauthorized_route,
              peering_id:     peering_id,
              route_table_id: rt.route_table_id,
              vpc_id:         rt.vpc_id,
              cidr:           cidr,
            }
          end
        end
      end
    end
  end
end
