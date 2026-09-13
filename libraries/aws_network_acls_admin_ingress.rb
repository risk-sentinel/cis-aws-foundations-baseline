# Account-wide scanner for NACL violations against CIS 6.2 — ingress
# from 0.0.0.0/0 to remote-administration ports (22, 3389) using TCP,
# UDP, or ALL protocols. Depends on `_aws_backend_bootstrap.rb` having
# loaded first.
#
# Why this exists: vendored inspec-aws 1.83.63 aws_network_acl exposes
# entries but no port-range / protocol predicate. Replicating CIS 6.2's
# "first-match wins on rule_number ordering" logic requires walking
# entries per-port — best done in one place rather than ad-hoc in
# control bodies.
#
# Implements CIS 6.2's DENY-precedence allowance: a NACL whose first
# 0.0.0.0/0 match for an admin port is an explicit DENY (lower rule
# number than any ALLOW) is acceptable. If no rule matches, the implicit
# default-deny (rule 32767) applies and the port is not exposed.
#
# Context: docs/dev/Vendored_Resource_Gaps.md.

class AwsNetworkAclsAdminIngress < AwsResourceBase
  include RegionEnumeration
  name "aws_network_acls_admin_ingress"
  desc "Network ACLs that ALLOW ingress from 0.0.0.0/0 to admin ports."
  example "
    describe aws_network_acls_admin_ingress(admin_ports: [22, 3389]) do
      its('violations') { should be_empty }
    end
  "

  ANY_IPV4 = "0.0.0.0/0".freeze
  TCP      = "6".freeze
  UDP      = "17".freeze
  ALL      = "-1".freeze
  PERMISSIVE_PROTOCOLS = [TCP, UDP, ALL].freeze

  attr_reader :violations, :admin_ports

  def initialize(opts = {})
    opts = opts.dup
    # Must be removed BEFORE super — AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters(allow: [:admin_ports])
    @admin_ports = Array(opts[:admin_ports] || [22, 3389]).map(&:to_i)
    @violations = []
    @all_regions = resolve_regions(region_override)
    fetch_data
  end

  def exists?
    @fetched == true
  end

  def to_s
    "AWS Network ACLs admin-port ingress scan"
  end

  private

  def fetch_data
    @fetched = false
    each_region_client(::Aws::EC2::Client) do |client, region|
      acls = client.describe_network_acls.network_acls || []
      @fetched = true
      acls.each do |acl|
        ingress_entries = (acl.entries || []).reject(&:egress)
                                              .sort_by(&:rule_number)
        @admin_ports.each do |port|
          first_match = ingress_entries.find do |entry|
            entry.cidr_block == ANY_IPV4 &&
              PERMISSIVE_PROTOCOLS.include?(entry.protocol.to_s) &&
              entry_covers_port?(entry, port)
          end
          next if first_match.nil?
          next if first_match.rule_action == "deny"
          @violations << {
            region:         region,
            network_acl_id: acl.network_acl_id,
            vpc_id:         acl.vpc_id,
            port:           port,
            rule_number:    first_match.rule_number,
            protocol:       first_match.protocol,
          }
        end
      end
    end
  end

  def entry_covers_port?(entry, port)
    return true if entry.protocol.to_s == ALL
    return true if entry.port_range.nil?
    entry.port_range.from <= port && entry.port_range.to >= port
  end
end
