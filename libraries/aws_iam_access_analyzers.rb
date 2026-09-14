# IAM External Access Analyzer enumeration across the partition's active
# regions. Added for CIS AWS Foundations 2.18. Not in inspec-aws 1.83.63.
# Context: docs/dev/issue_20_design.md.
#
# Regions: accepts an optional `regions:` kwarg (array). Empty or unset =
# dynamic discovery via compute_client.describe_regions (auto-narrows by
# partition). Non-empty = explicit allowlist, typically sourced from the
# scan_regions profile input so the same knob governs every per-region
# resource consistently.
#
# Instantiates Aws::AccessAnalyzer::Client per region directly rather than
# going through @aws.aws_client(klass) — that accessor caches by class with
# no region parameter, which would serialize every region's call through a
# single client. Per-region instantiation bypasses the cache intentionally.

class AwsIamAccessAnalyzers < AwsResourceBase
  include RegionScope
  name "aws_iam_access_analyzers"
  desc "IAM External Access Analyzer enumeration across active regions."
  example "
    describe aws_iam_access_analyzers do
      it { should exist }
      its('regions_without_active_analyzer') { should be_empty }
    end
  "

  attr_reader :table, :connection_error

  FilterTable.create
    .register_column(:arns,     field: :arn)
    .register_column(:names,    field: :name)
    .register_column(:types,    field: :type)
    .register_column(:statuses, field: :status)
    .register_column(:regions,  field: :region)
    .install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @connection_error = nil
    @table = []
    # The `aws-sdk-accessanalyzer` gem is not part of inspec-aws's default
    # vendored set — the docker image's bundled gems include only the
    # services inspec-aws wraps natively. Defensive require + LoadError
    # fallback (per `aws_workdocs_inventory` pattern) so controls degrade
    # to a clear connection_error skip instead of raising
    # `uninitialized constant Aws::AccessAnalyzer` at exec time.
    begin
      require "aws-sdk-accessanalyzer"
    rescue LoadError => e
      @connection_error = "aws-sdk-accessanalyzer gem not installed: #{e.message}. File a tracking issue against the cinc-auditor docker image to bundle the gem."
      @all_regions = Array(region_override)
      return
    end
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  def active_regions
    @table.select { |row| row[:status] == "ACTIVE" }.map { |row| row[:region] }.uniq
  end

  def regions_without_active_analyzer
    (@all_regions - active_regions).sort
  end

  def to_s
    "IAM External Access Analyzers"
  end

  private


  def fetch_data
    rows = []
    @all_regions.each do |region|
      rows.concat(list_analyzers_in(region))
    end
    rows
  end

  def list_analyzers_in(region)
    rows = []
    client = ::Aws::AccessAnalyzer::Client.new(region: region)
    pagination_options = { type: "ACCOUNT" }
    loop do
      begin
        resp = client.list_analyzers(pagination_options)
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_iam_access_analyzers: #{region} list_analyzers failed: #{e.message}")
        return rows
      end
      resp.analyzers.each do |a|
        rows << {
          arn:    a.arn,
          name:   a.name,
          type:   a.type,
          status: a.status,
          region: region,
        }
      end
      break unless resp.next_token
      pagination_options[:next_token] = resp.next_token
    end
    rows
  end
end
