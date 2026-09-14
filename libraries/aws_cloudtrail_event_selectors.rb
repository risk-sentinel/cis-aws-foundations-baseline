# CloudTrail event-selector enumeration across all visible trails. The
# vendored aws_cloudtrail_trail resource calls get_event_selectors but
# only surfaces a management-events boolean; CIS 4.8 / 4.9 need the
# data_resources[] attribute on classic selectors and the field_selectors
# on advanced selectors so we can tell whether S3-object-level logging
# is on. Added locally; not in inspec-aws 1.83.63.
# Context: docs/dev/issue_20_design.md.
#
# Regions: follows the scan_regions convention. Empty override = dynamic
# discovery via compute_client.describe_regions. Non-empty = explicit
# allowlist. Multi-region trails appear in describe_trails output from
# any region, so scan_regions controls how aggressively we sweep for
# single-region trails; it does not affect multi-region-trail visibility.
#
# Partition: S3-object ARN-prefix match accepts both 'arn:aws:s3' and
# 'arn:aws-us-gov:s3' so GovCloud runs cleanly without a per-call kwarg.

class AwsCloudtrailEventSelectors < AwsResourceBase
  include RegionScope
  name "aws_cloudtrail_event_selectors"
  desc "CloudTrail event-selector enumeration with S3 object-logging predicates."
  example "
    describe aws_cloudtrail_event_selectors(regions: Array(input('scan_regions'))) do
      its('logs_s3_object_writes?') { should eq true }
      its('logs_s3_object_reads?')  { should eq true }
    end
  "

  attr_reader :table, :connection_error

  FilterTable.create
    .register_column(:trail_arns,       field: :trail_arn)
    .register_column(:trail_names,      field: :trail_name)
    .register_column(:home_regions,     field: :home_region)
    .register_column(:selector_kinds,   field: :selector_kind)
    .register_column(:read_write_types, field: :read_write_type)
    .install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  def logs_s3_object_writes?
    @table.any? { |row| row[:logs_s3_writes] }
  end

  def logs_s3_object_reads?
    @table.any? { |row| row[:logs_s3_reads] }
  end

  def trails_logging_s3_object_writes
    @table.select { |row| row[:logs_s3_writes] }.map { |r| r[:trail_arn] }.uniq
  end

  def trails_logging_s3_object_reads
    @table.select { |row| row[:logs_s3_reads] }.map { |r| r[:trail_arn] }.uniq
  end

  def to_s
    "CloudTrail Event Selectors"
  end

  private

  def fetch_data
    rows = []
    enumerate_trails.each do |trail|
      rows.concat(selectors_for_trail(trail))
    end
    rows
  end

  def enumerate_trails
    trails = []
    seen = {}
    @all_regions.each do |region|
      begin
        client = ::Aws::CloudTrail::Client.new(region: region)
        resp = client.describe_trails
        Array(resp.trail_list).each do |t|
          next if seen.key?(t.trail_arn)
          seen[t.trail_arn] = true
          trails << {
            trail_arn:       t.trail_arn,
            trail_name:      t.name,
            home_region:     t.home_region,
            is_multi_region: t.is_multi_region_trail,
          }
        end
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_cloudtrail_event_selectors: describe_trails in #{region} failed: #{e.message}")
      end
    end
    trails
  end

  def selectors_for_trail(trail)
    rows = []
    begin
      client = ::Aws::CloudTrail::Client.new(region: trail[:home_region])
      resp = client.get_event_selectors(trail_name: trail[:trail_arn])
      Array(resp.event_selectors).each do |es|
        logs_writes = %w[All WriteOnly].include?(es.read_write_type) && s3_object_match?(es.data_resources)
        logs_reads  = %w[All ReadOnly].include?(es.read_write_type)  && s3_object_match?(es.data_resources)
        rows << row_for(trail, "classic", es.read_write_type, logs_writes, logs_reads)
      end
      Array(resp.advanced_event_selectors).each do |aes|
        fs_map    = Array(aes.field_selectors).each_with_object({}) { |fs, h| h[fs.field] = fs }
        is_data   = Array(fs_map["eventCategory"]&.equals).include?("Data")
        is_s3_obj = Array(fs_map["resources.type"]&.equals).include?("AWS::S3::Object")
        ro_equals = Array(fs_map["readOnly"]&.equals).first
        logs_writes = is_data && is_s3_obj && (ro_equals.nil? || ro_equals == "false")
        logs_reads  = is_data && is_s3_obj && (ro_equals.nil? || ro_equals == "true")
        rw = case ro_equals
             when "true"  then "ReadOnly"
             when "false" then "WriteOnly"
             else "All"
             end
        rows << row_for(trail, "advanced", rw, logs_writes, logs_reads)
      end
    rescue ::Aws::Errors::ServiceError => e
      Inspec::Log.warn("aws_cloudtrail_event_selectors: get_event_selectors(#{trail[:trail_arn]}) failed: #{e.message}")
    end
    rows
  end

  def s3_object_match?(data_resources)
    Array(data_resources).any? do |dr|
      next false unless dr.type == "AWS::S3::Object"
      Array(dr.values).any? do |v|
        s = v.to_s
        s.start_with?("arn:aws:s3") || s.start_with?("arn:aws-us-gov:s3")
      end
    end
  end

  def row_for(trail, selector_kind, read_write_type, logs_writes, logs_reads)
    {
      trail_arn:       trail[:trail_arn],
      trail_name:      trail[:trail_name],
      home_region:     trail[:home_region],
      selector_kind:   selector_kind,
      read_write_type: read_write_type,
      logs_s3_writes:  logs_writes,
      logs_s3_reads:   logs_reads,
    }
  end

end
