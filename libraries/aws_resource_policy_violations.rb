# Account-wide scanner for resource-based policies that grant
# unrestricted access via Principal: "*" without a restrictive
# Condition. Implements CIS AWS Foundations 2.21.
#
# Service surface: S3, KMS, Secrets Manager, SQS, SNS, Lambda.
# All but S3 are regional; S3 list_buckets is global but get_bucket_policy
# is regional (boto3/SDK handles redirects automatically when the bucket's
# region differs from the client's). Each service walker is independent —
# an AccessDenied or transient error in one service contributes to
# `partial_failures` rather than blocking the others.
#
# Wildcard-principal + condition heuristics live in
# `iam_policy_statement.rb` (pure Ruby, no SDK). This file is the
# enumeration + per-service plumbing.
#
# `excluded_arns` lets a consumer exempt specific resources whose
# policies are intentionally Principal: "*" with a documented
# justification (e.g., a public-by-design bucket fronting CloudFront).
# Match is exact-string against the resource ARN reported in each
# violation row. Glob/prefix matching is intentionally out of scope here
# — exact-ARN exemption forces operator deliberation per resource.
#
# Why we don't filter AWS-managed KMS keys: it would require an extra
# describe_key call per key, and AWS-managed keys with wildcard
# principals are still real findings even if not directly remediable.
# Operators can add their ARNs to `excluded_arns` if they want to
# suppress them.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

require "set"

class AwsResourcePolicyViolations < AwsResourceBase
  name "aws_resource_policy_violations"
  desc "Scan AWS resource-based policies for Principal: \"*\" without restrictive Condition."
  example "
    describe aws_resource_policy_violations(excluded_arns: input('c221_excluded_arns')) do
      its('violations') { should be_empty }
    end
  "

  attr_reader :violations, :partial_failures, :excluded_arns

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @excluded_arns = Array(opts.delete(:excluded_arns)).map(&:to_s).to_set
    @partition = (opts.delete(:aws_partition) || "aws").to_s
    super(opts)
    validate_parameters
    @violations = []
    @partial_failures = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "AWS resource-policy wildcard-principal scan"
  end

  private

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  def fetch_data
    scan_s3
    @regions.each do |region|
      scan_kms(region)
      scan_secrets_manager(region)
      scan_sqs(region)
      scan_sns(region)
      scan_lambda(region)
    end
  end

  # ----- per-service walkers -----

  def scan_s3
    buckets = []
    begin
      buckets = @aws.storage_client.list_buckets.buckets || []
    rescue ::Aws::Errors::ServiceError => e
      record_partial_failure("s3", "global", "list_buckets", e)
      return
    end
    buckets.each do |b|
      arn = "arn:#{@partition}:s3:::#{b.name}"
      next if excluded?(arn)
      policy = nil
      begin
        policy = @aws.storage_client.get_bucket_policy(bucket: b.name).policy
      rescue ::Aws::S3::Errors::NoSuchBucketPolicy
        next
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("s3", "global", "get_bucket_policy/#{b.name}", e)
        next
      end
      record_violations("s3", arn, policy)
    end
  end

  def scan_kms(region)
    client = ::Aws::KMS::Client.new(region: region)
    next_marker = nil
    loop do
      resp = nil
      begin
        resp = client.list_keys(marker: next_marker)
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("kms", region, "list_keys", e)
        return
      end
      Array(resp.keys).each do |k|
        next if excluded?(k.key_arn)
        policy = nil
        begin
          policy = client.get_key_policy(key_id: k.key_id, policy_name: "default").policy
        rescue ::Aws::KMS::Errors::AccessDeniedException,
               ::Aws::KMS::Errors::KMSInvalidStateException,
               ::Aws::KMS::Errors::NotFoundException
          next
        rescue ::Aws::Errors::ServiceError => e
          record_partial_failure("kms", region, "get_key_policy/#{k.key_id}", e)
          next
        end
        record_violations("kms", k.key_arn, policy)
      end
      break unless resp.truncated
      next_marker = resp.next_marker
    end
  end

  def scan_secrets_manager(region)
    client = ::Aws::SecretsManager::Client.new(region: region)
    next_token = nil
    loop do
      resp = nil
      begin
        resp = client.list_secrets(next_token: next_token)
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("secretsmanager", region, "list_secrets", e)
        return
      end
      Array(resp.secret_list).each do |s|
        next if excluded?(s.arn)
        policy = nil
        begin
          policy = client.get_resource_policy(secret_id: s.arn).resource_policy
        rescue ::Aws::SecretsManager::Errors::ResourceNotFoundException
          next
        rescue ::Aws::Errors::ServiceError => e
          record_partial_failure("secretsmanager", region, "get_resource_policy/#{s.name}", e)
          next
        end
        next if policy.nil? || policy.empty?
        record_violations("secretsmanager", s.arn, policy)
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def scan_sqs(region)
    client = ::Aws::SQS::Client.new(region: region)
    next_token = nil
    loop do
      resp = nil
      begin
        resp = client.list_queues(next_token: next_token)
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("sqs", region, "list_queues", e)
        return
      end
      Array(resp.queue_urls).each do |url|
        attrs = nil
        begin
          attrs = client.get_queue_attributes(
            queue_url: url,
            attribute_names: %w[Policy QueueArn],
          ).attributes
        rescue ::Aws::SQS::Errors::QueueDoesNotExist
          next
        rescue ::Aws::Errors::ServiceError => e
          record_partial_failure("sqs", region, "get_queue_attributes/#{url}", e)
          next
        end
        arn = attrs["QueueArn"]
        next if arn.nil? || excluded?(arn)
        policy = attrs["Policy"]
        next if policy.nil? || policy.empty?
        record_violations("sqs", arn, policy)
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def scan_sns(region)
    client = ::Aws::SNS::Client.new(region: region)
    next_token = nil
    loop do
      resp = nil
      begin
        resp = client.list_topics(next_token: next_token)
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("sns", region, "list_topics", e)
        return
      end
      Array(resp.topics).each do |t|
        arn = t.topic_arn
        next if excluded?(arn)
        attrs = nil
        begin
          attrs = client.get_topic_attributes(topic_arn: arn).attributes
        rescue ::Aws::SNS::Errors::NotFound
          next
        rescue ::Aws::Errors::ServiceError => e
          record_partial_failure("sns", region, "get_topic_attributes/#{arn}", e)
          next
        end
        policy = attrs["Policy"]
        next if policy.nil? || policy.empty?
        record_violations("sns", arn, policy)
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def scan_lambda(region)
    client = ::Aws::Lambda::Client.new(region: region)
    next_marker = nil
    loop do
      resp = nil
      begin
        resp = client.list_functions(marker: next_marker)
      rescue ::Aws::Errors::ServiceError => e
        record_partial_failure("lambda", region, "list_functions", e)
        return
      end
      Array(resp.functions).each do |f|
        arn = f.function_arn
        next if excluded?(arn)
        policy = nil
        begin
          policy = client.get_policy(function_name: arn).policy
        rescue ::Aws::Lambda::Errors::ResourceNotFoundException
          next
        rescue ::Aws::Errors::ServiceError => e
          record_partial_failure("lambda", region, "get_policy/#{f.function_name}", e)
          next
        end
        record_violations("lambda", arn, policy)
      end
      break if resp.next_marker.nil? || resp.next_marker.empty?
      next_marker = resp.next_marker
    end
  end

  # ----- shared helpers -----

  def record_violations(service, arn, policy_json)
    IamPolicyStatement.parse(policy_json).each do |statement|
      next unless IamPolicyStatement.allow?(statement)
      next unless IamPolicyStatement.principal_is_wildcard?(statement)
      next if IamPolicyStatement.has_condition?(statement)
      @violations << {
        service:           service,
        resource_arn:      arn,
        sid:               statement[:sid],
        principal:         IamPolicyStatement.principal_label(statement),
        condition_present: false,
      }
    end
  end

  def record_partial_failure(service, region, op, err)
    @partial_failures << {
      service: service,
      region:  region,
      op:      op,
      error:   err.message,
    }
    Inspec::Log.warn("aws_resource_policy_violations: #{service}/#{region} #{op} failed: #{err.message}")
  end

  def excluded?(arn)
    @excluded_arns.include?(arn.to_s)
  end
end
