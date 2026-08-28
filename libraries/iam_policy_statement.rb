# Pure-Ruby parser for AWS resource-based policy documents. No SDK
# calls. Used by `aws_resource_policy_violations` (CIS 2.21) to walk the
# six service families' policy strings statement-by-statement and decide
# whether each statement grants unrestricted access via Principal: "*".
#
# Why a separate file: the parser has no AWS dependency, has no state,
# and is reusable by any future control that needs the same wildcard-
# principal heuristic (e.g., follow-ups for Access Analyzer findings).
# Keeping it free of @aws makes it trivial to unit-test and easy to
# extend with sharper Condition heuristics later.
#
# Coarse condition heuristic: a statement
# with a wildcard principal AND any non-empty Condition block is
# accepted. We do not (yet) judge whether the supplied Condition keys
# actually narrow access — that is intentionally tracked as a follow-up
# in the issue body's Out-of-scope section. Sharper heuristics would
# need to know which keys narrow access for which service (e.g.,
# aws:SourceVpc is meaningful for some services and ignored by others).
#
# Wildcard shapes covered: "*", { "AWS" => "*" }, { "Service" => "*" },
# { "Federated" => "*" }, { "CanonicalUser" => "*" }, plus arrays
# containing "*" in any of those slots.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first only for
# load-order parity with sibling files; this file does not actually
# require aws_backend.

require "json"

module IamPolicyStatement
  WILDCARD = "*".freeze
  WILDCARD_PRINCIPAL_KEYS = %w[AWS Service Federated CanonicalUser].freeze

  module_function

  # Parse a policy document. Accepts a JSON string or an already-
  # decoded Hash (some SDK calls return one, some return the other).
  # Returns an array of normalized statement hashes; an unparseable or
  # empty input returns []. Always-defensive — the caller treats
  # parsing errors as "no violations contributed by this resource."
  def parse(policy)
    doc = decode(policy)
    return [] unless doc.is_a?(Hash)
    statements = Array(doc["Statement"] || doc[:Statement])
    statements.map { |s| normalize(s) }.compact
  end

  def decode(policy)
    return policy if policy.is_a?(Hash)
    return nil if policy.nil?
    str = policy.to_s
    return nil if str.empty?
    JSON.parse(str)
  rescue JSON::ParserError
    nil
  end

  def normalize(statement)
    return nil unless statement.is_a?(Hash)
    {
      sid:                    statement["Sid"] || statement[:Sid],
      effect:                 (statement["Effect"] || statement[:Effect]).to_s,
      principal:              statement["Principal"] || statement[:Principal],
      condition:              statement["Condition"] || statement[:Condition],
      raw:                    statement,
    }
  end

  def allow?(statement)
    statement[:effect] == "Allow"
  end

  # True if the Principal slot contains a wildcard "*" anywhere we
  # check for it. Catches "*" directly, the AWS/Service/Federated/
  # CanonicalUser sub-key shapes, and arrays of those.
  def principal_is_wildcard?(statement)
    principal = statement[:principal]
    return true if principal == WILDCARD
    return false unless principal.is_a?(Hash)
    WILDCARD_PRINCIPAL_KEYS.any? do |key|
      val = principal[key] || principal[key.to_sym]
      next false if val.nil?
      Array(val).any? { |v| v.to_s == WILDCARD }
    end
  end

  # Coarse: any non-empty Condition block. Sharper analysis (which
  # Condition keys actually narrow access for this service) is a
  # tracked follow-up — see file header.
  def has_condition?(statement)
    cond = statement[:condition]
    cond.is_a?(Hash) && !cond.empty?
  end

  # Render a Principal value back to a stable string for inclusion in
  # violation records. Hash principals are rendered as JSON to keep
  # downstream `violations.to_s` output greppable.
  def principal_label(statement)
    principal = statement[:principal]
    return WILDCARD if principal == WILDCARD
    return principal.to_json if principal.is_a?(Hash)
    principal.to_s
  end
end
