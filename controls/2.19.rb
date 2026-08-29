# encoding: UTF-8

control 'C-2.19' do
  title 'Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments'
  desc  "
    In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is provided through role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations. AWS IAM Identity Center (formerly AWS SSO) is the recommended approach for centralized user management in AWS Organizations.

    Centralizing IAM user management to a single identity store reduces complexity and the likelihood of access management errors. Using AWS IAM Identity Center further simplifies access management and reduces reliance on legacy per-account federation configurations.
  "
  desc  'rationale', "
    In multi-account environments, IAM user centralization facilitates greater user control. User access beyond the initial account is provided through role assumption. Centralization of users can be accomplished through federation with an external identity provider or through the use of AWS Organizations. AWS IAM Identity Center (formerly AWS SSO) is the recommended approach for centralized user management in AWS Organizations.

    Centralizing IAM user management to a single identity store reduces complexity and the likelihood of access management errors. Using AWS IAM Identity Center further simplifies access management and reduces reliance on legacy per-account federation configurations.
  "
  desc  'check', "
    For multi-account AWS environments with an external identity provider:

    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam 
    2. Click `Identity providers`
    3. Verify that federation is configured appropriately

    For environments using AWS IAM Identity Center (recommended):
    1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam 
    2. Navigate to `IAM Identity Center`
    3. Verify that IAM Identity Center is enabled
    4. Confirm that users and groups are centrally managed
    5. Confirm that access is assigned to accounts through IAM Identity Center

    For multi-account environments without centralized identity management:

    1. Identify accounts that should not contain local IAM users
    2. Sign in to the AWS Management Console
    3. Switch role into each identified account
    4. Navigate to the IAM console
    5. Select Users
    6. Confirm that no IAM users representing individuals are present
  "
  desc  'fix', "
    The remediation procedure will vary based on the organization's implementation of identity federation and or AWS Organizations.

    Ensure the following:

    1. IAM users are centrally managed through a single identity provider
    2. Local IAM users are removed from member accounts, except for service accounts where required
    3. Access to accounts is granted through role assumption
    4. Where possible, migrate to AWS IAM Identity Center for centralized access management
    5. Avoid legacy per-account federation configurations
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'RA-5 a']
  tag cci:                   ['CCI-000011', 'CCI-001054']
  tag cis_number:            '2.19'
  tag cis_rid:               '2.19'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0219r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  # Converted from Skip-with-rationale to Pass-with-evidence via the
  # document_attestation resource. The identity-provider
  # architecture + account-mapping remains a governance documentation concern;
  # what changes is that the EXISTENCE and FRESHNESS of that documentation are
  # now first-class HDF evidence instead of an unverified Skip.
  #
  # This is a `boundary`-class document (the boundary's own identity-architecture
  # record). The URI defaults via attestation_uri(:boundary, …), which resolves
  # against boundary_docs_base and returns '' when that base is unset — so an
  # unconfigured consumer SKIPs (and can still `saf attest apply` a CMS-pattern
  # attestation downstream) rather than FAILing on a vacuous "URI must be set"
  # expectation. A per-control override
  # (c_2_19_attestation_uri) still wins when set.
  # VERIFY-don't-trust (Phase C): direct identity federation leaves a checkable
  # footprint — a SAML or OIDC identity provider registered in the account. When the
  # consumer's model is direct federation (iam_require_federation: true), assert a
  # provider exists rather than trusting a doc. IAM Identity Center / Organizations
  # SSO is org-level (no account-level provider) -> attestation floor (matrix-documented).
  if input('iam_require_federation', value: false)
    has_federation = aws_iam_saml_providers.entries.any? || aws_iam_oidc_providers.entries.any?
    describe 'C-2.19 IAM identity providers (SAML/OIDC federation configured)' do
      subject { has_federation }
      it { should eq true }
    end
  else
    uri          = input('c_2_19_attestation_uri', value: '')
    uri = attestation_uri(:boundary, 'C-2.19') if uri.to_s.empty?
    max_age_days = input('c_2_19_attestation_max_age_days', value: 365)
    if uri.to_s.empty?
      describe 'C-2.19 centralized-identity attestation (no evidence source configured)' do
        skip 'attestation-required: set iam_require_federation: true to VERIFY a SAML/OIDC provider directly, or set boundary_docs_base / c_2_19_attestation_uri (IAM Identity Center / Organizations SSO case), or supply a CMS-pattern attestation via `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: max_age_days)
      describe "C-2.19 centralized-identity attestation (#{uri})" do
        it 'is reachable (no connection error)' do
          expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}"
        end
        it 'exists' do
          expect(doc.exists?).to eq(true)
        end
        it "is current within #{max_age_days} days" do
          expect(doc.current?).to eq(true)
        end
      end
    end
  end
end
