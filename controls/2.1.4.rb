# encoding: UTF-8

control 'C-2.1.4' do
  title 'Ensure Organizational Units are structured by environment and sensitivity'
  desc  "
    Ensure that AWS Organizations Organizational Units (OUs) are structured primarily by environment (for example, production, non‑production, sandbox) and sensitivity (for example, security, logging, shared services, regulated workloads), rather than mirroring the corporate org chart. OUs should group accounts that share similar security requirements and controls so that appropriate authorization policies and other guardrails can be applied consistently at the OU level.

    A clear OU structure based on environment and sensitivity makes it easier to apply consistent guardrails and centralized security controls to accounts that have similar risk profiles and compliance needs. Poorly defined or ad‑hoc OU structures complicate policy management, increase the chance of misapplied controls, and can lead to mixing workloads with different data sensitivities under the same set of controls.
  "
  desc  'rationale', "
    Ensure that AWS Organizations Organizational Units (OUs) are structured primarily by environment (for example, production, non‑production, sandbox) and sensitivity (for example, security, logging, shared services, regulated workloads), rather than mirroring the corporate org chart. OUs should group accounts that share similar security requirements and controls so that appropriate authorization policies and other guardrails can be applied consistently at the OU level.

    A clear OU structure based on environment and sensitivity makes it easier to apply consistent guardrails and centralized security controls to accounts that have similar risk profiles and compliance needs. Poorly defined or ad‑hoc OU structures complicate policy management, increase the chance of misapplied controls, and can lead to mixing workloads with different data sensitivities under the same set of controls.
  "
  desc  'check', "
    1. From the management account, use AWS Organizations console to obtain:
    - The full OU hierarchy (root, top‑level and child OUs).
    - The list of accounts in each OU.

    2. Review top‑level and key OUs and determine whether they are clearly aligned to:
    - Environment (for example, production, non‑production, sandbox).
    - Sensitivity/function (for example, security, logging, shared services, regulated).
    - Note any OUs whose purpose is unclear or that appear to be organized mainly by department or owner rather than environment/sensitivity.

    3. For each environment/sensitivity OU, select a sample of accounts and verify that their primary workloads match the OU's stated purpose.
    - Note any accounts that mix production and non‑production workloads in the same OU when separate OUs are defined.
    - Note any accounts that place highly sensitive or regulated workloads in OUs that are intended for lower‑sensitivity use.
  "
  desc  'fix', "
    1. Work with security, platform, and application teams to agree on a small set of top‑level OUs such as:
    - Security / Management
    - Shared Services / Infrastructure
    - Prod
    - Non‑Prod (dev, test, staging)
    - You may also define dedicated OUs for highly regulated workloads.

    2. In the AWS Organizations console (management account), navigate to AWS Accounts. Under the root, create the agreed top‑level OUs. If needed, create child OUs under these. 

    3. Export or list all existing accounts and their current OUs. Create a simple mapping from each account to its target OU based on environment and sensitivity.

    4. In the AWS Organizations console (management account), navigate to AWS Accounts. Move accounts into the new environment/sensitivity‑based OUs according to your mapping.
    - Start with low‑risk accounts (for example, sandbox and non‑production) to validate effects of inherited policies and guardrails before moving production and high‑sensitivity accounts.

    5. After accounts have been moved, remove old OUs that no longer reflect the target structure. 
    - Ensure no active accounts remain directly under the root unless explicitly justified and documented.

    6. Update architecture docs, onboarding runbooks, and account request processes to require new accounts to be created in the correct OU based on environment and sensitivity.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.1.4'
  tag cis_rid:               '2.1.4'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020104r1_rule'
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

  # Two-tier check (mirrors C-2.1.1):
  # 1. Necessary precondition (member-account-callable):
  #    - Account is enrolled in an AWS Organization with FeatureSet=ALL
  #      (CONSOLIDATED_BILLING orgs cannot have OUs at all).
  # 2. OU enumeration (organizations:ListRoots +
  #    ListOrganizationalUnitsForParent) requires management or
  #    delegated-admin context. Stays attested for member-account
  #    scans; full automation via aws_organizations_role_arn dual-mode
  #    (see C-2.1.2 / C-2.1.5 / C-2.1.6).
  org_ctx = aws_organizations_context

  if org_ctx.connection_error
    describe 'AWS Organizations enrollment (precondition for OU taxonomy)' do
      it 'requires the scanner account to be enrolled in an Organization' do
        expect(org_ctx.connection_error).to be_nil, org_ctx.connection_error
      end
    end
  else
    describe org_ctx do
      it                 { should be_in_organization }
      its('feature_set') { should eq 'ALL' }
    end

    describe 'OU taxonomy by environment + sensitivity (requires Organizations management context)' do
      skip 'partial-automation: enrollment + FeatureSet=ALL preconditions verified above. OU enumeration requires management or delegated-admin context — attest the OU taxonomy via profiles/cis-aws-foundations/attestations.example.json control_id C-2.1.4, OR run the profile with aws_organizations_role_arn set to a cross-account role in the management account (see C-2.1.2 dual-mode pattern).'
    end
  end
end
