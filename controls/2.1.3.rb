# encoding: UTF-8

control 'C-2.1.3' do
  title 'Ensure Organizations management account is not used for workloads'
  desc  "
    Ensure that the AWS Organizations management account is used only for organizational governance tasks and does not host production workloads, applications, or business data. The management account is the most privileged account in an AWS Organization and performs sensitive administrative functions such as creating and managing member accounts, applying service control policies (SCPs), and managing consolidated billing. Workloads, applications, and associated data should be deployed in dedicated member accounts, not in the management account.

    The management account has unique privileges that cannot be restricted by SCPs, making it the highest-risk account in an organization. Deploying workloads or storing business data in the management account increases the attack surface and blast radius of a compromise. If a workload vulnerability or misconfiguration occurs in the management account, it could grant attackers access to organization-wide administrative capabilities.
  "
  desc  'rationale', "
    Ensure that the AWS Organizations management account is used only for organizational governance tasks and does not host production workloads, applications, or business data. The management account is the most privileged account in an AWS Organization and performs sensitive administrative functions such as creating and managing member accounts, applying service control policies (SCPs), and managing consolidated billing. Workloads, applications, and associated data should be deployed in dedicated member accounts, not in the management account.

    The management account has unique privileges that cannot be restricted by SCPs, making it the highest-risk account in an organization. Deploying workloads or storing business data in the management account increases the attack surface and blast radius of a compromise. If a workload vulnerability or misconfiguration occurs in the management account, it could grant attackers access to organization-wide administrative capabilities.
  "
  desc  'check', "
    1. Confirm which AWS account is the management account for the organization (for example, via AWS Organizations \"Overview\" page or organizational documentation).

    2. Ensure you have read‑only access to review resources in this account.

    3. Use your organization's standard discovery methods (for example, AWS Config, CMDB/asset inventory, or CSPM) to obtain a list of services and resources running in the management account.
    - At a minimum, identify compute, storage, database, and application services (for example, EC2, Lambda, ECS, S3, RDS, DynamoDB, API Gateway, load balancers).

    4. For each identified resource, determine whether it is:

    - Governance/security: resources that support centralized management, logging, audit, or security (for example, org‑wide CloudTrail, Config aggregator, Security Hub or GuardDuty delegated admin, billing/cost tooling).

    - Workload/business: resources that support business applications, production or non‑production workloads, or customer‑facing systems.

    5. If any workload/business resources are present in the management account, record this as a gap and document the affected services and resource types
  "
  desc  'fix', "
    1. Inventory all workload resources currently in the management account (compute, storage, databases, application services).

    2. For each class of workload resource (for example, production, non‑production, shared services), create or confirm dedicated member accounts within the organization and place them into the appropriate OUs.

    3. For each workload resource, design a migration plan to the appropriate member account. 
    - Execute the migrations in phases, starting with lower‑risk environments (for example, development/test) before production.

    4. Review and adjust IAM roles and permissions in the management account so that only personnel responsible for organization governance and security have access

    5. Update architecture diagrams, runbooks, and onboarding processes to state that new workloads must be deployed only into designated workload accounts, not the management account.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.1.3'
  tag cis_rid:               '2.1.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020103r1_rule'
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
  # document_attestation resource. The governance
  # judgement — is the management account free of workloads — is still made by
  # a human and recorded in a periodic-review attestation document (the
  # determination requires AssumeRole into the mgmt account, cross-service
  # compute enumeration, and a workload-vs-infrastructure classification that
  # is genuinely governance-bound). What changes: the EXISTENCE and FRESHNESS
  # of that attestation are now first-class HDF evidence instead of an
  # unverified Skip.
  #
  # This is a `boundary`-class document (the boundary's own periodic-review
  # record). The URI defaults via attestation_uri(:boundary, …), which resolves
  # against boundary_docs_base and returns '' when that base is unset — so an
  # unconfigured consumer SKIPs (and can still `saf attest apply` a CMS-pattern
  # attestation downstream) rather than FAILing on a vacuous "URI must be set"
  # expectation. A per-control override
  # (c_2_1_3_attestation_uri) still wins when set.
  uri          = input('c_2_1_3_attestation_uri', value: attestation_uri(:boundary, 'C-2.1.3'))
  max_age_days = input('c_2_1_3_attestation_max_age_days', value: 365)

  if uri.to_s.empty?
    describe 'C-2.1.3 management-account-workloads attestation (no evidence source configured)' do
      skip 'attestation-required: no boundary evidence source configured; set ' \
           'boundary_docs_base / c_2_1_3_attestation_uri to the periodic-review ' \
           'attestation document, or supply a CMS-pattern attestation via ' \
           '`saf attest apply`.'
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.1.3 management-account-workloads attestation (#{uri})" do
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
