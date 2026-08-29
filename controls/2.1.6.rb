# encoding: UTF-8

control 'C-2.1.6' do
  title 'Ensure delegated admins manage AWS Organizations-integrated services'
  desc  "
    Ensure that AWS services (such as AWS CloudTrail) which integrate with AWS Organizations and support delegated administration are managed through delegated administrator member accounts instead of directly from the Organizations management account. For each such service, the management account should enable trusted access and register a purpose‑built member account as the delegated administrator, so that this account can perform service‑level administration across all organization accounts.

    The management account has unique and high privileges to manage AWS Organizations (for example, creating/deleting accounts, managing org structures) and is not subject to guardrails like SCPs. Without delegated administrators, organization‑wide security, logging, and management services must be operated directly from the management account, concentrating operational activity and credentials in the most privileged account in the organization. Registering member accounts as delegated administrators for AWS services distributes service‑specific administration to dedicated security, logging, or operations accounts that can be restricted by SCPs, monitored like other workload accounts, and aligned with team responsibilities, while reducing day‑to‑day use of the management account.
  "
  desc  'rationale', "
    Ensure that AWS services (such as AWS CloudTrail) which integrate with AWS Organizations and support delegated administration are managed through delegated administrator member accounts instead of directly from the Organizations management account. For each such service, the management account should enable trusted access and register a purpose‑built member account as the delegated administrator, so that this account can perform service‑level administration across all organization accounts.

    The management account has unique and high privileges to manage AWS Organizations (for example, creating/deleting accounts, managing org structures) and is not subject to guardrails like SCPs. Without delegated administrators, organization‑wide security, logging, and management services must be operated directly from the management account, concentrating operational activity and credentials in the most privileged account in the organization. Registering member accounts as delegated administrators for AWS services distributes service‑specific administration to dedicated security, logging, or operations accounts that can be restricted by SCPs, monitored like other workload accounts, and aligned with team responsibilities, while reducing day‑to‑day use of the management account.
  "
  desc  'check', "
    Note: This audit uses AWS CloudTrail as a concrete example. You must perform similar audits for all other AWS services that integrate with AWS Organizations and support delegated administration that are in use in your environment.

    1. Sign in to the management account and open the CloudTrail console.

    2. In the left navigation pane, choose Trails.
    - Verify that there is at least one organization trail (trail with Apply trail to all accounts in my organization or equivalent setting enabled)
    - If CloudTrail is only configured as single‑account trails and no organization trail is in use, note that delegated admin for CloudTrail is not in scope and this recommendation is not applicable for CloudTrail in this environment.

    3. In the same management account CloudTrail console, choose Settings in the left navigation pane, and scroll to the Organization delegated administrators section.

    4. Verify the configuration for Organization delegated administrators:
    - Verify that at least one member account ID (not the management account) is listed as a delegated administrator for CloudTrail.
    - Verify that the account(s) are appropriate for security/logging operations (for example, a named Security or Logging account, not a sandbox or general workload account).
    - If the section shows \"No delegated administrators\" when an organization trail is in use, CloudTrail is effectively administered from the management account and this is a gap.
  "
  desc  'fix', "
    Note: This remediation section uses AWS CloudTrail as a concrete example. You must perform similar procedure for all other AWS services that integrate with AWS Organizations and support delegated administration that are in use in your environment.

    1. In the management account, verify that trusted access for CloudTrail is enabled in AWS Organizations (AWS Organizations → Services). 

    2. In the management account CloudTrail console, choose Settings in the left navigation pane. Scroll to Organization delegated administrators.

    3. Click on \"Register administrator\"
    - Enter the account ID of the designated Logging or Security account.
    - Click on Register administrator. CloudTrail will automatically create the necessary service‑linked roles and register the account.

    4. In the delegated administrator account, open the CloudTrail console and confirm that the organization trail is visible and administrative actions are accessible.

    5. Update operational runbooks so that routine CloudTrail administration is performed from the delegated admin account, not the management account.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '2.1.6'
  tag cis_rid:               '2.1.6'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020106r1_rule'
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

  # Dual-mode (see C-2.1.2): when aws_organizations_role_arn is set,
  # AssumeRole into the mgmt account and enumerate the Organizations-
  # integrated services with trusted access enabled. CIS 2.1.6 expects
  # the security-relevant integrated services (IAM, Config, GuardDuty,
  # Security Hub, etc.) to be enabled so they can roll up centrally.
  # We assert IAM trusted access at minimum, since that's the prereq
  # for centralized root access (C-2.1.1) and for SCP/RCP enforcement
  # to apply to IAM principals.
  role_arn = input('aws_organizations_role_arn').to_s

  if role_arn.empty?
    describe 'Delegated admins manage Organizations-integrated services (requires management context)' do
      skip 'attestation-required: list_aws_service_access_for_organization requires Organizations management context. Set input aws_organizations_role_arn to a cross-account role for full automation; otherwise periodic-review attestation per profiles/cis-aws-foundations/attestations.example.json control_id C-2.1.6.'
    end
  else
    svc_access = aws_organizations_aws_service_access(role_arn: role_arn)

    if svc_access.connection_error
      describe 'Trusted-service access enumeration (requires aws_organizations_role_arn)' do
        it 'is callable via the cross-account role' do
          expect(svc_access.connection_error).to be_nil, svc_access.connection_error
        end
      end
    else
      describe svc_access do
        its('service_principals') { should include 'iam.amazonaws.com' }
      end
    end
  end
end
