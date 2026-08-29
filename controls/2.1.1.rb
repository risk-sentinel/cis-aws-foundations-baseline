# encoding: UTF-8

control 'C-2.1.1' do
  title 'Ensure centralized root access in AWS Organizations'
  desc  "
    Ensure centralized root access management is enabled to manage and secure root user credentials for member accounts in AWS Organizations. This allows the management account and an optional delegated administrator account to centrally delete, prevent recovery of, and if necessary, perform short‑lived, scoped root‑required actions in member accounts without maintaining long‑term root user credentials in each account.

    The AWS account root user is a powerful, default administrative identity that is difficult to manage safely across many accounts. When each member account manages its own root credentials, organizations often end up with numerous long‑lived root passwords, access keys, and MFA devices that are hard to inventory, rotate, and protect. Centralized root access management lets security teams remove or avoid creating root user credentials in member accounts, centrally review and manage any remaining root credentials, and perform necessary root‑only tasks via short‑term, task‑scoped root sessions. This significantly reduces privileged credential sprawl, supports least privilege and dedicated administrator models, and improves visibility and auditability of root‑level activity across the organization.
  "
  desc  'rationale', "
    Ensure centralized root access management is enabled to manage and secure root user credentials for member accounts in AWS Organizations. This allows the management account and an optional delegated administrator account to centrally delete, prevent recovery of, and if necessary, perform short‑lived, scoped root‑required actions in member accounts without maintaining long‑term root user credentials in each account.

    The AWS account root user is a powerful, default administrative identity that is difficult to manage safely across many accounts. When each member account manages its own root credentials, organizations often end up with numerous long‑lived root passwords, access keys, and MFA devices that are hard to inventory, rotate, and protect. Centralized root access management lets security teams remove or avoid creating root user credentials in member accounts, centrally review and manage any remaining root credentials, and perform necessary root‑only tasks via short‑term, task‑scoped root sessions. This significantly reduces privileged credential sprawl, supports least privilege and dedicated administrator models, and improves visibility and auditability of root‑level activity across the organization.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console with the management account.

    2. In the console search bar, type Organizations and open AWS Organizations.
    - On the Overview page, confirm that an Organization exists and that this account is listed as the Management account.
    ​
    3. In AWS Organizations, choose Services. 
    - Confirm that AWS Identity and Access Management appears in the list of services with trusted access enabled.

    4. In the console search bar, type IAM and open IAM. In the left navigation pane, choose Root access management. Check the status banner. 
    - If you see that Root access management is enabled and the feature card shows that root credentials management is turned on for member accounts, the organization has centralized root access management enabled. 

    - If you see Root access management is disabled with an option to Enable, centralized root access is not yet enabled. 

    5. (Optional) On the same Root access management page, review the Delegated administrator information (if shown).
    - Confirm that the delegated account (if present) is a security or management‑focused account, not a general workload account.
  "
  desc  'fix', "
    1. Sign in to the AWS Management Console with the management account.

    2. In the console search bar, type Organizations and open AWS Organizations.
    - On the Overview page, confirm that an Organization exists and that this account is listed as the Management account.
    ​
    3. In AWS Organizations, choose Services. Locate AWS Identity and Access Management in the list and, if it is not already enabled, choose Enable trusted access and confirm.
    - This allows IAM to integrate with AWS Organizations to manage root access centrally.

    4. In the console search bar, type IAM and open IAM. In the left navigation pane, choose Root access management. If you see Root access management is disabled, choose Enable.

    - In the enable dialog, confirm that you want to - \"Root credentials management\" and if desired - \"Privileged root actions in member accounts\"
    - In the Delegated administrator field, enter the account ID of the account that will manage root user access and take privileged actions on member accounts. AWS recommends using an account intended for security or management purposes, not a general workload account.
    - When you enable centralized root access in the console, IAM also enables trusted access for IAM in AWS Organizations if it isn't already enabled.
    - Choose Enable to save the configuration.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c', 'AC-2 f', 'AC-2 (2)']
  tag ksi:                   ['KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 (2)', 'AC-2 c', 'AC-2 f']
  tag cci:                   ['CCI-002113', 'CCI-000011', 'CCI-001682']
  tag cis_number:            '2.1.1'
  tag cis_rid:               '2.1.1'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020101r1_rule'
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

  # Two-tier check:
  # 1. Necessary preconditions, automatable from member-account context:
  #    - Account is enrolled in an AWS Organization
  #    - Organization's FeatureSet is ALL (CONSOLIDATED_BILLING orgs
  #      cannot enable centralized root access)
  # 2. Sufficient check (RootCredentialsManagement feature enabled via
  #    iam:ListOrganizationsFeatures) requires management or delegated-
  #    admin context. Stays attestation here; the dual-mode org-role
  #    automation in C-2.1.2 / 2.1.5 / 2.1.6 covers consumers who run
  #    the scan with an Organizations cross-account role.
  org_ctx = aws_organizations_context

  if org_ctx.connection_error
    describe 'AWS Organizations enrollment (precondition for centralized root access)' do
      it 'requires the scanner account to be enrolled in an Organization' do
        expect(org_ctx.connection_error).to be_nil, org_ctx.connection_error
      end
    end
  else
    describe org_ctx do
      it                 { should be_in_organization }
      its('feature_set') { should eq 'ALL' }
    end

    describe 'Centralized root access management (feature-toggle check requires Organizations management context)' do
      skip 'partial-automation: enrollment + FeatureSet=ALL preconditions verified above. The IAM RootCredentialsManagement feature toggle (iam:ListOrganizationsFeatures) requires management or delegated-admin context — attest via profiles/cis-aws-foundations/attestations.example.json control_id C-2.1.1, OR run the profile with aws_organizations_role_arn set to a cross-account role in the management account (see C-2.1.2 dual-mode pattern).'
    end
  end
end
