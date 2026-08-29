# encoding: UTF-8

control 'C-2.1.5' do
  title 'Ensure delegated admin manages AWS Organizations policies'
  desc  "
    Ensure that a dedicated member account is configured as a delegated administrator for AWS Organizations to manage organization policies (SCPs, RCPs, tag policies, backup policies, AI opt‑out policies) and other Organizations features, instead of performing these tasks directly from the management account. The delegated administrator for AWS Organizations is configured via a resource‑based delegation policy in the management account, which grants specific member accounts limited permissions to perform Organizations policy and account management actions across the organization. This allows policy management, OU operations, and other governance tasks to be handled from purpose‑built accounts without requiring broad access to the management account.

    The management account has unique and high privileges to manage AWS Organizations (for example, creating/deleting accounts, managing org structures) and is not subject to guardrails like SCPs. Without a delegated administrator for Organizations, all policy management, OU changes, and account governance must be performed directly from the management account. This results in concentrating operational activity in the most powerful account. Configuring a dedicated member account as a delegated administrator for Organizations policy management distributes these tasks to a purpose‑built AWS account that can be protected by SCPs and other controls, reduces the number of users and roles that need management‑account access, and supports separation of duties while maintaining centralized control over organization‑wide features.
  "
  desc  'rationale', "
    Ensure that a dedicated member account is configured as a delegated administrator for AWS Organizations to manage organization policies (SCPs, RCPs, tag policies, backup policies, AI opt‑out policies) and other Organizations features, instead of performing these tasks directly from the management account. The delegated administrator for AWS Organizations is configured via a resource‑based delegation policy in the management account, which grants specific member accounts limited permissions to perform Organizations policy and account management actions across the organization. This allows policy management, OU operations, and other governance tasks to be handled from purpose‑built accounts without requiring broad access to the management account.

    The management account has unique and high privileges to manage AWS Organizations (for example, creating/deleting accounts, managing org structures) and is not subject to guardrails like SCPs. Without a delegated administrator for Organizations, all policy management, OU changes, and account governance must be performed directly from the management account. This results in concentrating operational activity in the most powerful account. Configuring a dedicated member account as a delegated administrator for Organizations policy management distributes these tasks to a purpose‑built AWS account that can be protected by SCPs and other controls, reduces the number of users and roles that need management‑account access, and supports separation of duties while maintaining centralized control over organization‑wide features.
  "
  desc  'check', "
    1. Sign in to the AWS Organizations console. From the AWS Accounts section, verify that this is the management account for the organization.

    2. In the AWS Organizations console, navigate to Settings. Scroll to the Delegated administrator for AWS Organizations section

    3. Review the delegation policy status:
    - If a delegation policy is configured and shows one or more member accounts registered to manage Organizations policies, proceed to step 4.
    - If no delegation policy is configured or the section shows No delegated administrator (or equivalent), the audit fails because Organizations management is performed directly from the management account.

    4. In the Delegated administrator section, note the account IDs registered for Organizations policy management. Confirm that the delegated accounts are purpose‑built governance, security, or policy management accounts, not general workload, sandbox, or development accounts.

    5. View the delegation policy details to confirm it grants appropriate least-privilege permissions for policy types (for example, SCPs, tag policies, backup policies) and actions (CreatePolicy, AttachPolicy, UpdatePolicy, etc.).
  "
  desc  'fix', "
    1. Identify a dedicated member account for governance/policy management (for example, create a new \"Policy Management\" account or use an existing Security account)

    2. You must be in the management account with permissions to manage Organizations resource policies. Navigate to AWS Organizations console, then click on Settings and browse to \"Delegated administrator for AWS Organizations\" section. 

    3. If no policy exists, click on Delegate. If a policy exists, choose Edit policy.
    - In the policy editor, paste or construct a delegation policy statement mentioning the Principal as the AWS account Root which is being delegated access to, and the Actions with the list of least-privileged permissions that could be performed by the delegated AWS account. 
    - Save and validate the delegation policy.

    4. Sign in to the delegated administrator account and open the AWS Organizations console.
    - Confirm that policy management (Policies, Attach/Detach, etc.) is accessible and that users/roles in this account can perform Organizations tasks without management‑account access.

    5. Grant IAM roles/users in the delegated admin account only the permissions needed for Organizations policy management.

    6. Update procedures so that routine Organizations policy tasks are performed from the delegated account, reserving the management account for tasks that only it can perform
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '2.1.5'
  tag cis_rid:               '2.1.5'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-020105r1_rule'
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
  # AssumeRole into the mgmt account and assert at least one delegated
  # administrator is registered. CIS 2.1.5 wants policy management
  # delegated away from the mgmt account itself; the bare existence of
  # a delegated admin is the necessary precondition.
  role_arn = input('aws_organizations_role_arn').to_s

  if role_arn.empty?
    describe 'Delegated admin manages Organizations policies (requires management context)' do
      skip 'attestation-required: list_delegated_administrators requires management or delegated-admin context. Set input aws_organizations_role_arn to a cross-account role for full automation; otherwise periodic-review attestation per profiles/cis-aws-foundations/attestations.example.json control_id C-2.1.5.'
    end
  else
    delegated = aws_organizations_delegated_administrators(role_arn: role_arn)

    if delegated.connection_error
      describe 'Delegated administrators enumeration (requires aws_organizations_role_arn)' do
        it 'is callable via the cross-account role' do
          expect(delegated.connection_error).to be_nil, delegated.connection_error
        end
      end
    else
      describe delegated do
        its('count') { should be > 0 }
      end
    end
  end
end
