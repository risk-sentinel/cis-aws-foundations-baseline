# encoding: UTF-8

control 'C-2.14' do
  title 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached'
  desc  "
    IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered standard security advice to grant least privilege, granting only the permissions required to perform a task. Determine what users need to do, and then craft policies for them that allow the users to perform only those tasks, instead of granting full administrative privileges.

    It is more secure to start with a minimal set of permissions and grant additional permissions as necessary, rather than starting with overly permissive access and attempting to restrict it later.

    Providing full administrative privileges instead of restricting access to the minimum required exposes resources to potentially unintended or malicious actions.

    IAM policies that contain a statement with `\"Effect\": \"Allow\"` and `\"Action\": \"*\"` over `\"Resource\": \"*\"` should be removed.
  "
  desc  'rationale', "
    IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered standard security advice to grant least privilege, granting only the permissions required to perform a task. Determine what users need to do, and then craft policies for them that allow the users to perform only those tasks, instead of granting full administrative privileges.

    It is more secure to start with a minimal set of permissions and grant additional permissions as necessary, rather than starting with overly permissive access and attempting to restrict it later.

    Providing full administrative privileges instead of restricting access to the minimum required exposes resources to potentially unintended or malicious actions.

    IAM policies that contain a statement with `\"Effect\": \"Allow\"` and `\"Action\": \"*\"` over `\"Resource\": \"*\"` should be removed.
  "
  desc  'check', "
    Perform the following to determine existing policies:

    From Command Line:

    1. Run the following to get a list of IAM policies:
    ```
    aws iam list-policies --only-attached --output text
    ```
    2. For each policy returned, evaluate the default policy version to determine if it allows full administrative privileges (\"*:*\"). The default version represents the effective permissions applied.

    3. Alternatively, the following command can be used to identify all attached policies that allow full administrative privileges and list associated entities:

    ```
    policies=$(aws iam list-policies --scope All --only-attached --query 'Policies[*].Arn' --output text)

    for arn in $policies; do
      version=$(aws iam get-policy --policy-arn \"$arn\" --query 'Policy.DefaultVersionId' --output text)

      is_admin=$(aws iam get-policy-version --policy-arn \"$arn\" --version-id \"$version\" --query 'PolicyVersion.Document' | jq -r '
          .Statement | 
          (if type == \"array\" then .[] else . end) | 
          select(.Effect == \"Allow\") | 
          select(
              (.Action | if type == \"array\" then .[] else . end == \"*\") and 
              (.Resource | if type == \"array\" then .[] else . end == \"*\")
          )
      ')

      if [ ! -z \"$is_admin\" ]; then
          echo \"------------------------------------------------------------\"
          echo \"ADMIN POLICY FOUND: $arn\"
          echo \"ATTACHED ENTITIES:\"
      
          aws iam list-entities-for-policy --policy-arn \"$arn\" --query '{Users: PolicyUsers[*].UserName, Roles: PolicyRoles[*].RoleName, Groups: PolicyGroups[*].GroupName}' --output yaml
      fi
    done
    ```
    4. In the output, no policy should contain a statement with:
    - \"Effect\": \"Allow\"
    - \"Action\": \"*\"
    - \"Resource\": \"*\"
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and open the IAM console
    2. In the navigation pane, click `Policies`
    3. Search for the policy identified in the audit step
    4. Select the policy
    5. Choose `Detach`
    6. Detach the policy from all `Users`, `Groups`, and `Roles`
    7. Delete the policy if it is no longer required

    From Command Line:

    1. List all entities attached to the policy:
    ```
    aws iam list-entities-for-policy --policy-arn ```
    2. Detach from users:
    ```
    aws iam detach-user-policy --user-name --policy-arn ```
    3. Detach from groups:
    ```
    aws iam detach-group-policy --group-name --policy-arn ```
    4. Detach from roles:
    ```
    aws iam detach-role-policy --role-name --policy-arn ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a', 'AC-2 c']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['AC-2 c', 'CM-6 a']
  tag cci:                   ['CCI-000364', 'CCI-002113']
  tag cis_number:            '2.14'
  tag cis_rid:               '2.14'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0214r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  # Scan every customer-managed attached policy; fail if any has a
  # statement with Action "*" and Resource "*".
  aws_iam_policies.where { attachment_count.positive? }.policy_names.each do |name|
    describe aws_iam_policy(policy_name: name) do
      it { should_not have_statement(Action: '*', Resource: '*') }
    end
  end
end
