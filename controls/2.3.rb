# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure security contact information is registered'
  desc  "
    AWS provides customers with the option to specify contact information for the account's security team. It is recommended that this information be configured. In AWS Organizations environments, this applies to all member accounts.

    Specifying security-specific contact information helps ensure that security advisories sent by AWS reach the team within your organization that is best equipped to respond to them.
  "
  desc  'rationale', "
    AWS provides customers with the option to specify contact information for the account's security team. It is recommended that this information be configured. In AWS Organizations environments, this applies to all member accounts.

    Specifying security-specific contact information helps ensure that security advisories sent by AWS reach the team within your organization that is best equipped to respond to them.
  "
  desc  'check', "
    Perform the following to determine if security contact information is present:

    From Console:

    1. Click on your account name at the top right corner of the console
    2. From the drop-down menu, Click `Account` 
    3. Scroll down to the `Alternate Contacts`  section
    4. Ensure contact information is specified in the `Security contact` section

    From Command Line:

    1.  Run the following command:

    ``` 
    aws account put-alternate-contact --alternate-contact-type SECURITY --email-address \"\" --name \"\" --phone-number \"\"
    ```
    2. Ensure proper contact information is specified for the `Security` contact.
  "
  desc  'fix', "
    Perform the following to establish security contact information:

    From Console:

    1. Click on your account name at the top right corner of the console
    2. From the drop-down menu click `My Account` 
    3. Scroll down to the `Alternate Contacts` section
    4. Enter contact information in the `Security` section

    From Command Line:

    Run the following command with the following input parameters:
    --email-address, --name, and --phone-number.

    ```
    aws account put-alternate-contact --alternate-contact-type SECURITY --email-address \"\" --name \"\" --phone-number \"\" 
    ``` 

    Note: Consider specifying an internal email distribution list to ensure emails are regularly monitored by more than one individual.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IR-6 a', 'CP-8']
  tag cci:                   ['CCI-000834', 'CCI-000522']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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

  security_contact = aws_account_alternate_contact(contact_type: 'SECURITY')
  if security_contact.respond_to?(:connection_error) && security_contact.connection_error
    describe 'AWS account SECURITY alternate contact' do
      skip "pending-resource: #{security_contact.connection_error}"
    end
  else
    describe security_contact do
      it { should exist }
      its('email_address') { should match(/@/) }
      its('phone_number')  { should_not be_empty }
    end
  end
end
