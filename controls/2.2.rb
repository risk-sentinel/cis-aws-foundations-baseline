# encoding: UTF-8

control 'C-2.2' do
  title 'Maintain current AWS account contact details'
  desc  "
    Ensure contact email and telephone details for AWS accounts are current and mapped to more than one individual in your organization.

    An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of the Acceptable Use Policy or indicative of a likely security compromise is observed by the AWS Abuse team. Contact details should not be associated with a single individual, as circumstances may arise where that individual is unavailable. Email contact details should point to a mail alias that forwards messages to multiple individuals within the organization; where feasible, phone contact details should point to a PABX hunt group or other call-forwarding system. In AWS Organizations environments, this applies to all member accounts, not just the management account.

    If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the listed contact details. If this is unsuccessful and the account behavior requires urgent mitigation, proactive measures may be taken, including throttling traffic between the account exhibiting suspicious behavior and AWS API endpoints or the Internet. This may result in impaired service to and from the affected account. Therefore, it is in both the customer's and AWS's best interests to ensure that prompt contact can be established. This is best achieved by configuring AWS account contact details to point to resources that reach multiple individuals, such as email aliases and PABX hunt groups.
  "
  desc  'rationale', "
    Ensure contact email and telephone details for AWS accounts are current and mapped to more than one individual in your organization.

    An AWS account supports a number of contact details, and AWS will use these to contact the account owner if activity judged to be in breach of the Acceptable Use Policy or indicative of a likely security compromise is observed by the AWS Abuse team. Contact details should not be associated with a single individual, as circumstances may arise where that individual is unavailable. Email contact details should point to a mail alias that forwards messages to multiple individuals within the organization; where feasible, phone contact details should point to a PABX hunt group or other call-forwarding system. In AWS Organizations environments, this applies to all member accounts, not just the management account.

    If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the listed contact details. If this is unsuccessful and the account behavior requires urgent mitigation, proactive measures may be taken, including throttling traffic between the account exhibiting suspicious behavior and AWS API endpoints or the Internet. This may result in impaired service to and from the affected account. Therefore, it is in both the customer's and AWS's best interests to ensure that prompt contact can be established. This is best achieved by configuring AWS account contact details to point to resources that reach multiple individuals, such as email aliases and PABX hunt groups.
  "
  desc  'check', "
    This activity can only be performed via the AWS Console, with a user who has permission to read and write Billing information (aws-portal:*Billing).

    1. Sign in to the AWS Management Console and open the `Billing and Cost Management` console at https://console.aws.amazon.com/billing/home#/.
    2. On the navigation bar, choose your account name, and then choose `Account`.
    3. Under `Contact Information`, review and verify the current details.
  "
  desc  'fix', "
    This activity can only be performed via the AWS Console, with a user who has permission to read and write Billing information (aws-portal:*Billing).

    From Console:

    1. Sign in to the AWS Management Console and open the `Billing and Cost Management` console at https://console.aws.amazon.com/billing/home#/.
    2. On the navigation bar, choose your account name, and then choose `Account`.
    3. On the `Account Settings` page, next to `Account Settings`, choose `Edit`.
    4. Next to the field that you need to update, choose `Edit`.
    5. After you have entered your changes, choose `Save changes`.
    6. After you have made your changes, choose `Done`.
    7. To edit your contact information, under `Contact Information`, choose `Edit`.
    8. For the fields that you want to change, type your updated information, and then choose `Update`.

    From Command Line:

    1. Run the following command:

    ```
    aws account get-contact-information '{
    \"AddressLine1\": \" \",
    \"AddressLine2\": \" \",
    \"City\": \" \",
    \"CompanyName\": \" \",
    \"CountryCode\": \" \",
    \"FullName\": \" \",
    \"PhoneNumber\": \" \",
    \"PostalCode\": \" \",
    \"StateOrRegion\": \" \"
    }'
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IR-6 a']
  tag nist_r4:               ['IR-6 a']
  tag cci:                   ['CCI-000834']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0202r1_rule'
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

  primary = aws_account_primary_contact
  if primary.respond_to?(:connection_error) && primary.connection_error
    describe 'AWS account primary contact' do
      skip "pending-resource: #{primary.connection_error}"
    end
  else
    describe primary do
      it { should exist }
      its('full_name')    { should_not be_empty }
      its('phone_number') { should_not be_empty }
    end
  end
end
