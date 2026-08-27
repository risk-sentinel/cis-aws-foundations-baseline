# Custom resources for AWS Account contact information.
# Depends on `_aws_backend_bootstrap.rb` having been loaded first (its
# leading underscore sorts it before this file in InSpec's alphabetical
# library-load order).
# Not in inspec-aws 1.83.63; added locally to cover CIS AWS Foundations
# controls 2.2 (primary contact) and 2.3 (security alternate contact).
# Context: docs/dev/issue_20_design.md.
#
# Uses @aws.aws_client(Aws::Account::Client) — train-aws does not expose
# an account_client accessor, but aws_client(klass) is the supported path
# and retains SDK-call caching.
#
# The `aws-sdk-account` gem is not part of inspec-aws's default vendored
# set. Defensive require, following the `aws_workdocs_inventory` pattern,
# so controls degrade to a clear connection_error skip if the gem is
# missing from the cinc-auditor image instead of raising
# `uninitialized constant Aws::Account` at exec time.
ACCOUNT_GEM_LOAD_ERROR = begin
  require "aws-sdk-account"
  nil
rescue LoadError => e
  "aws-sdk-account gem not installed: #{e.message}. File a tracking issue against the cinc-auditor docker image to bundle the gem."
end

class AwsAccountAlternateContact < AwsResourceBase
  name "aws_account_alternate_contact"
  desc "AWS account alternate contact (BILLING, OPERATIONS, or SECURITY)."
  example "
    describe aws_account_alternate_contact(contact_type: 'SECURITY') do
      it { should exist }
      its('email_address') { should match(/@/) }
      its('phone_number')  { should_not be_empty }
    end
  "

  VALID_TYPES = %w[BILLING OPERATIONS SECURITY].freeze

  attr_reader :contact_type, :contact_name, :title, :email_address, :phone_number, :connection_error

  def initialize(opts = {})
    opts = { contact_type: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:contact_type])
    @contact_type = opts[:contact_type].to_s.upcase
    raise ArgumentError, "contact_type must be one of: #{VALID_TYPES.join(', ')}" \
      unless VALID_TYPES.include?(@contact_type)
    @connection_error = ACCOUNT_GEM_LOAD_ERROR
    return if @connection_error
    fetch_data
  end

  def exists?
    @exists == true
  end

  def to_s
    "AWS Account #{@contact_type} Contact"
  end

  private

  def fetch_data
    @exists = false
    catch_aws_errors do
      begin
        resp = account_client.get_alternate_contact(alternate_contact_type: @contact_type)
        ac = resp.alternate_contact
        @exists = true
        @contact_name  = ac.name
        @title         = ac.title
        @email_address = ac.email_address
        @phone_number  = ac.phone_number
      rescue Aws::Account::Errors::ResourceNotFoundException
        @exists = false
      end
    end
  end

  def account_client
    @aws.aws_client(Aws::Account::Client)
  end
end

class AwsAccountPrimaryContact < AwsResourceBase
  name "aws_account_primary_contact"
  desc "AWS account primary contact information."
  example "
    describe aws_account_primary_contact do
      it { should exist }
      its('full_name')    { should_not be_empty }
      its('phone_number') { should_not be_empty }
    end
  "

  attr_reader :full_name, :address_line_1, :address_line_2, :city,
              :company_name, :country_code, :district_or_county,
              :phone_number, :postal_code, :state_or_region, :website_url,
              :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @connection_error = ACCOUNT_GEM_LOAD_ERROR
    return if @connection_error
    fetch_data
  end

  def exists?
    @exists == true
  end

  def to_s
    "AWS Account Primary Contact"
  end

  private

  def fetch_data
    @exists = false
    catch_aws_errors do
      begin
        resp = account_client.get_contact_information
        ci = resp.contact_information
        @exists             = true
        @full_name          = ci.full_name
        @address_line_1     = ci.address_line_1
        @address_line_2     = ci.address_line_2
        @city               = ci.city
        @company_name       = ci.company_name
        @country_code       = ci.country_code
        @district_or_county = ci.district_or_county
        @phone_number       = ci.phone_number
        @postal_code        = ci.postal_code
        @state_or_region    = ci.state_or_region
        @website_url        = ci.website_url
      rescue Aws::Account::Errors::ResourceNotFoundException
        @exists = false
      end
    end
  end

  def account_client
    @aws.aws_client(Aws::Account::Client)
  end
end
