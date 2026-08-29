# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure rotation for customer-created symmetric CMKs is enabled'
  desc  "
    AWS Key Management Service (KMS) allows customers to rotate the backing key, which is key material stored within the KMS that is tied to the key ID of the customer-created customer master key (CMK). The backing key is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can occur transparently. It is recommended that CMK key rotation be enabled for symmetric keys. Key rotation cannot be enabled for any asymmetric CMK.

    Rotating encryption keys helps reduce the potential impact of a compromised key, as data encrypted with a new key cannot be accessed with a previous key that may have been exposed. Keys should be rotated every year or upon an event that could result in the compromise of that key.
  "
  desc  'rationale', "
    AWS Key Management Service (KMS) allows customers to rotate the backing key, which is key material stored within the KMS that is tied to the key ID of the customer-created customer master key (CMK). The backing key is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can occur transparently. It is recommended that CMK key rotation be enabled for symmetric keys. Key rotation cannot be enabled for any asymmetric CMK.

    Rotating encryption keys helps reduce the potential impact of a compromised key, as data encrypted with a new key cannot be accessed with a previous key that may have been exposed. Keys should be rotated every year or upon an event that could result in the compromise of that key.
  "
  desc  'check', "
    From Console:

    1. Sign in to the AWS Management Console and open the KMS console at: [https://console.aws.amazon.com/kms](https://console.aws.amazon.com/kms).
    2. In the left navigation pane, click `Customer-managed keys`.
    3. Select a customer-managed CMK where `Key spec = SYMMETRIC_DEFAULT`.
    4. Select the `Key rotation` tab.
    5. Ensure the `Automatically rotate this KMS key every year` box is checked.
    6. Repeat steps 3-5 for all customer-managed CMKs where `Key spec = SYMMETRIC_DEFAULT`.

    From Command Line:

    1. Run the following command to get a list of all keys and their associated `KeyIds`:

    ```
      aws kms list-keys
    ```

    2. For each key, note the KeyId and run the following command:

    ```
    aws kms describe-key --key-id ```

    3. If the response contains `\"KeySpec = SYMMETRIC_DEFAULT\"`, run the following command:

    ```
      aws kms get-key-rotation-status --key-id ```

    4. Ensure `KeyRotationEnabled` is set to `true`.
    5. Repeat steps 2-4 for all remaining CMKs.
    6. Alternatively, the following command can be used to check all keys more comprehensively:
    ```
    KEY_IDS=$(aws kms list-keys --query \"Keys[].KeyId\" --output text)

    for KEY_ID in $KEY_IDS; do
      aws kms get-key-rotation-status --key-id \"$KEY_ID\" --query \"{KeyId:KeyId,RotationEnabled:KeyRotationEnabled}\" --output table
    done
    ```
  "
  desc  'fix', "
    From Console:

    1. Sign in to the AWS Management Console and open the KMS console at: [https://console.aws.amazon.com/kms](https://console.aws.amazon.com/kms).
    2. In the left navigation pane, click `Customer-managed keys`.
    3. Select a key with `Key spec = SYMMETRIC_DEFAULT` that does not have automatic rotation enabled.
    4. Select the `Key rotation` tab.
    5. Check the `Automatically rotate this KMS key every year` box.
    6. Click `Save`.
    7. Repeat steps 3-6 for all customer-managed CMKs that do not have automatic rotation enabled.

    From Command Line:

    1. Run the following command to enable key rotation:

    ```
      aws kms enable-key-rotation --key-id ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0406r1_rule'
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

  rid = '4.6'
  # Iterate every KMS key in the account, skip AWS-managed and external
  # keys (can't rotate externally-keyed material), and require the rest
  # to have rotation enabled.
  aws_kms_keys.key_arns.each do |key_arn|
    key = aws_kms_key(key_arn)
    next unless key.enabled?
    next if key.managed_by_aws?
    next if key.external?

    describe aws_kms_key(key_arn) do
      it { should have_rotation_enabled }
    end
  end
end
