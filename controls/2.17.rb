# encoding: UTF-8

control 'C-2.17' do
  title 'Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed'
  desc  "
    To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You should use AWS Certificate Manager (ACM) to store and deploy server certificates, as storing certificates in IAM is no longer recommended. Use IAM only when you must support HTTPS connections in a region or service that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console.

    Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application or website behind the ELB. As a best practice, it is recommended to delete expired certificates and migrate certificate management to AWS Certificate Manager (ACM) where supported.
  "
  desc  'rationale', "
    To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You should use AWS Certificate Manager (ACM) to store and deploy server certificates, as storing certificates in IAM is no longer recommended. Use IAM only when you must support HTTPS connections in a region or service that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console.

    Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application or website behind the ELB. As a best practice, it is recommended to delete expired certificates and migrate certificate management to AWS Certificate Manager (ACM) where supported.
  "
  desc  'check', "
    From Console:

    Getting certificate expiration information via the AWS Management Console is not currently supported for IAM-stored certificates. To request information about SSL/TLS certificates stored in IAM, use the Command Line Interface (CLI).

    From Command Line:

    1. Run the following command to list all IAM-stored server certificates:


    ```
    aws iam list-server-certificates
    ```

    2. The command output returns an array containing all SSL/TLS certificates and their metadata:

    ```
    {
        \"ServerCertificateMetadataList\": [
            {
                \"ServerCertificateId\": \"EHDGFRW7EJFYTE88D\",
                \"ServerCertificateName\": \"MyServerCertificate\",
                \"Expiration\": \"2018-07-10T23:59:59Z\",
                \"Path\": \"/\",
                \"Arn\": \"arn:aws:iam::012345678910:server-certificate/MySSLCertificate\",
                \"UploadDate\": \"2018-06-10T11:56:08Z\"
            }
        ]
    }
    ```

    3. Review the `Expiration` value for each certificate and determine if any certificates are expired

    4. If expired certificates are identified, they should be removed

    5. If the command returns:

    ```
    { { \"ServerCertificateMetadataList\": [] }
    ```

    This indicates that no certificates are currently stored in IAM
  "
  desc  'fix', "
    From Console:

    Removing expired certificates via the AWS Management Console is not currently supported. Use the CLI to delete IAM-stored certificates.


    From Command Line:

    1. Run the following command to delete an expired certificate:

    ```
    aws iam delete-server-certificate --server-certificate-name ```
    2. A successful command returns no output
  "
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'AU-7 a']
  tag cci:                   ['CCI-001315', 'CCI-001875']
  tag cis_number:            '2.17'
  tag cis_rid:               '2.17'
  tag cis_benchmark:         'CIS Amazon Web Services Foundations Benchmark v7.0.0'
  tag cis_rule_id:           'SV-0217r1_rule'
  tag cis_version:           '7.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  impact 0.5
  cert_names = scoped_or_na(aws_iam_server_certificates.server_certificate_names,
                               in_scope: applicable_partition,
                               reason:   "Control out of scope (partition=#{input('aws_partition')}) or no IAM server certificates in this account")

  # Any IAM server certificate whose expiration is in the past fails.
  cert_names.each do |name|
    describe aws_iam_server_certificate(server_certificate_name: name) do
      its('expiration') { should be > Time.now }
    end
  end
end
