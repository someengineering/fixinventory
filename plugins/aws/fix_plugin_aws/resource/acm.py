import logging
from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsResource, AwsApiSpec, GraphBuilder
from fix_plugin_aws.utils import ToDict
from fixlib.json_bender import Bender, S, ForallBend, Bend, F

log = logging.getLogger("fix.plugins.aws")
service_name = "acm"


@define(eq=False, slots=False)
class AwsAcmResourceRecord:
    kind: ClassVar[str] = "aws_acm_resource_record"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "type": S("Type"), "value": S("Value")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the DNS record to create in your domain. This is supplied by ACM."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The type of DNS record. Currently this can be CNAME."})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The value of the CNAME record to add to your DNS database. This is supplied by ACM."})  # fmt: skip


@define(eq=False, slots=False)
class AwsAcmDomainValidation:
    kind: ClassVar[str] = "aws_acm_domain_validation"
    mapping: ClassVar[Dict[str, Bender]] = {
        "domain_name": S("DomainName"),
        "validation_emails": S("ValidationEmails", default=[]),
        "validation_domain": S("ValidationDomain"),
        "validation_status": S("ValidationStatus"),
        "resource_record": S("ResourceRecord") >> Bend(AwsAcmResourceRecord.mapping),
        "validation_method": S("ValidationMethod"),
    }
    domain_name: Optional[str] = field(default=None, metadata={"description": "A fully qualified domain name (FQDN) in the certificate. For example, www.example.com or example.com."})  # fmt: skip
    validation_emails: Optional[List[str]] = field(default=None, metadata={"description": "A list of email addresses that ACM used to send domain validation emails."})  # fmt: skip
    validation_domain: Optional[str] = field(default=None, metadata={"description": "The domain name that ACM used to send domain validation emails."})  # fmt: skip
    validation_status: Optional[str] = field(default=None, metadata={"description": "The validation status of the domain name."})  # fmt: skip
    resource_record: Optional[AwsAcmResourceRecord] = field(default=None, metadata={"description": "Contains the CNAME record that you add to your DNS database for domain validation."})  # fmt: skip
    validation_method: Optional[str] = field(default=None, metadata={"description": "Specifies the domain validation method."})  # fmt: skip


@define(eq=False, slots=False)
class AwsAcmRenewalSummary:
    kind: ClassVar[str] = "aws_acm_renewal_summary"
    mapping: ClassVar[Dict[str, Bender]] = {
        "renewal_status": S("RenewalStatus"),
        "domain_validation_options": S("DomainValidationOptions", default=[])
        >> ForallBend(AwsAcmDomainValidation.mapping),
        "renewal_status_reason": S("RenewalStatusReason"),
        "updated_at": S("UpdatedAt"),
    }
    renewal_status: Optional[str] = field(default=None, metadata={"description": "The status of ACM's managed renewal of the certificate."})  # fmt: skip
    domain_validation_options: Optional[List[AwsAcmDomainValidation]] = field(factory=list, metadata={"description": "Contains information about the validation of each domain name in the certificate, as it pertains to ACM's managed renewal. This is different from the initial validation that occurs as a result of the RequestCertificate request. This field exists only when the certificate type is AMAZON_ISSUED."})  # fmt: skip
    renewal_status_reason: Optional[str] = field(default=None, metadata={"description": "The reason that a renewal request was unsuccessful."})  # fmt: skip
    updated_at: Optional[datetime] = field(default=None, metadata={"description": "The time at which the renewal summary was last updated."})  # fmt: skip


@define(eq=False, slots=False)
class AwsAcmExtendedKeyUsage:
    kind: ClassVar[str] = "aws_acm_extended_key_usage"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "oid": S("OID")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of an Extended Key Usage value."})  # fmt: skip
    oid: Optional[str] = field(default=None, metadata={"description": "An object identifier (OID) for the extension value. OIDs are strings of numbers separated by periods. The following OIDs are defined in RFC 3280 and RFC 5280.     1.3.6.1.5.5.7.3.1 (TLS_WEB_SERVER_AUTHENTICATION)     1.3.6.1.5.5.7.3.2 (TLS_WEB_CLIENT_AUTHENTICATION)     1.3.6.1.5.5.7.3.3 (CODE_SIGNING)     1.3.6.1.5.5.7.3.4 (EMAIL_PROTECTION)     1.3.6.1.5.5.7.3.8 (TIME_STAMPING)     1.3.6.1.5.5.7.3.9 (OCSP_SIGNING)     1.3.6.1.5.5.7.3.5 (IPSEC_END_SYSTEM)     1.3.6.1.5.5.7.3.6 (IPSEC_TUNNEL)     1.3.6.1.5.5.7.3.7 (IPSEC_USER)"})  # fmt: skip


@define(eq=False, slots=False)
class AwsAcmCertificate(AwsResource):
    kind: ClassVar[str] = "aws_acm_certificate"
    kind_display: ClassVar[str] = "AWS ACM Certificate"
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/acm/home?region={region}#/certificates/{id}", "arn_tpl": "arn:{partition}:acm:{region}:{account}:certificate/{id}"}  # fmt: skip
    kind_description: ClassVar[str] = "An AWS ACM Certificate is used to provision, manage, and deploy Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificates for secure web traffic on AWS services."  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("acm", "describe-certificate", "Certificate")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("CertificateArn") >> F(AwsResource.id_from_arn),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("DomainName"),
        "ctime": S("CreatedAt"),
        "arn": S("CertificateArn"),
        "subject_alternative_names": S("SubjectAlternativeNames", default=[]),
        "domain_validation_options": S("DomainValidationOptions", default=[])
        >> ForallBend(AwsAcmDomainValidation.mapping),
        "serial": S("Serial"),
        "subject": S("Subject"),
        "issuer": S("Issuer"),
        "issued_at": S("IssuedAt"),
        "imported_at": S("ImportedAt"),
        "status": S("Status"),
        "revoked_at": S("RevokedAt"),
        "revocation_reason": S("RevocationReason"),
        "not_before": S("NotBefore"),
        "not_after": S("NotAfter"),
        "key_algorithm": S("KeyAlgorithm"),
        "signature_algorithm": S("SignatureAlgorithm"),
        "in_use_by": S("InUseBy", default=[]),
        "failure_reason": S("FailureReason"),
        "type": S("Type"),
        "renewal_summary": S("RenewalSummary") >> Bend(AwsAcmRenewalSummary.mapping),
        "key_usages": S("KeyUsages", default=[]) >> ForallBend(S("Name")),
        "extended_key_usages": S("ExtendedKeyUsages", default=[]) >> ForallBend(AwsAcmExtendedKeyUsage.mapping),
        "certificate_authority_arn": S("CertificateAuthorityArn"),
        "renewal_eligibility": S("RenewalEligibility"),
        "certificate_transparency_logging": S("Options", "CertificateTransparencyLoggingPreference"),
    }
    subject_alternative_names: Optional[List[str]] = field(factory=list, metadata={"description": "One or more domain names (subject alternative names) included in the certificate. This list contains the domain names that are bound to the public key that is contained in the certificate. The subject alternative names include the canonical domain name (CN) of the certificate and additional domain names that can be used to connect to the website."})  # fmt: skip
    domain_validation_options: Optional[List[AwsAcmDomainValidation]] = field(factory=list, metadata={"description": "Contains information about the initial validation of each domain name that occurs as a result of the RequestCertificate request. This field exists only when the certificate type is AMAZON_ISSUED."})  # fmt: skip
    serial: Optional[str] = field(default=None, metadata={"description": "The serial number of the certificate."})  # fmt: skip
    subject: Optional[str] = field(default=None, metadata={"description": "The name of the entity that is associated with the public key contained in the certificate."})  # fmt: skip
    issuer: Optional[str] = field(default=None, metadata={"description": "The name of the certificate authority that issued and signed the certificate."})  # fmt: skip
    issued_at: Optional[datetime] = field(default=None, metadata={"description": "The time at which the certificate was issued. This value exists only when the certificate type is AMAZON_ISSUED."})  # fmt: skip
    imported_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time when the certificate was imported. This value exists only when the certificate type is IMPORTED."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the certificate. A certificate enters status PENDING_VALIDATION upon being requested, unless it fails for any of the reasons given in the troubleshooting topic Certificate request fails. ACM makes repeated attempts to validate a certificate for 72 hours and then times out. If a certificate shows status FAILED or VALIDATION_TIMED_OUT, delete the request, correct the issue with DNS validation or Email validation, and try again. If validation succeeds, the certificate enters status ISSUED."})  # fmt: skip
    revoked_at: Optional[datetime] = field(default=None, metadata={"description": "The time at which the certificate was revoked. This value exists only when the certificate status is REVOKED."})  # fmt: skip
    revocation_reason: Optional[str] = field(default=None, metadata={"description": "The reason the certificate was revoked. This value exists only when the certificate status is REVOKED."})  # fmt: skip
    not_before: Optional[datetime] = field(default=None, metadata={"description": "The time before which the certificate is not valid."})  # fmt: skip
    not_after: Optional[datetime] = field(default=None, metadata={"description": "The time after which the certificate is not valid."})  # fmt: skip
    key_algorithm: Optional[str] = field(default=None, metadata={"description": "The algorithm that was used to generate the public-private key pair."})  # fmt: skip
    signature_algorithm: Optional[str] = field(default=None, metadata={"description": "The algorithm that was used to sign the certificate."})  # fmt: skip
    # TODO: add edge to the resources that are using the certificate
    in_use_by: Optional[List[str]] = field(factory=list, metadata={"ignore_history": True, "description": "A list of ARNs for the Amazon Web Services resources that are using the certificate. A certificate can be used by multiple Amazon Web Services resources."})  # fmt: skip
    failure_reason: Optional[str] = field(default=None, metadata={"description": "The reason the certificate request failed. This value exists only when the certificate status is FAILED. For more information, see Certificate Request Failed in the Certificate Manager User Guide."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The source of the certificate. For certificates provided by ACM, this value is AMAZON_ISSUED. For certificates that you imported with ImportCertificate, this value is IMPORTED. ACM does not provide managed renewal for imported certificates. For more information about the differences between certificates that you import and those that ACM provides, see Importing Certificates in the Certificate Manager User Guide."})  # fmt: skip
    renewal_summary: Optional[AwsAcmRenewalSummary] = field(default=None, metadata={"description": "Contains information about the status of ACM's managed renewal for the certificate. This field exists only when the certificate type is AMAZON_ISSUED."})  # fmt: skip
    key_usages: Optional[List[str]] = field(factory=list, metadata={"description": "A list of Key Usage X.509 v3 extension objects. Each object is a string value that identifies the purpose of the public key contained in the certificate. Possible extension values include DIGITAL_SIGNATURE, KEY_ENCHIPHERMENT, NON_REPUDIATION, and more."})  # fmt: skip
    extended_key_usages: Optional[List[AwsAcmExtendedKeyUsage]] = field(factory=list, metadata={"description": "Contains a list of Extended Key Usage X.509 v3 extension objects. Each object specifies a purpose for which the certificate public key can be used and consists of a name and an object identifier (OID)."})  # fmt: skip
    certificate_authority_arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the private certificate authority (CA) that issued the certificate. This has the following format:   arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012"})  # fmt: skip
    renewal_eligibility: Optional[str] = field(default=None, metadata={"description": "Specifies whether the certificate is eligible for renewal. At this time, only exported private certificates can be renewed with the RenewCertificate command."})  # fmt: skip
    certificate_transparency_logging: Optional[str] = field(default=None, metadata={"description": "Value that specifies whether to add the certificate to a transparency log. Certificate transparency makes it possible to detect SSL certificates that have been mistakenly or maliciously issued. A browser might respond to certificate that has not been logged by showing an error message. The logs are cryptographically secure."})  # fmt: skip

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        def fetch_certificate(arn: str) -> None:
            with builder.suppress(f"{service_name}.describe-certificate"):
                if res := builder.client.get(service_name, "describe-certificate", "Certificate", CertificateArn=arn):
                    AwsAcmCertificate.collect([res], builder)

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        try:
            for item in builder.client.list(
                aws_service=service_name, action="list-certificates", result_name="CertificateSummaryList"
            ):
                builder.submit_work(service_name, fetch_certificate, item["CertificateArn"])
        except Boto3Error as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.error(msg, log)
            raise
        except Exception as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.info(msg, log)
            raise

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [AwsApiSpec(service_name, "list-certificates"), cls.api_spec]


resources: List[Type[AwsResource]] = [AwsAcmCertificate]
