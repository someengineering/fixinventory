from datetime import datetime
from typing import ClassVar, Dict, Optional, List, Type

from attrs import define, field

from resoto_plugin_aws.resource.base import AwsResource, AwsApiSpec
from resoto_plugin_aws.utils import ToDict
from resotolib.json_bender import Bender, S

service_name = "acm"


@define(eq=False, slots=False)
class AwsAcmCertificate(AwsResource):
    kind: ClassVar[str] = "aws_certificate"
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec(service_name, "list-certificates", "CertificateSummaryList")
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("id"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "name": S("DomainName"),
        "ctime": S("CreatedAt"),
        "arn": S("CertificateArn"),
        "subject_alternative_name_summaries": S("SubjectAlternativeNameSummaries", default=[]),
        "has_additional_subject_alternative_names": S("HasAdditionalSubjectAlternativeNames"),
        "status": S("Status"),
        "type": S("Type"),
        "key_algorithm": S("KeyAlgorithm"),
        "key_usages": S("KeyUsages", default=[]),
        "extended_key_usages": S("ExtendedKeyUsages", default=[]),
        "in_use": S("InUse"),
        "exported": S("Exported"),
        "renewal_eligibility": S("RenewalEligibility"),
        "not_before": S("NotBefore"),
        "not_after": S("NotAfter"),
        "created_at": S("CreatedAt"),
        "issued_at": S("IssuedAt"),
        "imported_at": S("ImportedAt"),
        "revoked_at": S("RevokedAt"),
    }
    subject_alternative_name_summaries: Optional[List[str]] = field(factory=list, metadata={"description": "One or more domain names (subject alternative names) included in the certificate. This list contains the domain names that are bound to the public key that is contained in the certificate. The subject alternative names include the canonical domain name (CN) of the certificate and additional domain names that can be used to connect to the website.  When called by ListCertificates, this parameter will only return the first 100 subject alternative names included in the certificate. To display the full list of subject alternative names, use DescribeCertificate."})  # fmt: skip
    has_additional_subject_alternative_names: Optional[bool] = field(default=None, metadata={"description": "When called by ListCertificates, indicates whether the full list of subject alternative names has been included in the response. If false, the response includes all of the subject alternative names included in the certificate. If true, the response only includes the first 100 subject alternative names included in the certificate. To display the full list of subject alternative names, use DescribeCertificate."})  # fmt: skip
    status: Optional[str] = field(default=None, metadata={"description": "The status of the certificate. A certificate enters status PENDING_VALIDATION upon being requested, unless it fails for any of the reasons given in the troubleshooting topic Certificate request fails. ACM makes repeated attempts to validate a certificate for 72 hours and then times out. If a certificate shows status FAILED or VALIDATION_TIMED_OUT, delete the request, correct the issue with DNS validation or Email validation, and try again. If validation succeeds, the certificate enters status ISSUED."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "The source of the certificate. For certificates provided by ACM, this value is AMAZON_ISSUED. For certificates that you imported with ImportCertificate, this value is IMPORTED. ACM does not provide managed renewal for imported certificates. For more information about the differences between certificates that you import and those that ACM provides, see Importing Certificates in the Certificate Manager User Guide."})  # fmt: skip
    key_algorithm: Optional[str] = field(default=None, metadata={"description": "The algorithm that was used to generate the public-private key pair."})  # fmt: skip
    key_usages: Optional[List[str]] = field(factory=list, metadata={"description": "A list of Key Usage X.509 v3 extension objects. Each object is a string value that identifies the purpose of the public key contained in the certificate. Possible extension values include DIGITAL_SIGNATURE, KEY_ENCHIPHERMENT, NON_REPUDIATION, and more."})  # fmt: skip
    extended_key_usages: Optional[List[str]] = field(factory=list, metadata={"description": "Contains a list of Extended Key Usage X.509 v3 extension objects. Each object specifies a purpose for which the certificate public key can be used and consists of a name and an object identifier (OID)."})  # fmt: skip
    in_use: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the certificate is currently in use by any Amazon Web Services resources."})  # fmt: skip
    exported: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the certificate has been exported. This value exists only when the certificate type is PRIVATE."})  # fmt: skip
    renewal_eligibility: Optional[str] = field(default=None, metadata={"description": "Specifies whether the certificate is eligible for renewal. At this time, only exported private certificates can be renewed with the RenewCertificate command."})  # fmt: skip
    not_before: Optional[datetime] = field(default=None, metadata={"description": "The time before which the certificate is not valid."})  # fmt: skip
    not_after: Optional[datetime] = field(default=None, metadata={"description": "The time after which the certificate is not valid."})  # fmt: skip
    issued_at: Optional[datetime] = field(default=None, metadata={"description": "The time at which the certificate was issued. This value exists only when the certificate type is AMAZON_ISSUED."})  # fmt: skip
    imported_at: Optional[datetime] = field(default=None, metadata={"description": "The date and time when the certificate was imported. This value exists only when the certificate type is IMPORTED."})  # fmt: skip
    revoked_at: Optional[datetime] = field(default=None, metadata={"description": "The time at which the certificate was revoked. This value exists only when the certificate status is REVOKED."})  # fmt: skip


resources: List[Type[AwsResource]] = [AwsAcmCertificate]
