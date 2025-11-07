
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager.models
{
    #region Base Response Models

    public class ApiResponse
    {
        [JsonPropertyName("error")]
        public int Error { get; set; }

        [JsonPropertyName("msg")]
        public string Message { get; set; }
    }

    public class ApiErrorResponse : ApiResponse
    {
    }

    public class ApiErrorResponseWithCertIds : ApiResponse
    {
        [JsonPropertyName("errors")]
        public List<CertificateError> Errors { get; set; }
    }

    public class CertificateError
    {
        [JsonPropertyName("certid")]
        public string CertId { get; set; }

        [JsonPropertyName("errorcode")]
        public int ErrorCode { get; set; }

        [JsonPropertyName("errormessage")]
        public string ErrorMessage { get; set; }

        [JsonPropertyName("servererrormessage")]
        public string ServerErrorMessage { get; set; }
    }

    public class ApiErrorResponseWithJsonArrayIndex : ApiResponse
    {
        [JsonPropertyName("errors")]
        public List<ImportError> Errors { get; set; }
    }

    public class ImportError
    {
        [JsonPropertyName("arrayindex")]
        public int ArrayIndex { get; set; }

        [JsonPropertyName("errorcode")]
        public int ErrorCode { get; set; }

        [JsonPropertyName("errormessage")]
        public string ErrorMessage { get; set; }

        [JsonPropertyName("servererrormessage")]
        public string ServerErrorMessage { get; set; }

        [JsonPropertyName("limit")]
        public int? Limit { get; set; }
    }

    #endregion

    #region Certificate Models

    public class CertificateListResponse : ApiResponse
    {
        [JsonPropertyName("searchHits")]
        public int SearchHits { get; set; }

        [JsonPropertyName("certificates")]
        public List<JsonCertificate> Certificates { get; set; }
    }

    public class CertificateDetailsResponse : ApiResponse
    {
        [JsonPropertyName("certificate")]
        public JsonCertificate Certificate { get; set; }
    }

    public class JsonCertificate
    {
        [JsonPropertyName("certid")]
        public string CertId { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("reason")]
        public string Reason { get; set; }

        [JsonPropertyName("revocationtime")]
        public DateTime? RevocationTime { get; set; }

        [JsonPropertyName("validto")]
        public long? ValidTo { get; set; }

        [JsonPropertyName("validfrom")]
        public long? ValidFrom { get; set; }

        [JsonPropertyName("certificateserialnumber")]
        public string CertificateSerialNumber { get; set; }

        [JsonPropertyName("subject")]
        public string Subject { get; set; }

        [JsonPropertyName("issuer")]
        public string Issuer { get; set; }

        [JsonPropertyName("keyusage")]
        public List<string> KeyUsage { get; set; }

        [JsonPropertyName("subjectType")]
        public string SubjectType { get; set; }

        [JsonPropertyName("extendedcertsearch")]
        public ExtendedCertSearch ExtendedCertSearch { get; set; }

        [JsonPropertyName("authorityKeyIdentifier")]
        public string AuthorityKeyIdentifier { get; set; }

        [JsonPropertyName("subjectKeyIdentifier")]
        public string SubjectKeyIdentifier { get; set; }

        [JsonPropertyName("validity")]
        public string Validity { get; set; }
    }

    public class ExtendedCertSearch
    {
        [JsonPropertyName("field1")]
        public string Field1 { get; set; }

        [JsonPropertyName("field2")]
        public string Field2 { get; set; }

        [JsonPropertyName("field3")]
        public string Field3 { get; set; }

        [JsonPropertyName("field4")]
        public string Field4 { get; set; }

        [JsonPropertyName("field5")]
        public string Field5 { get; set; }

        [JsonPropertyName("field6")]
        public string Field6 { get; set; }
    }

    public class IssuerListResponse : ApiResponse
    {
        [JsonPropertyName("searchHits")]
        public int SearchHits { get; set; }

        [JsonPropertyName("subjects")]
        public List<JsonIssuer> Subjects { get; set; }
    }

    public class JsonIssuer
    {
        [JsonPropertyName("subjectDn")]
        public string SubjectDn { get; set; }

        [JsonPropertyName("subject")]
        public Dictionary<string, string> Subject { get; set; }
    }

    #endregion

    #region Certificate Operation Requests

    public class RevokeCertificateRequest
    {
        [JsonPropertyName("certid")]
        public List<string> CertId { get; set; }

        [JsonPropertyName("reason")]
        public int Reason { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    public class RemoveCertificatesRequest
    {
        [JsonPropertyName("certid")]
        public List<string> CertId { get; set; }

        [JsonPropertyName("cleanAuditLog")]
        public bool CleanAuditLog { get; set; } = true;

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    #endregion

    #region Certificate Issuance Models

    public class IssueCertificatePkcs10Request
    {
        [JsonPropertyName("pkcs10")]
        public string Pkcs10 { get; set; }

        [JsonPropertyName("validfrom")]
        public DateTime? ValidFrom { get; set; }

        [JsonPropertyName("validto")]
        public DateTime? ValidTo { get; set; }

        [JsonPropertyName("procname")]
        public string ProcName { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    public class IssueCertificatePkcs10ToAttrCertRequest
    {
        [JsonPropertyName("pkcs10")]
        public string Pkcs10 { get; set; }

        [JsonPropertyName("validfrom")]
        public DateTime? ValidFrom { get; set; }

        [JsonPropertyName("validto")]
        public DateTime? ValidTo { get; set; }

        [JsonPropertyName("procname")]
        public string ProcName { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    public class ImportPkiX509Request
    {
        [JsonPropertyName("procname")]
        public string ProcName { get; set; }

        [JsonPropertyName("importdata")]
        public List<ImportCertificateData> ImportData { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    public class ImportCertificateData
    {
        [JsonPropertyName("certificate")]
        public string Certificate { get; set; }

        [JsonPropertyName("reason")]
        public int? Reason { get; set; }

        [JsonPropertyName("revocationtime")]
        public DateTime? RevocationTime { get; set; }
    }

    public class SignatureResponse
    {
        [JsonPropertyName("error")]
        public int Error { get; set; }

        [JsonPropertyName("msg")]
        public string Message { get; set; }

        [JsonPropertyName("dataToSign")]
        public string DataToSign { get; set; }
    }

    #endregion

    #region Enums

    public static class RevocationReason
    {
        public const int Unspecified = 0;
        public const int KeyCompromise = 1;
        public const int AffiliationChanged = 3;
        public const int Superseded = 4;
        public const int CessationOfOperation = 5;
        public const int CertificateHold = 6;
        public const int PrivilegeWithdrawn = 9;
    }

    public static class RegistrationType
    {
        public const string EST = "est";
        public const string CMP = "cmp";
        public const string SCEP = "scep";
        public const string Device = "device";
        public const string ACME = "acme";
        public const string ACMEAccount = "acme/account";
        public const string ITSS = "itss";
    }

    public static class RegistrationStatus
    {
        public const string Open = "open";
        public const string Closed = "closed";
    }

    public static class CertificateStatus
    {
        public const string Active = "active";
        public const string Revoked = "revoked";
    }

    public static class CertificateValidity
    {
        public const string Valid = "valid";
        public const string Expired = "expired";
        public const string NotYetValid = "notYetValid";
    }

    public static class SubjectType
    {
        public const string EndEntity = "EE";
        public const string CertificateAuthority = "CA";
    }

    public static class HashAlgorithm
    {
        public const string SHA224 = "SHA-224";
        public const string SHA256 = "SHA-256";
        public const string SHA384 = "SHA-384";
        public const string SHA512 = "SHA-512";
        public const string SHA512_224 = "SHA-512/224";
        public const string SHA512_256 = "SHA-512/256";
        public const string SHA3_224 = "SHA3-224";
        public const string SHA3_256 = "SHA3-256";
        public const string SHA3_384 = "SHA3-384";
        public const string SHA3_512 = "SHA3-512";
    }

    public static class SignatureFormat
    {
        public const string SignedData = "SignedData";
        public const string Signature = "Signature";
    }

    public static class Protocol
    {
        public const string SCEP = "SCEP";
        public const string CMP = "CMP";
        public const string Device = "DEVICE";
        public const string ACME = "ACME";
        public const string EST = "EST";
        public const string ITSS = "ITSS";
    }

    #endregion

}
