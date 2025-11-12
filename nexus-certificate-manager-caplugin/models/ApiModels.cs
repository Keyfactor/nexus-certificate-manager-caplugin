
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

        /// <summary>
        /// Indicates whether the API call was successful (Error == 0)
        /// </summary>
        [JsonIgnore]
        public bool IsSuccess => Error == 0;

        /// <summary>
        /// Indicates whether the API call failed (Error != 0)
        /// </summary>
        [JsonIgnore]
        public bool IsError => Error != 0;
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

    /// <summary>
    /// Query parameters for listing certificates
    /// </summary>
    public class ListCertificatesRequest
    {
        // Pagination parameters
        public int? SearchLimit { get; set; }
        public int? SearchOffset { get; set; }
        public string OrderBy { get; set; }
        public bool? OrderDescending { get; set; }

        // Certificate identification
        public string CardSerialNumber { get; set; }
        public string CertificateSerialNumber { get; set; }

        // Revocation filters
        public DateTime? RevocationTimeFrom { get; set; }
        public DateTime? RevocationTimeTo { get; set; }
        public List<int> RevocationReason { get; set; }
        public bool? IsNotRevoked { get; set; }

        // Subject filters
        public string SubjectCommonName { get; set; }
        public string SubjectGivenName { get; set; }
        public string SubjectSurName { get; set; }
        public string SubjectOrganisationName { get; set; }
        public string SubjectOrganisationUnit { get; set; }
        public string SubjectSerialNumber { get; set; }
        public string SubjectCountry { get; set; }

        // Publication filters
        public bool? PublicationAllowed { get; set; }
        public DateTime? PublicationTimeFrom { get; set; }
        public DateTime? PublicationTimeTo { get; set; }

        // OCSP filters
        public DateTime? OcspActivationTimeFrom { get; set; }
        public DateTime? OcspActivationTimeTo { get; set; }

        // Validity filters
        public DateTime? ValidFromTimeFrom { get; set; }
        public DateTime? ValidFromTimeTo { get; set; }
        public bool? IsNotYetValid { get; set; }
        public DateTime? ValidToTimeFrom { get; set; }
        public DateTime? ValidToTimeTo { get; set; }
        public bool? IsExpired { get; set; }

        // Extended search fields
        public string Field1 { get; set; }
        public string Field2 { get; set; }
        public string Field3 { get; set; }
        public string Field4 { get; set; }
        public string Field5 { get; set; }
        public string Field6 { get; set; }

        // Key identifiers
        public string AuthorityKeyIdentifier { get; set; }
        public string SubjectKeyIdentifier { get; set; }

        // Subject type
        public List<string> SubjectType { get; set; }

        // Issuer (RFC1779 distinguished name string, URL encoded)
        public string Issuer { get; set; }

        /// <summary>
        /// Converts the request to a query string
        /// </summary>
        public string ToQueryString()
        {
            var parameters = new List<string>();

            if (SearchLimit.HasValue) parameters.Add($"searchLimit={SearchLimit.Value}");
            if (SearchOffset.HasValue) parameters.Add($"searchOffset={SearchOffset.Value}");
            if (!string.IsNullOrEmpty(OrderBy)) parameters.Add($"orderBy={Uri.EscapeDataString(OrderBy)}");
            if (OrderDescending.HasValue) parameters.Add($"orderDescending={OrderDescending.Value.ToString().ToLower()}");

            if (!string.IsNullOrEmpty(CardSerialNumber)) parameters.Add($"cardSerialNumber={Uri.EscapeDataString(CardSerialNumber)}");
            if (!string.IsNullOrEmpty(CertificateSerialNumber)) parameters.Add($"certificateSerialNumber={Uri.EscapeDataString(CertificateSerialNumber)}");

            if (RevocationTimeFrom.HasValue) parameters.Add($"revocationTimeFrom={Uri.EscapeDataString(RevocationTimeFrom.Value.ToString("o"))}");
            if (RevocationTimeTo.HasValue) parameters.Add($"revocationTimeTo={Uri.EscapeDataString(RevocationTimeTo.Value.ToString("o"))}");
            if (RevocationReason != null && RevocationReason.Any()) parameters.Add($"revocationReason={string.Join(",", RevocationReason)}");
            if (IsNotRevoked.HasValue) parameters.Add($"isNotRevoked={IsNotRevoked.Value.ToString().ToLower()}");

            if (!string.IsNullOrEmpty(SubjectCommonName)) parameters.Add($"subjectCommonName={Uri.EscapeDataString(SubjectCommonName)}");
            if (!string.IsNullOrEmpty(SubjectGivenName)) parameters.Add($"subjectGivenName={Uri.EscapeDataString(SubjectGivenName)}");
            if (!string.IsNullOrEmpty(SubjectSurName)) parameters.Add($"subjectSurName={Uri.EscapeDataString(SubjectSurName)}");
            if (!string.IsNullOrEmpty(SubjectOrganisationName)) parameters.Add($"subjectOrganisationName={Uri.EscapeDataString(SubjectOrganisationName)}");
            if (!string.IsNullOrEmpty(SubjectOrganisationUnit)) parameters.Add($"subjectOrganisationUnit={Uri.EscapeDataString(SubjectOrganisationUnit)}");
            if (!string.IsNullOrEmpty(SubjectSerialNumber)) parameters.Add($"subjectSerialNumber={Uri.EscapeDataString(SubjectSerialNumber)}");
            if (!string.IsNullOrEmpty(SubjectCountry)) parameters.Add($"subjectCountry={Uri.EscapeDataString(SubjectCountry)}");

            if (PublicationAllowed.HasValue) parameters.Add($"publicationAllowed={PublicationAllowed.Value.ToString().ToLower()}");
            if (PublicationTimeFrom.HasValue) parameters.Add($"publicationTimeFrom={Uri.EscapeDataString(PublicationTimeFrom.Value.ToString("o"))}");
            if (PublicationTimeTo.HasValue) parameters.Add($"publicationTimeTo={Uri.EscapeDataString(PublicationTimeTo.Value.ToString("o"))}");

            if (OcspActivationTimeFrom.HasValue) parameters.Add($"ocspActivationTimeFrom={Uri.EscapeDataString(OcspActivationTimeFrom.Value.ToString("o"))}");
            if (OcspActivationTimeTo.HasValue) parameters.Add($"ocspActivationTimeTo={Uri.EscapeDataString(OcspActivationTimeTo.Value.ToString("o"))}");

            if (ValidFromTimeFrom.HasValue) parameters.Add($"validFromTimeFrom={Uri.EscapeDataString(ValidFromTimeFrom.Value.ToString("o"))}");
            if (ValidFromTimeTo.HasValue) parameters.Add($"validFromTimeTo={Uri.EscapeDataString(ValidFromTimeTo.Value.ToString("o"))}");
            if (IsNotYetValid.HasValue) parameters.Add($"isNotYetValid={IsNotYetValid.Value.ToString().ToLower()}");
            if (ValidToTimeFrom.HasValue) parameters.Add($"validToTimeFrom={Uri.EscapeDataString(ValidToTimeFrom.Value.ToString("o"))}");
            if (ValidToTimeTo.HasValue) parameters.Add($"validToTimeTo={Uri.EscapeDataString(ValidToTimeTo.Value.ToString("o"))}");
            if (IsExpired.HasValue) parameters.Add($"isExpired={IsExpired.Value.ToString().ToLower()}");

            if (!string.IsNullOrEmpty(Field1)) parameters.Add($"field1={Uri.EscapeDataString(Field1)}");
            if (!string.IsNullOrEmpty(Field2)) parameters.Add($"field2={Uri.EscapeDataString(Field2)}");
            if (!string.IsNullOrEmpty(Field3)) parameters.Add($"field3={Uri.EscapeDataString(Field3)}");
            if (!string.IsNullOrEmpty(Field4)) parameters.Add($"field4={Uri.EscapeDataString(Field4)}");
            if (!string.IsNullOrEmpty(Field5)) parameters.Add($"field5={Uri.EscapeDataString(Field5)}");
            if (!string.IsNullOrEmpty(Field6)) parameters.Add($"field6={Uri.EscapeDataString(Field6)}");

            if (!string.IsNullOrEmpty(AuthorityKeyIdentifier)) parameters.Add($"authorityKeyIdentifier={Uri.EscapeDataString(AuthorityKeyIdentifier)}");
            if (!string.IsNullOrEmpty(SubjectKeyIdentifier)) parameters.Add($"subjectKeyIdentifier={Uri.EscapeDataString(SubjectKeyIdentifier)}");

            if (SubjectType != null && SubjectType.Any()) parameters.Add($"subjectType={string.Join(",", SubjectType)}");

            if (!string.IsNullOrEmpty(Issuer)) parameters.Add($"issuer={Uri.EscapeDataString(Issuer)}");

            return parameters.Any() ? "?" + string.Join("&", parameters) : string.Empty;
        }
    }

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

    public class CertificateBinaryResponse
    {
        /// <summary>
        /// The binary certificate data (DER, PEM, or PKCS#7 depending on Accept header)
        /// </summary>
        public byte[] CertificateData { get; set; }

        /// <summary>
        /// The CertId of the issued certificate from the response header
        /// </summary>
        public string CertId { get; set; }

        /// <summary>
        /// The content type of the response
        /// </summary>
        public string ContentType { get; set; }

        /// <summary>
        /// Indicates if this is a PKCS#7 response
        /// </summary>
        public bool IsPkcs7 => ContentType?.Contains("pkcs7") == true;

        /// <summary>
        /// Indicates if this is a PEM response
        /// </summary>
        public bool IsPem => ContentType?.Contains("pem") == true;

        /// <summary>
        /// Indicates if this is a DER response
        /// </summary>
        public bool IsDer => ContentType?.Contains("pkix-cert") == true;

        public string Base64EncodedCertificateData => Convert.ToBase64String(CertificateData);

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
