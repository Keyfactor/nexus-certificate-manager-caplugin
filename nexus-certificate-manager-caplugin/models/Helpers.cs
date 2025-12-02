
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.PKI.X509;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using RestSharp;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager.models
{
    public static class Helpers
    {
        public static string ParseSubject(string subject, string rdn)
        {
            string escapedSubject = subject.Replace("\\,", "|");
            string rdnString = escapedSubject.Split(',').ToList().Where(x => x.Contains(rdn)).FirstOrDefault();

            if (!string.IsNullOrEmpty(rdnString))
            {
                return rdnString.Replace(rdn, "").Replace("|", ",").Trim();
            }
            else
            {
                throw new Exception($"The request is missing a {rdn} value");
            }
        }

        public static int GetStatusCodeFromNexusCADescription(string status)
        {
            switch (status)
            {
                case "issued":
                case "approved":
                case "expired":
                case "active":
                    return (int)EndEntityStatus.GENERATED;

                case "processing":
                case "reissue_pending":
                case "pending": // Pending from DigiCert means it will be issued after validation
                case "waiting_pickup":
                case "needs_approval":
                    return (int)EndEntityStatus.EXTERNALVALIDATION;

                case "denied":
                case "rejected":
                case "canceled":
                    return (int)EndEntityStatus.FAILED;

                case "revoked":
                    return (int)EndEntityStatus.REVOKED;
                default:
                    return (int)EndEntityStatus.NEW; // set the status to "NEW" for any unknown description; to be evaluated as neededs
            }
        }

        public static int? GetRevocationReasonCodeFromNexusCADescription(string reason)
        {
            //from the NexusCA API docs:
            //* 0: Unspecified
            //* 1: Key Compromise
            //* 3: Affiliation Changed
            //* 4: Superseded
            //* 5: Cessation Of Operation
            //* 6: Certificate Hold
            //* 9: Privilege Withdrawn

            switch (reason?.ToLower())
            {
                case "key compromise":
                    return (int)RevocationReason.KeyCompromise;
                case "affiliation changed":
                    return (int)RevocationReason.AffiliationChanged;
                case "superseded":
                    return (int)RevocationReason.Superseded;
                case "cessation of operation":
                    return (int)RevocationReason.CessationOfOperation;
                case "certificate hold":
                    return (int)RevocationReason.CertificateHold;
                case "privilege withdrawn":
                    return (int)RevocationReason.PrivilegeWithdrawn;
                default:
                    return (int)RevocationReason.Unspecified;

            }
        }

        // Helper method to extract end entity certificate from PEM chain
        public static string GetEndEntityCertificate(string certData, ILogger _logger)
        {
            var splitCerts = certData.Split(
                new[] { "-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----" },
                StringSplitOptions.RemoveEmptyEntries);

            X509Certificate2Collection col = new X509Certificate2Collection();

            foreach (var cert in splitCerts)
            {
                _logger.LogTrace($"Split Cert Value: {cert}");
                try
                {
                    // Clean the cert string and add PEM headers if needed
                    var cleanCert = cert.Trim();
                    if (!cleanCert.StartsWith("-----BEGIN CERTIFICATE-----"))
                    {
                        cleanCert = $"-----BEGIN CERTIFICATE-----\n{cleanCert}\n-----END CERTIFICATE-----";
                    }
                    col.Import(Encoding.UTF8.GetBytes(cleanCert));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Failed to import certificate segment: {ex.Message}");
                }
            }

            _logger.LogTrace("Getting End Entity Certificate");
            var currentCert = X509Utilities.ExtractEndEntityCertificateContents(ExportCollectionToPem(col), "");

            _logger.LogTrace("Converting to Byte Array");
            var byteArray = currentCert?.Export(X509ContentType.Cert);

            _logger.LogTrace("Initializing empty string");
            var certString = string.Empty;
            if (byteArray != null)
            {
                certString = Convert.ToBase64String(byteArray);
            }

            _logger.LogTrace($"Got certificate {certString}");
            return certString;
        }

        // Helper method to export X509Certificate2Collection to PEM format
        private static string ExportCollectionToPem(X509Certificate2Collection collection)
        {
            var sb = new StringBuilder();
            foreach (var cert in collection)
            {
                sb.AppendLine("-----BEGIN CERTIFICATE-----");
                sb.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                sb.AppendLine("-----END CERTIFICATE-----");
            }
            return sb.ToString();
        }
    }


    /// <summary>
    /// Helper methods for handling CM REST API responses with RestSharp
    /// </summary>
    public static class RestSharpResponseHandler
    {
        /// <summary>
        /// Pattern 1: Deserialize to specific type and check IsSuccess property
        /// This is the recommended approach for most scenarios
        /// </summary>
        public static T HandleResponse<T>(RestResponse<T> response) where T : ApiResponse
        {
            // Check HTTP status
            if (!response.IsSuccessful)
            {
                // Try to parse error from content
                if (!string.IsNullOrEmpty(response.Content))
                {
                    try
                    {
                        var errorResponse = JsonSerializer.Deserialize<ApiErrorResponse>(
                            response.Content,
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                        );

                        if (errorResponse != null && errorResponse.IsError)
                        {
                            throw new CmApiException(errorResponse.Error, errorResponse.Message);
                        }
                    }
                    catch (JsonException)
                    {
                        // Not JSON, use raw content
                        throw new CmApiException(
                            (int)response.StatusCode,
                            $"HTTP {response.StatusCode}: {response.ErrorMessage ?? response.Content}"
                        );
                    }
                }

                throw new CmApiException(
                    (int)response.StatusCode,
                    response.ErrorMessage ?? $"HTTP {response.StatusCode}"
                );
            }

            if (response.Data == null)
            {
                throw new CmApiException(-1, "Failed to deserialize response");
            }

            // Check the error code in the response body
            if (response.Data.IsError)
            {
                throw new CmApiException(response.Data.Error, response.Data.Message);
            }

            return response.Data;
        }

        /// <summary>
        /// Handles binary certificate responses (PKCS#7, DER, PEM)
        /// Use for POST /certificates/pkcs10 and similar endpoints
        /// </summary>
        public static CertificateBinaryResponse HandleCertificateBinaryResponse(RestResponse response)
        {
            // Check if response is JSON (error response)
            var contentType = response.ContentType; 
            var res = new CertificateBinaryResponse();

            if (contentType?.Contains("json") == true)
            {
                try
                {
                    var errorResponse = JsonSerializer.Deserialize<ApiErrorResponse>(
                        response.Content,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                    );

                    if (errorResponse != null && errorResponse.IsError)
                    {
                        throw new CmApiException(errorResponse.Error, errorResponse.Message);
                    }
                }
                catch (JsonException)
                {
                    // Not a valid error response, continue
                }
            }

            // Check HTTP status
            if (!response.IsSuccessful)
            {
                throw new CmApiException(
                    (int)response.StatusCode,
                    response.ErrorMessage ?? $"HTTP {response.StatusCode}"
                );
            }

            if (contentType?.Contains(Constants.PEMCHAIN) == true) {
                //the response content is the PEM cert chain, 
                res.PEMString = response.Content;
            }
            // Get binary data
            var binaryData = response.RawBytes;
            
            // Get CertId from response header
            var certIdHeader = response.Headers?.FirstOrDefault(h =>
                h.Name.Equals("certId", StringComparison.OrdinalIgnoreCase));
            string certId = certIdHeader?.Value?.ToString();

            res.CertificateData = binaryData;
            res.CertId = certId;
            res.ContentType = contentType;

            return res;
        }
    }


    /// <summary>
    /// Custom exception for CM API errors
    /// </summary>
    public class CmApiException : Exception
    {
        public int ErrorCode { get; }

        public CmApiException(int errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        /// Returns a user-friendly description of the error code
        /// </summary>
        public string GetErrorDescription()
        {
            return ErrorCode switch
            {
                0 => "Success",
                -1 => "General error",
                -7 => "Missing field",
                -8 => "Encoding error",
                -12 => "Not initialized",
                -14 => "Bad field value",
                -15 => "Privilege error",
                -17 => "Bad signature",
                -18 => "Connection error",
                -19 => "Signature required",
                -40 => "Too many requests",
                _ => "Unknown error"
            };
        }
    }


}
