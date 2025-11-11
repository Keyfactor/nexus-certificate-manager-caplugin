using RestSharp;
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
        public static IssueCertificateBinaryResponse HandleCertificateBinaryResponse(RestResponse response)
        {
            // Check if response is JSON (error response)
            var contentType = response.ContentType;
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

            // Get binary data
            var binaryData = response.RawBytes;

            // Get CertId from response header
            var certIdHeader = response.Headers?.FirstOrDefault(h =>
                h.Name.Equals("certId", StringComparison.OrdinalIgnoreCase));
            string certId = certIdHeader?.Value?.ToString();

            return new IssueCertificateBinaryResponse
            {
                CertificateData = binaryData,
                CertId = certId,
                ContentType = contentType
            };
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
