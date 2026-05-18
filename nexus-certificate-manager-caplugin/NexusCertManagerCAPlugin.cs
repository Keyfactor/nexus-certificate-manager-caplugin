
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public class NexusCertManagerCAPlugin : IAnyCAPlugin
    {
        private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };

        private readonly ILogger _logger;
        private NexusCertManagerCAPluginConfig _config;
        private ICertificateDataReader _certificateDataReader;
        private INexusCertManagerClient _client;

        public NexusCertManagerCAPlugin(ILogger<NexusCertManagerCAPlugin> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Internal constructor used by unit tests to inject mock dependencies
        /// without requiring a live Nexus CA or a PFX certificate on disk.
        /// </summary>
        internal NexusCertManagerCAPlugin(
            ILogger<NexusCertManagerCAPlugin> logger,
            INexusCertManagerClient client,
            ICertificateDataReader certificateDataReader,
            NexusCertManagerCAPluginConfig config)
        {
            _logger = logger;
            _client = client;
            _certificateDataReader = certificateDataReader;
            _config = config;
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            LogPluginVersion();

            string rawConfig = JsonSerializer.Serialize(configProvider.CAConnectionData);
            _logger.LogTrace($"serialized configuration values: \n{rawConfig}\n");
            _config = JsonSerializer.Deserialize<NexusCertManagerCAPluginConfig>(rawConfig, _jsonOptions);
            _logger.LogTrace($"deserialized the configuration:\nAuthCertPath: {_config.AuthCertificatePath}\nHost: {_config.Host}\nAuthCertPassword: {_config.AuthCertPassword}");
            _client = new NexusCertManagerClient(_config.Host, _config.AuthCertificatePath, _config.AuthCertPassword); // need to set the values            
            _certificateDataReader = certificateDataReader;
        }

        private void LogPluginVersion()
        {
            var targetAssembly = typeof(NexusCertManagerCAPlugin).Assembly;
            var assemblyName = targetAssembly?.GetName();
            var version = assemblyName?.Version;
            _logger.LogTrace("Keyfactor CA Gateway Plugin for Nexus Certificate Manager");
            _logger.LogTrace($"{assemblyName?.Name ?? "unknown"} v{version}");
        }

        /// <summary>
        /// Enroll a certificate with the CA
        /// </summary>
        /// <param name="csr">The CSR for the certificate request</param>
        /// <param name="subject">The subject string</param>
        /// <param name="san">The list of SANs</param>
        /// <param name="productInfo">Collection of product information and options. Includes both product-level config options as well as custom enrollment fields.</param>
        /// <param name="requestFormat">The format of the request</param>
        /// <param name="enrollmentType">The type of enrollment (new, renew, reissue)</param>
        /// <returns></returns>
        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();
            string sans = string.Join(";", san.Select(s => string.Format("{0}:{1}", s.Key, string.Join(",", s.Value))));
            string paramsList = string.Join(";", productInfo.ProductParameters.Select(x => string.Format("{0}={1}", x.Key, x.Value)));
            string commonName = Helpers.ParseSubject(subject, "CN=");

            _logger.LogTrace($"Attempting to enroll for certificate with:\nSubject: {subject}\nSANs: {sans}\nParams: {paramsList}\nCSR: {csr}");
            try
            {
                var res = await _client.Enroll(csr, productInfo.ProductID);

                var enrollmentResult = new EnrollmentResult
                {
                    CARequestID = res.CertId,
                    Certificate = res.Base64EncodedCertificateData,
                    Status = (int)EndEntityStatus.GENERATED,
                    StatusMessage = $"Successfully enrolled certificate {commonName}"
                };
                return enrollmentResult;
            }
            catch (Exception ex)
            {
                _logger.LogError($"there was an error enrolling the certificate: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Get the annotations for the CA Connector-level configuration fields
        /// </summary>
        /// <returns>A dictionary of the details for each property</returns>
        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            _logger.MethodEntry();

            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.HOST] = new PropertyConfigInfo
                {
                    Comments = "The URI of the Nexus Certificate Manager API, including port. Example: https://192.168.1.10:8444",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.AUTHCERTPATH] = new PropertyConfigInfo
                {
                    Comments = "The full path on the AnyCA Gateway host to the PFX certificate used for authenticating into Nexus Certificate Manager.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.AUTHCERTPASSWORD] = new PropertyConfigInfo
                {
                    Comments = "The password for the PFX authentication certificate.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.ENABLED] = new PropertyConfigInfo()
                {
                    Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                },
                [Constants.SYNC_PROCEDURE_FIELD] = new PropertyConfigInfo
                {
                    Comments = "Optional. Enables certificate synchronization. Set this to the name of the Nexus CA ExtendedCertSearch field (e.g. \"field1\") " +
                               "that your CA administrator has configured to store the issuing procedure name at enrollment time. " +
                               "When provided, Synchronize will read that field from each certificate to reconstruct its ProductID (procedure name). " +
                               "When omitted, Synchronize is disabled because the Nexus CA API does not natively return the issuing procedure with certificate records. " +
                               "NOTE: Configuring the Nexus CA to populate this field requires custom Java InputView development and AWB policy changes by a CA administrator. " +
                               "This configuration is outside the scope of Keyfactor support.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                }
            };
        }


        /// <summary>
        /// Product ID's correspond to 'procedures' in the Nexus Certificate Manager        
        /// </summary>
        /// <returns>A list of procedure identifiers to use as the product ID's</returns>
        public List<string> GetProductIds()
        {
            _logger.MethodEntry();
            var productIds = new List<string>();
            try
            {
                productIds = _client.GetProceduresByMediaType().GetAwaiter().GetResult();
                _logger.LogTrace($"successfully retrieved {productIds.Count} procedure names");
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred when attempting to retrieve the procedure names: {LogHandler.FlattenException(ex)}");
            }
            finally
            {
                _logger.MethodExit();
            }
            return productIds;
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            _logger.MethodEntry();
            try
            {
                _logger.LogTrace($"getting certificate details for certId: {caRequestID}");
                var certDetails = await _client.GetCertificateDetails(caRequestID);

                _logger.LogTrace($"downloading certificate with ID: {caRequestID}");
                var certContent = await _client.DownloadCertificate(caRequestID);

                // Resolve ProductID from the configured ExtendedCertSearch field if available;
                // otherwise leave null so the Gateway framework handles the unresolvable case.
                string productId = ResolveProductIdFromExtendedSearch(certDetails.Certificate.ExtendedCertSearch);
                if (productId == null)
                    _logger.LogWarning($"Unable to resolve ProductID for cert {caRequestID}: SyncProcedureField is not configured or the field was empty.");

                var cert = new AnyCAPluginCertificate()
                {
                    CARequestID = caRequestID,
                    Certificate = certContent.Base64EncodedCertificateData,
                    ProductID = productId,
                    Status = Helpers.GetStatusCodeFromNexusCADescription(certDetails.Certificate.Status),
                };
                if (cert.Status == (int)EndEntityStatus.REVOKED)
                {
                    cert.RevocationDate = certDetails.Certificate.RevocationTime;
                    cert.RevocationReason = Helpers.GetRevocationReasonCodeFromNexusCADescription(certDetails.Certificate.Reason);
                }
                return cert;
            }
            catch (Exception ex)
            {
                _logger.LogError($"there was an error getting the certificate: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }


        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>(); // there are no template specific parameters for this CA Plugin
        }

        /// <summary>
        /// Sends an arbitrary request to the Nexus CA server to ensure that it is reachable
        /// </summary>
        /// <returns></returns>
        public async Task Ping()
        {
            _logger.MethodEntry();

            try
            {
                _logger.LogTrace($"attempting to ping the Nexus CM server at {_config.Host}");
                var res = await _client.PingServer();
            }
            catch (Exception ex)
            {
                _logger.LogError($"the attempt to ping the server failed: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        /// <summary>
        /// Revokes a certificate
        /// </summary>
        /// <param name="caRequestID"></param>
        /// <param name="hexSerialNumber"></param>
        /// <param name="revocationReason"></param>
        /// <returns>An integer representing the updated certificate status</returns>
        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            _logger.MethodEntry();
            try
            {
                _logger.LogTrace($"attempting to revoke certificate with id {caRequestID} and serial number {hexSerialNumber} with reason code {revocationReason}");
                await _client.RevokeCertificate(caRequestID, (int)revocationReason);
                _logger.LogTrace("successfully revoked certificate");
                return (int)EndEntityStatus.REVOKED;
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to revoke certificate with id {caRequestID}");
                _logger.LogError(LogHandler.FlattenException(ex));
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        /// <summary>
        /// Synchronizes certificates from the Nexus CA into Command.
        /// <para>
        /// Synchronization requires the <c>SyncProcedureField</c> CA connection parameter to be configured.
        /// When not configured, this method throws <see cref="NotSupportedException"/> with an explanation.
        /// See the plugin documentation for guidance on enabling sync.
        /// </para>
        /// </summary>
        /// <param name="blockingBuffer">Certificate buffer provided by the Gateway framework.</param>
        /// <param name="lastSync">The time of the last sync operation.</param>
        /// <param name="fullSync">Whether to perform a full sync regardless of last-sync time.</param>
        /// <param name="cancelToken">Cancellation token.</param>
        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            _logger.MethodEntry();

            if (string.IsNullOrWhiteSpace(_config.SyncProcedureField))
            {
                throw new NotSupportedException(
                    "Certificate synchronization is not supported by the Nexus Certificate Manager CA Plugin unless the " +
                    "'SyncProcedureField' CA connection parameter is configured. " +
                    "The Nexus CA REST API does not return the issuing procedure name in certificate list or detail responses, " +
                    "making it impossible to associate synced certificates with their originating ProductID (procedure). " +
                    "To enable sync, a Nexus CA administrator must configure a token procedure to populate one of the " +
                    "ExtendedCertSearch fields (field1-field6) with the procedure name at enrollment time, then set " +
                    "'SyncProcedureField' on this CA connection to the name of that field (e.g. 'field1'). " +
                    "See the plugin documentation for full details. Note: this CA-side configuration requires custom " +
                    "Java InputView development and is outside the scope of Keyfactor support.");
            }

            _logger.LogTrace($"Sync is enabled. Resolving ProductID from ExtendedCertSearch field: '{_config.SyncProcedureField}'");

            var updatedCerts = new List<AnyCAPluginCertificate>();
            int offset = 0;
            int totalHits = 0;
            int pageCount = 0;

            try
            {
                // paginated fetch loop
                do
                {
                    cancelToken.ThrowIfCancellationRequested();

                    _logger.LogTrace($"Fetching certificate page: offset={offset}, pageSize={Constants.SYNC_PAGE_SIZE}");
                    var page = await _client.GetCertificateList(new ListCertificatesRequest
                    {
                        SearchLimit = Constants.SYNC_PAGE_SIZE,
                        SearchOffset = offset
                    }, cancelToken);

                    if (pageCount == 0)
                    {
                        totalHits = page.SearchHits;
                        _logger.LogTrace($"Total certificates reported by Nexus CA: {totalHits}");
                    }

                    var certs = page.Certificates ?? new List<JsonCertificate>();
                    _logger.LogTrace($"Page returned {certs.Count} certificates");

                    foreach (var cert in certs)
                    {
                        var productId = ResolveProductIdFromExtendedSearch(cert.ExtendedCertSearch);
                        if (productId == null)
                        {
                            _logger.LogWarning($"Cert {cert.CertId}: ExtendedCertSearch field '{_config.SyncProcedureField}' was empty or missing. " +
                                               $"This certificate will be skipped during sync.");
                            continue;
                        }

                        var updatedCert = new AnyCAPluginCertificate
                        {
                            CARequestID = cert.CertId,
                            ProductID = productId,
                            Status = Helpers.GetStatusCodeFromNexusCADescription(cert.Status),
                            RevocationDate = cert.RevocationTime,
                        };

                        if (!string.IsNullOrEmpty(cert.Reason))
                            updatedCert.RevocationReason = Helpers.GetRevocationReasonCodeFromNexusCADescription(cert.Reason);

                        // check for an existing local entry
                        var dbStatus = -1;
                        try
                        {
                            dbStatus = await _certificateDataReader.GetStatusByRequestID(cert.CertId);
                        }
                        catch
                        {
                            _logger.LogTrace($"Cert {cert.CertId} not found in local database — will be added.");
                        }

                        if (dbStatus == -1 || fullSync || updatedCert.Status != dbStatus)
                            updatedCerts.Add(updatedCert);
                    }

                    offset += certs.Count;
                    pageCount++;

                } while (offset < totalHits);

                _logger.LogTrace($"Pagination complete. {pageCount} page(s) fetched. {updatedCerts.Count} certificates queued for update.");

                // download certificate content for each cert that needs updating
                foreach (var cert in updatedCerts)
                {
                    cancelToken.ThrowIfCancellationRequested();

                    _logger.LogTrace($"Downloading certificate content for certId: {cert.CARequestID}");
                    var certContent = await _client.DownloadCertificate(cert.CARequestID, Constants.PEMCHAIN, cancelToken);
                    cert.Certificate = Helpers.GetEndEntityCertificate(certContent.Base64EncodedCertificateData, _logger);
                }

                _logger.LogTrace($"Writing {updatedCerts.Count} certificates to the buffer.");
                foreach (var cert in updatedCerts)
                {
                    _logger.LogTrace($"Buffering cert id={cert.CARequestID}, productId={cert.ProductID}");
                    blockingBuffer.Add(cert, cancelToken);
                }

                _logger.LogInformation($"Nexus CA sync complete. {updatedCerts.Count} certificate(s) synchronized.");
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Nexus CA sync was cancelled.");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred during sync: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        /// <summary>
        /// Reads the ProductID (procedure name) from the configured ExtendedCertSearch field on a certificate.
        /// Returns null if <c>SyncProcedureField</c> is not configured or the field value is empty.
        /// </summary>
        private string ResolveProductIdFromExtendedSearch(ExtendedCertSearch extendedCertSearch)
        {
            if (string.IsNullOrWhiteSpace(_config.SyncProcedureField) || extendedCertSearch == null)
                return null;

            var fieldName = _config.SyncProcedureField.Trim().ToLowerInvariant();
            var value = fieldName switch
            {
                "field1" => extendedCertSearch.Field1,
                "field2" => extendedCertSearch.Field2,
                "field3" => extendedCertSearch.Field3,
                "field4" => extendedCertSearch.Field4,
                "field5" => extendedCertSearch.Field5,
                "field6" => extendedCertSearch.Field6,
                _ => null
            };

            if (value == null)
                _logger.LogWarning($"SyncProcedureField '{_config.SyncProcedureField}' is not a recognised ExtendedCertSearch field name. Valid values are: field1, field2, field3, field4, field5, field6.");

            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry();
            var errors = new List<string>();

            if (!(bool)connectionInfo[Constants.ENABLED])
            {
                _logger.LogWarning($"The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping validation...");
                return;
            }

            // cert path
            _logger.LogTrace("validating auth cert path..");
            if (string.IsNullOrEmpty((string)connectionInfo[Constants.AUTHCERTPATH]))
            {
                errors.Add($"{Constants.AUTHCERTPATH} is missing or empty");
            }
            else
            {
                try
                {
                    // see if we can open the file for reading..
                    using (var _ = new FileStream((string)connectionInfo[Constants.AUTHCERTPATH], FileMode.Open, FileAccess.Read))
                    {
                        // if we get this far, we can
                        _logger.LogTrace($"successfully read the file at path {connectionInfo[Constants.AUTHCERTPATH]}");
                    }
                }
                catch (FileNotFoundException)
                {
                    errors.Add($"unable to find the certificate for authenticating at the path {connectionInfo[Constants.AUTHCERTPATH]}");
                }
                catch (UnauthorizedAccessException)
                {
                    errors.Add($"the file exists at {connectionInfo[Constants.AUTHCERTPATH]}, but it is inaccessible due to insufficient permissions.");
                }
            }

            // cert password

            // validate that it exists
            if (string.IsNullOrEmpty((string)connectionInfo[Constants.AUTHCERTPASSWORD]))
            {
                errors.Add("no password was provided for the authentication certificate");
            }
            else
            {
                try
                {
                    var certPath = (string)connectionInfo[Constants.AUTHCERTPATH];
                    var certPassword = (string)connectionInfo[Constants.AUTHCERTPASSWORD];

                    // validate that it works
                    using (var clientCertificate = new X509Certificate2(certPath, certPassword))
                    {
                        var pub = clientCertificate.GetPublicKey();
                        var pubString = Convert.ToBase64String(pub);
                        _logger.LogTrace($"was able to successfully read the cert with the provided password.  public key: {pubString}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogTrace($"unable to open the certificate with the provided password: {LogHandler.FlattenException(ex)}");
                    errors.Add("unable to open the certificate with the provided password");
                }
            }

            // host

            // validate that there is a value

            if (string.IsNullOrEmpty((string)connectionInfo[Constants.HOST]))
            {
                errors.Add("the host url for the instance of the Nexus Certificate Manager is required.");
            }
            else
            {
                // validate that it is a valid url
                var valid = Uri.TryCreate((string)connectionInfo[Constants.HOST], UriKind.Absolute, out _);
                if (!valid)
                {
                    errors.Add($"the host URL {connectionInfo[Constants.HOST]} could not be parsed as a valid URL");
                }
            }

            // perform the final validation of calling an authenticated endpoint, if the values are present and seem valid
            if (!errors.Any())
            {

                var host = (string)connectionInfo[Constants.HOST];
                var certPath = (string)connectionInfo[Constants.AUTHCERTPATH];
                var certPassword = (string)connectionInfo[Constants.AUTHCERTPASSWORD];

                try
                {
                    _client = new NexusCertManagerClient(host, certPath, certPassword);

                    await _client.PingServer();
                }
                catch (Exception ex)
                {
                    errors.Add($"unable to make an authenticated request with the provided information: {LogHandler.FlattenException(ex)}");
                }
            }

            if (errors.Any())
            {
                var validationMsg = $"Validation errors:\n{string.Join("\n", errors)}";
                throw new AnyCAValidationException(validationMsg);
            }
            else
            {
                _logger.LogTrace("CA Connector configuration passed all validation checks");
            }
        }

        /// <summary>
        /// Validates that the ProductID on the enrollment request is a non-empty string.
        /// ProductIDs correspond to Nexus CA procedure names; an empty value would cause
        /// enrollment to fall back to the server-side default procedure, which is rarely intended.
        /// </summary>
        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            if (string.IsNullOrWhiteSpace(productInfo?.ProductID))
                throw new AnyCAValidationException("ProductID (procedure name) must not be empty. Ensure the certificate template is configured with a valid Nexus CA procedure name.");

            return Task.CompletedTask;
        }
    }
}
