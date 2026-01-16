
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Newtonsoft.Json;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Threading;
using System.IO;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public class NexusCertManagerCAPlugin : IAnyCAPlugin
    {
        private readonly ILogger _logger;
        private NexusCertManagerCAPluginConfig _config;
        private ICertificateDataReader _certificateDataReader;
        private NexusCertManagerClient _client;

        public NexusCertManagerCAPlugin(ILogger<NexusCertManagerCAPlugin> logger)
        {
            _logger = logger;
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            LogPluginVersion();

            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            _logger.LogTrace($"serialized configuration values: \n{rawConfig}\n");
            _config = JsonConvert.DeserializeObject<NexusCertManagerCAPluginConfig>(rawConfig);
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
                var res = await _client.Enroll(csr);

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
                    Comments = "The path to the Nexus CM server, including port",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.AUTHCERTPATH] = new PropertyConfigInfo
                {
                    Comments = "The path to the PFX certificate for authenticating into Nexus CM",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.AUTHCERTPASSWORD] = new PropertyConfigInfo
                {
                    Comments = "The password for the authentication certificate",
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
                }
            };
        }


        /// <summary>
        /// this CA is does not split it's certificates into discernable "product types"
        /// consequently, we are using a single product type for all certificates.
        /// </summary>
        /// <returns>A list of strings containing one element: "NexusCA"</returns>
        public List<string> GetProductIds()
        {
            _logger.MethodEntry();
            return new List<string> { Constants.PRODUCTID };
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            _logger.MethodEntry();
            try
            {
                _logger.LogTrace($"getting certificate details for certId: {caRequestID}");
                var certDetails = await _client.GetCertificateDetails(caRequestID);

                _logger.LogTrace($"download certificate with ID: {caRequestID}");
                var certContent = await _client.DownloadCertificate(caRequestID);

                var cert = new AnyCAPluginCertificate()
                {
                    CARequestID = caRequestID,
                    Certificate = certContent.Base64EncodedCertificateData,
                    ProductID = certDetails.Certificate.CertId,
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
        /// Synchronize gets the list of certs from the CA and updates the status of each known cert to the latest, and adds missing cert info to the database.
        /// </summary>
        /// <param name="blockingBuffer">the database reader, passed by framework</param>
        /// <param name="lastSync">the time of last sync</param>
        /// <param name="fullSync">whether or not to perform a full sync</param>
        /// <param name="cancelToken">the cancel token</param>
        /// <returns></returns>
        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            _logger.MethodEntry();
            var updatedCerts = new List<AnyCAPluginCertificate>();

            try
            {
                // retreive the list of certs from Nexus CM
                _logger.LogTrace("attempting to retrieve the list of cert names from Nexus CM");
                var certList = await _client.GetCertificateList(null, cancelToken);
                _logger.LogTrace($"successfully returned {certList.SearchHits} results.");

                certList.Certificates.ForEach(cert =>
                {
                    _logger.LogTrace("- cert details - ");
                    _logger.LogTrace($"certId: {cert.CertId}");
                    _logger.LogTrace($"status: {cert.Status}");
                    _logger.LogTrace($"revocation time: {cert.RevocationTime}");
                    _logger.LogTrace($"serial number: {cert.CertificateSerialNumber}");
                    _logger.LogTrace($"reason: {cert.Reason}");

                    var updatedCert = new AnyCAPluginCertificate
                    {
                        CARequestID = cert.CertId,
                        ProductID = Constants.PRODUCTID,
                        Status = Helpers.GetStatusCodeFromNexusCADescription(cert.Status),
                        RevocationDate = cert.RevocationTime,
                        
                    };
                    if (!string.IsNullOrEmpty(cert.Reason)) {
                        updatedCert.RevocationReason = Helpers.GetRevocationReasonCodeFromNexusCADescription(cert.Reason);
                    }

                    updatedCerts.Add(updatedCert);
                });

                // now get the cert content for each.. 
                _logger.LogTrace($"getting certificate content for each..");

                foreach (var cert in updatedCerts)
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        _logger.LogInformation("Nexus CA sync cancelled.");
                        cancelToken.ThrowIfCancellationRequested();
                    }
                    var certContent = await _client.DownloadCertificate(cert.CARequestID, Constants.PEMCHAIN, cancelToken);
                    _logger.LogTrace("getting the leaf certificate");
                    cert.Certificate = Helpers.GetEndEntityCertificate(certContent.Base64EncodedCertificateData, _logger);
                    _logger.LogTrace($"leaf cert: {cert.Certificate}");
                }

                _logger.LogTrace($"got the content for {updatedCerts.Count} certs");
                _logger.LogTrace($"updating the database..");
                
                foreach (var cert in updatedCerts)
                {
                    _logger.LogTrace($"adding cert with id: {cert.CARequestID} and productID {cert.ProductID}");
                    blockingBuffer.Add(cert, cancelToken);
                }

                _logger.LogTrace($"successfully synced {updatedCerts.Count}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred during the sync: {ex.Message}");
                _logger.LogError($"{LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                _logger.LogTrace("successfully completed CA sync for Nexus CM");
                _logger.MethodExit();
            }
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
                    var clientCertificate = new X509Certificate2(certPath, certPassword);

                    var pub = clientCertificate.GetPublicKey();
                    var pubString = Convert.ToBase64String(pub);
                    _logger.LogTrace($"was able to successfully read the cert with the provided password.  public key: {pubString}");
                }
                catch (Exception ex)
                {
                    errors.Add($"unable to open the certificate with the provided password: {LogHandler.FlattenException(ex)}");
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
                var valid = Uri.TryCreate((string)connectionInfo[Constants.HOST], UriKind.Absolute, out var newUri);
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
        /// Since we are using a single productId, there is nothing to validate
        /// </summary>
        /// <param name="productInfo"></param>
        /// <param name="connectionInfo"></param>
        /// <returns>Task.CompletedTask</returns>
        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {            
            return Task.CompletedTask;
        }
    }
}
