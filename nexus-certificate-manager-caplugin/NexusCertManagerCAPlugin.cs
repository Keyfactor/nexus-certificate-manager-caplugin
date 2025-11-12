
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
            _certificateDataReader = certificateDataReader;
            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            _config = JsonConvert.DeserializeObject<NexusCertManagerCAPluginConfig>(rawConfig);

            _client = new NexusCertManagerClient(_config.Host, _config.AuthCertPath, _config.AuthCertPassword); // need to set the values            
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

        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            throw new NotImplementedException();
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
                var certDetails = await _client.GetCertificateDetails(caRequestID);
                var certContent = await _client.DownloadCertificate(caRequestID);

                var cert = new AnyCAPluginCertificate()
                {
                    CARequestID = caRequestID,
                    Certificate = certContent.Base64EncodedCertificateData,
                    ProductID = certDetails.Certificate.CertId,                    
                    Status = Helpers.GetStatusCodeFromNexusCADescription(certDetails.Certificate.Status),                    
                };
                if (cert.Status == (int)EndEntityStatus.REVOKED) {
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
            throw new NotImplementedException();
        }

        public Task Ping()
        {
            throw new NotImplementedException();
        }

        public Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Synchronize gets the list of certs from the CA and updates the status of each known cert to the latest; and adds missing cert info to the database        /// 
        /// </summary>
        /// <param name="blockingBuffer">the database reader, passed by framework</param>
        /// <param name="lastSync">the time of last sync</param>
        /// <param name="fullSync">whether or not to perform a full sync</param>
        /// <param name="cancelToken">the cancel token</param>
        /// <returns></returns>
        public Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            _logger.MethodEntry();

            try
            {
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred during the sync: {ex.Message}");
                throw;
            }
            finally
            {
                _logger.MethodExit();
            }
        }

        public Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }
    }
}
