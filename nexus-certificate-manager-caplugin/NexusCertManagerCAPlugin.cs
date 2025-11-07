
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Collections.Concurrent;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public class NexusCertManagerCAPlugin : IAnyCAPlugin
    {
        private readonly ILogger _logger;
        private NexusCertManagerCAPluginConfig _config;
        private ICertificateDataReader _certificateDataReader;

        public NexusCertManagerCAPlugin(ILogger<NexusCertManagerCAPlugin> logger)
        {
            _logger = logger;
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _certificateDataReader = certificateDataReader;
            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            _config = JsonConvert.DeserializeObject<NexusCertManagerCAPluginConfig>(rawConfig);
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
        public Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();
            string sans = string.Join(";", san.Select(s => string.Format("{0}:{1}", s.Key, string.Join(",", s.Value))));
            string paramsList = string.Join(";", productInfo.ProductParameters.Select(x => string.Format("{0}={1}", x.Key, x.Value)));
            _logger.LogTrace($"Attempting to enroll for certificate with:\nSubject: {subject}\nSANs: {sans}\nParams: {paramsList}\nCSR: {csr}");


        }

        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            throw new NotImplementedException();
        }

        public List<string> GetProductIds()
        {
            throw new NotImplementedException();
        }

        public Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            throw new NotImplementedException();
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

        public Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            throw new NotImplementedException();
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
