//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using RestSharp;
using System.Buffers.Text;
using System.Security.Cryptography.X509Certificates;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{

    public class NexusCertManagerClient
    {
        ILogger _logger;
        private RestClient _restClient;
        private string _host;
        private string _authCertPath;


        public NexusCertManagerClient(string hostAndPort, string authCertPath, string authCertPassword)
        {
            _logger = LogHandler.GetClassLogger(typeof(NexusCertManagerClient));
            _host = hostAndPort;
            _authCertPath = authCertPath;

            var url = _host.EndsWith(Constants.APIPATH) ? _host : _host.TrimEnd('/') + "/" + Constants.APIPATH;
            _logger.LogTrace($"full api path: {url}");

            _logger.LogTrace($"importing the client auth certificate from path {authCertPath}");

            X509Certificate2 clientCertificate;

            try
            {
                clientCertificate = new X509Certificate2(authCertPath, authCertPassword);
            }
            catch (Exception ex) {
                _logger.LogError($"there was an error attempting to load the certificate from the path {authCertPath}.  Make sure that it is stored in the PFX format and that you have provided the password.");
                _logger.LogError($"error message: {ex.Message}");
                throw;
            }

            var clientCerts = new X509CertificateCollection();
            clientCerts.Add(clientCertificate);
            var options = new RestClientOptions(url) { ClientCertificates = clientCerts };            
            _restClient = new RestClient(options);
        }

        public async Task<IssueCertificateBinaryResponse> Enroll(string csr)
        {
            _logger.MethodEntry();
            var req = new RestRequest(ApiEndpoints.ENROLL, Method.Post);
            req.AddHeader("Accept", "application/pkcs7-mime"); // Or your preferred format
            req.AddParameter("pkcs10", csr);
            _logger.LogTrace($"preparing the request for enrollment.");

            try
            {
                _logger.LogTrace($"submitting request to the endpoint '{_restClient.BuildUri(req)}'");
                var response = await _restClient.ExecuteAsync(req);
                _logger.LogTrace($"recieved a response, parsing the result");
                var result = RestSharpResponseHandler.HandleCertificateBinaryResponse(response);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to submit the CSR: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        public CertificateDetailsResponse GetCertificateDetails(string certId)
        {
            _logger.MethodEntry();
            try
            {
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to get the certificate details: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        public Task RevokeCertificate(string certId)
        {
            _logger.MethodEntry();
            try
            {
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to revoke the certificate: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        public Task<CertificateListResponse> GetCertificateList(ListCertificatesRequest req)
        {
            _logger.MethodEntry();
            try
            {
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to get a list of certificates: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }

        }

    }
}
