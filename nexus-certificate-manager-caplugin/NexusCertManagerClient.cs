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
            catch (Exception ex)
            {
                _logger.LogError($"there was an error attempting to load the certificate from the path {authCertPath}.  Make sure that it is stored in the PFX format and that you have provided the password.");
                _logger.LogError($"error message: {ex.Message}");
                throw;
            }

            var clientCerts = new X509CertificateCollection();
            clientCerts.Add(clientCertificate);
            var options = new RestClientOptions(url) { ClientCertificates = clientCerts };
            _restClient = new RestClient(options);
        }

        public async Task<CertificateBinaryResponse> Enroll(string csr, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            var req = new RestRequest(ApiEndpoints.ENROLL, Method.Post);
            req.AddHeader("Accept", "application/pkcs7-mime"); 
            req.AddParameter("pkcs10", csr);
            _logger.LogTrace($"preparing the request for enrollment.");

            try
            {
                _logger.LogTrace($"submitting request to the endpoint '{_restClient.BuildUri(req)}'");
                var response = await _restClient.ExecuteAsync(req, ct);
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

        /// <summary>
        /// Returns detailed information about a certificate
        /// </summary>
        /// <param name="certId">The certificate ID on the Nexus Certificate Manager</param>
        /// <param name="ct"></param>
        /// <returns></returns>
        /// <exception cref="CmApiException"></exception>
        public async Task<CertificateDetailsResponse> GetCertificateDetails(string certId, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            try
            {
                var endpoint = ApiEndpoints.CERTDETAILS(certId);
                _logger.LogTrace($"performing the GET request for endpoint {endpoint}");

                var res = await _restClient.GetAsync<CertificateDetailsResponse>(endpoint, ct);
                _logger.LogTrace($"received a response; message: {res.Message}, error: {res.Error}");
                if (res.IsError) throw new CmApiException(res.Error, res.Message);
                return res;
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to get the certificate details: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        /// <summary>
        /// Downloads the contents of a certificate
        /// </summary>
        /// <param name="certId">The certificate ID on the Nexus Certificate Manager</param>
        /// <param name="format">if provided, should be one of: 
        /// "application/zip"
        /// "application/pkix-cert"
        /// "application/pkcs7-mime" (default)
        /// "application/pem-certificate-chain"
        /// "application/pem-certificate-chain;depth=<value>"        
        /// </param>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task<CertificateBinaryResponse> DownloadCertificate(string certId, string format = "application/pkcs7-mime", CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            try 
            {                
                var endpoint = ApiEndpoints.DOWNLOADCERT(certId);
                var req = new RestRequest(endpoint, Method.Get);
                req.AddHeader("Accept", format);
                
                _logger.LogTrace($"performing the GET request for endpoint {endpoint}");
                var res = await _restClient.GetAsync(req, ct);
                _logger.LogTrace($"recieved a response.  status code: {res.StatusCode}");
                var response = RestSharpResponseHandler.HandleCertificateBinaryResponse(res);
                return response;

            }
            catch (Exception ex) 
            {
                _logger.LogError($"an error occurred when attempting to download the certificate: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }

        /// <summary>
        /// Sends a request to revoke a certificate
        /// </summary>
        /// <param name="certId">The certificate ID on the Nexus Certificate Manager</param>
        /// <param name="reason">The reason code</param>
        /// <param name="ct">Cancellation Token</param>        
        public async Task RevokeCertificate(string certId, int reason, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            try
            {
                var endpoint = ApiEndpoints.REVOKE;

                var body = new RevokeCertificateRequest() { CertId = new List<string> { certId }, Reason = reason };
                var req = new RestRequest(endpoint, Method.Post);
                req.AddJsonBody(body);
                
                _logger.LogTrace($"sending a request to {endpoint} to revoke certificate with ID {certId} and reason code {reason}");
                var res = await _restClient.PostAsync<ApiResponse>(req, ct);
                _logger.LogTrace($"response: {res.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to revoke the certificate: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }
        }
        /// <summary>
        /// Returns a list of certificates
        /// </summary>
        /// <param name="req"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task<CertificateListResponse> GetCertificateList(ListCertificatesRequest req, CancellationToken ct)
        {
            _logger.MethodEntry();
            try
            {
                var endpoint = ApiEndpoints.LISTCERTS;
                _logger.LogTrace($"performing the GET request for endpoint {endpoint}");
                var res = await _restClient.GetAsync<CertificateListResponse>(endpoint, ct);
                _logger.LogTrace($"received a response.  Number of certs returned:  {res.SearchHits}");
                return res;
            }
            catch (Exception ex)
            {
                _logger.LogError($"an error occurred when attempting to get a list of certificates: {ex.Message}");
                throw;
            }
            finally { _logger.MethodExit(); }

        }
        /// <summary>
        /// This method calls the "/procedures" endpoint of the API
        /// The ping is successful if the server returns "200".  
        /// The content of the response is ignored
        /// </summary>
        /// <returns>A boolean indicating whether the server is reachable and responding.</returns>
        public async Task<Boolean> PingServer() {
            _logger.MethodEntry();
            try {
                var endpoint = ApiEndpoints.LISTPROCEDURES;
                _logger.LogTrace($"pinging the endpoint {endpoint} to verify server is accessible");
                var req = new RestRequest(endpoint);
                var res = await _restClient.GetAsync(req);
                if (res.IsSuccessStatusCode) return true;
            }
            catch (Exception ex) {
                _logger.LogError($"the attempt to ping the server failed: {ex.Message}");                
            }
            finally { _logger.MethodExit(); }
            return false;
        }

    }
}
