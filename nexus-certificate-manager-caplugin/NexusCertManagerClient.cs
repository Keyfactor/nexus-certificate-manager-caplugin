
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using RestSharp;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public class NexusCertManagerClient : INexusCertManagerClient
    {
        private readonly ILogger _logger;
        private RestClient _restClient;
        private string _host;
        private string _authCertPath;

        public NexusCertManagerClient(string hostAndPort, string authCertPath, string authCertPassword)
        {
            _logger = LogHandler.GetClassLogger(typeof(NexusCertManagerClient));
            _host = hostAndPort;
            _logger.LogTrace($"about to clean up the file path: {authCertPath}");
            _authCertPath = authCertPath.Replace(@"\\", @"\"); // remove the double encoded slashes
            _logger.LogTrace($"clean cert path: {_authCertPath}");

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
            
            var options = new RestClientOptions(url) { ClientCertificates = clientCerts, RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true };           
            _restClient = new RestClient(options);
        }


        public async Task<CertificateBinaryResponse> Enroll(string csr, string procName, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            _logger.LogTrace($"preparing the request for enrollment.");

            var req = new RestRequest(ApiEndpoints.ENROLL, Method.Post);
            req.AddHeader("Accept", Constants.PEMCHAIN);
            req.AddParameter("pkcs10", csr);
            req.AddParameter("procname", procName);

            _logger.LogTrace($"using the provided procedure name (product ID) of {procName}");                        

            try
            {
                _logger.LogTrace($"submitting request to the endpoint '{_restClient.BuildUri(req)}'");
                var response = await _restClient.ExecuteAsync(req, ct);
                _logger.LogTrace($"response status code: {response.StatusCode}");
                _logger.LogTrace($"response content: {response.Content}");
                _logger.LogTrace($"received a response, parsing the result");
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
        public async Task<CertificateBinaryResponse> DownloadCertificate(string certId, string format = Constants.PEMCHAIN, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            try
            {
                var endpoint = ApiEndpoints.DOWNLOADCERT(certId);
                var req = new RestRequest(endpoint, Method.Get);
                req.AddHeader("Accept", format);
                _logger.LogTrace($"accept header: {format}");
                _logger.LogTrace($"performing the GET request for endpoint {endpoint}");
                var res = await _restClient.GetAsync(req, ct);
                _logger.LogTrace($"recieved a response.  status code: {res.StatusCode}");
                _logger.LogTrace($"content: {res.Content}");

                var response = RestSharpResponseHandler.HandleCertificateBinaryResponse(res);
                _logger.LogTrace($"parsed content: {response.Base64EncodedCertificateData}");
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
                                
                var req = new RestRequest(endpoint, Method.Post);
                req.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                req.AddParameter("certId", certId);
                req.AddParameter("reason", reason);

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
        /// Returns one page of certificates matching the provided search parameters.
        /// Use <see cref="ListCertificatesRequest.SearchLimit"/> and
        /// <see cref="ListCertificatesRequest.SearchOffset"/> for pagination.
        /// The total result count is available on the returned <see cref="CertificateListResponse.SearchHits"/>.
        /// </summary>
        /// <param name="req">Optional search / pagination parameters.</param>
        /// <param name="ct"></param>
        /// <returns></returns>
        public async Task<CertificateListResponse> GetCertificateList(ListCertificatesRequest req = null, CancellationToken ct = new CancellationToken())
        {
            _logger.MethodEntry();
            try
            {
                var restReq = new RestRequest(ApiEndpoints.LISTCERTS, Method.Get);

                if (req != null)
                {
                    if (req.SearchLimit.HasValue)        restReq.AddQueryParameter("searchLimit",        req.SearchLimit.Value.ToString());
                    if (req.SearchOffset.HasValue)       restReq.AddQueryParameter("searchOffset",       req.SearchOffset.Value.ToString());
                    if (!string.IsNullOrEmpty(req.OrderBy)) restReq.AddQueryParameter("orderBy",          req.OrderBy);
                    if (req.OrderDescending.HasValue)    restReq.AddQueryParameter("orderDescending",    req.OrderDescending.Value.ToString().ToLower());
                    if (req.IsNotRevoked.HasValue)       restReq.AddQueryParameter("isNotRevoked",       req.IsNotRevoked.Value.ToString().ToLower());
                    if (req.IsExpired.HasValue)          restReq.AddQueryParameter("isExpired",          req.IsExpired.Value.ToString().ToLower());
                    if (req.IsNotYetValid.HasValue)      restReq.AddQueryParameter("isNotYetValid",      req.IsNotYetValid.Value.ToString().ToLower());
                    if (!string.IsNullOrEmpty(req.Field1)) restReq.AddQueryParameter("field1",           req.Field1);
                    if (!string.IsNullOrEmpty(req.Field2)) restReq.AddQueryParameter("field2",           req.Field2);
                    if (!string.IsNullOrEmpty(req.Field3)) restReq.AddQueryParameter("field3",           req.Field3);
                    if (!string.IsNullOrEmpty(req.Field4)) restReq.AddQueryParameter("field4",           req.Field4);
                    if (!string.IsNullOrEmpty(req.Field5)) restReq.AddQueryParameter("field5",           req.Field5);
                    if (!string.IsNullOrEmpty(req.Field6)) restReq.AddQueryParameter("field6",           req.Field6);
                    if (!string.IsNullOrEmpty(req.SubjectCommonName))      restReq.AddQueryParameter("subjectCommonName",      req.SubjectCommonName);
                    if (!string.IsNullOrEmpty(req.CertificateSerialNumber)) restReq.AddQueryParameter("certificateSerialNumber", req.CertificateSerialNumber);
                    if (!string.IsNullOrEmpty(req.Issuer)) restReq.AddQueryParameter("issuer",           req.Issuer);
                    if (!string.IsNullOrEmpty(req.AuthorityKeyIdentifier)) restReq.AddQueryParameter("authorityKeyIdentifier", req.AuthorityKeyIdentifier);
                    if (!string.IsNullOrEmpty(req.SubjectKeyIdentifier))   restReq.AddQueryParameter("subjectKeyIdentifier",   req.SubjectKeyIdentifier);
                    if (req.SubjectType != null && req.SubjectType.Count > 0)
                        restReq.AddQueryParameter("subjectType", string.Join(",", req.SubjectType));
                    if (req.RevocationReason != null && req.RevocationReason.Count > 0)
                        restReq.AddQueryParameter("revocationReason", string.Join(",", req.RevocationReason));
                    if (req.RevocationTimeFrom.HasValue)  restReq.AddQueryParameter("revocationTimeFrom",  req.RevocationTimeFrom.Value.ToString("o"));
                    if (req.RevocationTimeTo.HasValue)    restReq.AddQueryParameter("revocationTimeTo",    req.RevocationTimeTo.Value.ToString("o"));
                    if (req.ValidFromTimeFrom.HasValue)   restReq.AddQueryParameter("validFromTimeFrom",   req.ValidFromTimeFrom.Value.ToString("o"));
                    if (req.ValidFromTimeTo.HasValue)     restReq.AddQueryParameter("validFromTimeTo",     req.ValidFromTimeTo.Value.ToString("o"));
                    if (req.ValidToTimeFrom.HasValue)     restReq.AddQueryParameter("validToTimeFrom",     req.ValidToTimeFrom.Value.ToString("o"));
                    if (req.ValidToTimeTo.HasValue)       restReq.AddQueryParameter("validToTimeTo",       req.ValidToTimeTo.Value.ToString("o"));
                }

                _logger.LogTrace($"performing the GET request for endpoint {_restClient.BuildUri(restReq)}");
                var res = await _restClient.GetAsync<CertificateListResponse>(restReq, ct);
                _logger.LogTrace($"received a response. searchHits: {res.SearchHits}, certificates in page: {res.Certificates?.Count}");
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
        /// retreives the procedures associated with the provided media type value
        /// </summary>
        /// <param name="mediaType"></param>
        /// <returns>a list of the procedure IDs</returns>
        public async Task<List<string>> GetProceduresByMediaType(string mediaType = Constants.MEDIATYPE_PKCS10)
        {
            _logger.MethodEntry();
            _logger.LogTrace($"getting available procedures for media type: {mediaType}");

            try
            {
                var endpoint = ApiEndpoints.LISTPROCEDURES;
                var req = new RestRequest(endpoint);
                req.AddQueryParameter("mediaType", mediaType);
                var res = await _restClient.GetAsync<ListProceduresResponse>(req);

                var procedures = res.Procedures.Select(p => p.Name).ToList();
                _logger.LogTrace($"successfully retrieved a list of {procedures.Count} procedures for mediaType {mediaType}");
                return procedures;
            }
            catch (Exception ex)
            {
                _logger.LogError($"there was an error retrieving the procedures for mediaType {mediaType}: {LogHandler.FlattenException(ex)}");
                throw;
            }
        }


        /// <summary>
        /// This method calls the "/procedures" endpoint of the API
        /// The ping is successful if the server returns "200".  
        /// The content of the response is ignored
        /// </summary>
        /// <returns>A boolean indicating whether the server is reachable and responding.</returns>
        public async Task<bool> PingServer()
        {
            _logger.MethodEntry();
            try
            {
                var endpoint = ApiEndpoints.LISTPROCEDURES;
                _logger.LogTrace($"pinging the endpoint {endpoint} to verify server is accessible");
                var req = new RestRequest(endpoint);
                var res = await _restClient.GetAsync(req);
                if (res.IsSuccessStatusCode) return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"the attempt to ping the server failed: {LogHandler.FlattenException(ex)}");
            }
            finally { _logger.MethodExit(); }
            return false;
        }
    }
}
