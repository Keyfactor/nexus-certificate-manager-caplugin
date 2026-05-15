// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    /// <summary>
    /// Abstraction over the Nexus Certificate Manager REST API client.
    /// Extracted primarily to enable unit testing of <see cref="NexusCertManagerCAPlugin"/>
    /// without requiring a live Nexus CA instance or a real PFX certificate on disk.
    /// </summary>
    public interface INexusCertManagerClient
    {
        Task<CertificateBinaryResponse> Enroll(string csr, string procName, CancellationToken ct = default);
        Task<CertificateDetailsResponse> GetCertificateDetails(string certId, CancellationToken ct = default);
        Task<CertificateBinaryResponse> DownloadCertificate(string certId, string format = Constants.PEMCHAIN, CancellationToken ct = default);
        Task RevokeCertificate(string certId, int reason, CancellationToken ct = default);
        Task<CertificateListResponse> GetCertificateList(ListCertificatesRequest req = null, CancellationToken ct = default);
        Task<List<string>> GetProceduresByMediaType(string mediaType = Constants.MEDIATYPE_PKCS10);
        Task<bool> PingServer();
    }
}
