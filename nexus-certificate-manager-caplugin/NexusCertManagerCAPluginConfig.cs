
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public class NexusCertManagerCAPluginConfig
    {
        [JsonPropertyName(Constants.HOST)]
        public string Host { get; set; }

        [JsonPropertyName(Constants.AUTHCERTPATH)]
        public string AuthCertificatePath { get; set; }

        [JsonPropertyName(Constants.AUTHCERTPASSWORD)]
        public string AuthCertPassword { get; set; }

        [JsonPropertyName(Constants.ENABLED)]
        public bool Enabled { get; set; }

        /// <summary>
        /// Optional. The name of the ExtendedCertSearch field (e.g. "field1") that the Nexus CA
        /// has been configured to populate with the issuing procedure name at certificate issuance
        /// time. When set, Synchronize will use this field to resolve each certificate's ProductID.
        /// When absent, Synchronize is disabled — see documentation for details.
        /// </summary>
        [JsonPropertyName(Constants.SYNC_PROCEDURE_FIELD)]
        public string SyncProcedureField { get; set; }
    }
}
