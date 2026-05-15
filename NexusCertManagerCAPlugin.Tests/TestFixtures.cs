// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager.Tests
{
    /// <summary>
    /// Shared factory helpers used across all test classes.
    /// </summary>
    internal static class TestFixtures
    {
        // ── Config factories ──────────────────────────────────────────────────

        /// <summary>Returns a config with SyncProcedureField unset (sync disabled).</summary>
        public static NexusCertManagerCAPluginConfig ConfigWithoutSync() =>
            new NexusCertManagerCAPluginConfig
            {
                Host = "https://nexus.example.com:8444",
                AuthCertificatePath = @"C:\certs\auth.pfx",
                AuthCertPassword = "password",
                Enabled = true,
                SyncProcedureField = null
            };

        /// <summary>Returns a config with SyncProcedureField set to the given field name.</summary>
        public static NexusCertManagerCAPluginConfig ConfigWithSync(string fieldName = "field1") =>
            new NexusCertManagerCAPluginConfig
            {
                Host = "https://nexus.example.com:8444",
                AuthCertificatePath = @"C:\certs\auth.pfx",
                AuthCertPassword = "password",
                Enabled = true,
                SyncProcedureField = fieldName
            };

        // ── Plugin factory ────────────────────────────────────────────────────

        /// <summary>
        /// Builds a plugin instance with all dependencies injected.
        /// Avoids any file I/O or real HTTP calls.
        /// </summary>
        public static NexusCertManagerCAPlugin BuildPlugin(
            INexusCertManagerClient client,
            ICertificateDataReader dataReader,
            NexusCertManagerCAPluginConfig config)
        {
            var logger = NullLogger<NexusCertManagerCAPlugin>.Instance;
            return new NexusCertManagerCAPlugin(logger, client, dataReader, config);
        }

        // ── Model factories ───────────────────────────────────────────────────

        public static JsonCertificate MakeCert(
            string certId,
            string status = "active",
            string reason = null,
            ExtendedCertSearch extendedCertSearch = null) =>
            new JsonCertificate
            {
                CertId = certId,
                Status = status,
                Reason = reason,
                ExtendedCertSearch = extendedCertSearch
            };

        public static ExtendedCertSearch MakeExtendedSearch(
            string field1 = null, string field2 = null, string field3 = null,
            string field4 = null, string field5 = null, string field6 = null) =>
            new ExtendedCertSearch
            {
                Field1 = field1,
                Field2 = field2,
                Field3 = field3,
                Field4 = field4,
                Field5 = field5,
                Field6 = field6,
            };

        public static CertificateListResponse MakeCertListPage(
            int totalHits, List<JsonCertificate> certs) =>
            new CertificateListResponse
            {
                SearchHits = totalHits,
                Certificates = certs
            };

        public static CertificateDetailsResponse MakeCertDetailsResponse(JsonCertificate cert) =>
            new CertificateDetailsResponse { Certificate = cert };

        // A real self-signed certificate used as stub data in tests that exercise the
        // certificate download/parse path. Generated once with openssl; never expires in
        // any timeframe relevant to this codebase (expiry 2036).
        private const string _stubPemCert =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIC/zCCAeegAwIBAgIUIs543UBfs01GyhSpIf0rU9RBT1swDQYJKoZIhvcNAQEL\n" +
            "BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA1MTQxNzA2MTlaFw0zNjA1MTExNzA2\n" +
            "MTlaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQC0scDeekblipzkK5EEUfT5Ozh8KqDJMvr7kgT4LjuV6M1N73F9fLGzEq7Y\n" +
            "4EqfgJ3k/+mEdxZbPDr8pZhQu8oeeM35Mjmf2fpH/APqLcszG2Ms4SOW3bsvcM7u\n" +
            "WUmig405gvQNgNQJyXJf/bZKakCWI00LA86GC1hN2Vj6TqEQNIqXRttJVtvqbfET\n" +
            "P2QTDCwI04o0IUpdRkom0HpWqtmPb5+Q3Vz2CwebsSVc3wOUEzeo91J0qCQmSZmX\n" +
            "Fxiy8FbWsAWRoMuQgCiBoSmcUBH5gHhm+S5AHClt3y1Lqzb/FBXIvAv94djjLZHI\n" +
            "q4T59m/Q7AqZ3jrZizgVv6MnND7TAgMBAAGjUzBRMB0GA1UdDgQWBBS8tnCUL7Bc\n" +
            "IDEP1r0BoxTnk2PM7DAfBgNVHSMEGDAWgBS8tnCUL7BcIDEP1r0BoxTnk2PM7DAP\n" +
            "BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBqMKqxc//BqpGhSVWV\n" +
            "HjusamahkkKA+sRuWctuWjNcX5Y5dJ/DEgnymXcLf19BOZToFy9MQUquAC8Rv2cX\n" +
            "AdktYFIASabwLEnbXqiEmUqTND8xpe5tnlsK6q+cHoJTv9lW02j9pKb0KndhU6bw\n" +
            "AFjLYOwOyLjMFHLuM2VbOkLOli1gqyZGrzDSmqFeGs0JCSzTNsKpZYe8ihlBhKpG\n" +
            "ult87ygYu16KbXLyFifLAwqxkPicfS+04MVRzdj5BgkgtyCutKk+cIu44iIK9S3R\n" +
            "lnCR6RG9fNloWZ/yCLChe3BiP7pbPbCasQ59/Xkyv9RIzjRpYn2wNHyhyXt+VQcb\n" +
            "bv6i\n" +
            "-----END CERTIFICATE-----\n";

        public static CertificateBinaryResponse MakeBinaryResponse(
            string certId = "cert-001",
            string pemContent = null) =>
            new CertificateBinaryResponse
            {
                CertId = certId,
                PEMString = pemContent ?? _stubPemCert,
                ContentType = Constants.PEMCHAIN
            };

        public static EnrollmentProductInfo MakeProductInfo(string productId, Dictionary<string, string> parameters = null) =>
            new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = parameters ?? new Dictionary<string, string>()
            };
    }
}
