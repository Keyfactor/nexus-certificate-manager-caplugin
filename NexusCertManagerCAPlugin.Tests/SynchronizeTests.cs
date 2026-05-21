// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager.Tests
{
    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.Synchronize"/>.
    ///
    /// Covers:
    ///   - Guard clause: throws NotSupportedException when SyncProcedureField is not configured
    ///   - Happy path: single page, all certs have procedure field populated
    ///   - Pagination: multiple pages are fetched until SearchHits is exhausted
    ///   - Skipping: certs with empty ExtendedCertSearch field are skipped
    ///   - Field routing: each of field1-field6 is read correctly
    ///   - Invalid field name: unrecognised SyncProcedureField skips all certs
    ///   - Full sync: certs already in DB are included when fullSync=true
    ///   - Status-change sync: cert is included when its status differs from DB
    ///   - Cancellation: OperationCanceledException propagates cleanly
    /// </summary>
    public class SynchronizeTests
    {
        // ── Guard clause ──────────────────────────────────────────────────────

        [Fact]
        public async Task Synchronize_WhenSyncProcedureFieldNotConfigured_ThrowsNotSupportedException()
        {
            var client = new Mock<INexusCertManagerClient>();
            var reader = new Mock<ICertificateDataReader>();
            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithoutSync());

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Invoking(p => p.Synchronize(buffer, null, false, CancellationToken.None))
                .Should().ThrowAsync<NotSupportedException>()
                .WithMessage("*SyncProcedureField*");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Synchronize_WhenSyncProcedureFieldIsNullOrWhitespace_ThrowsNotSupportedException(string fieldValue)
        {
            var config = TestFixtures.ConfigWithSync(fieldValue);
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Invoking(p => p.Synchronize(buffer, null, false, CancellationToken.None))
                .Should().ThrowAsync<NotSupportedException>();
        }

        // ── Happy path (single page) ──────────────────────────────────────────

        [Fact]
        public async Task Synchronize_SinglePage_AllCertsBuffered()
        {
            var certs = new List<JsonCertificate>
            {
                TestFixtures.MakeCert("cert-001", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")),
                TestFixtures.MakeCert("cert-002", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcB")),
            };

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(2, certs));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("not found")); // simulates cert not in DB yet

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            buffer.Count.Should().Be(2, because: "both certs had a populated field1 value");
            buffer.Should().Contain(c => c.CARequestID == "cert-001" && c.ProductID == "ProcA");
            buffer.Should().Contain(c => c.CARequestID == "cert-002" && c.ProductID == "ProcB");
        }

        // ── Pagination ────────────────────────────────────────────────────────

        [Fact]
        public async Task Synchronize_MultiplePagesRequired_AllPagesAreFetched()
        {
            // 3 certs total, page size 500 but we simulate 2-cert pages by
            // returning searchHits=3 on first call, then 1 cert on the second page.
            var page1Certs = new List<JsonCertificate>
            {
                TestFixtures.MakeCert("cert-001", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")),
                TestFixtures.MakeCert("cert-002", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")),
            };
            var page2Certs = new List<JsonCertificate>
            {
                TestFixtures.MakeCert("cert-003", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcB")),
            };

            int callCount = 0;
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(() =>
                  {
                      callCount++;
                      return callCount == 1
                          ? TestFixtures.MakeCertListPage(3, page1Certs)
                          : TestFixtures.MakeCertListPage(3, page2Certs);
                  });
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("not found"));

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            client.Verify(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2), "3 total certs required 2 page fetches");
            buffer.Count.Should().Be(3);
        }

        [Fact]
        public async Task Synchronize_PaginationPassesCorrectOffsets()
        {
            var capturedRequests = new List<ListCertificatesRequest>();

            var page1 = TestFixtures.MakeCertListPage(600,
                new List<JsonCertificate> { TestFixtures.MakeCert("cert-001", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")) });
            // Fill the rest of page 1 to simulate 500 returned on first call
            for (int i = 2; i <= 500; i++)
                page1.Certificates.Add(TestFixtures.MakeCert($"cert-{i:D3}", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")));

            var page2 = TestFixtures.MakeCertListPage(600,
                new List<JsonCertificate>());
            for (int i = 501; i <= 600; i++)
                page2.Certificates.Add(TestFixtures.MakeCert($"cert-{i:D3}", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")));

            int call = 0;
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync((ListCertificatesRequest req, CancellationToken _) =>
                  {
                      capturedRequests.Add(req);
                      return ++call == 1 ? page1 : page2;
                  });
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("not found"));

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10000);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            capturedRequests[0].SearchOffset.Should().Be(0, because: "first page starts at offset 0");
            capturedRequests[0].SearchLimit.Should().Be(Constants.SYNC_PAGE_SIZE);
            capturedRequests[1].SearchOffset.Should().Be(500, because: "second page starts at offset equal to first page count");
        }

        // ── Skipping certs with empty field ───────────────────────────────────

        [Fact]
        public async Task Synchronize_CertWithEmptyProcedureField_IsSkipped()
        {
            var certs = new List<JsonCertificate>
            {
                TestFixtures.MakeCert("cert-001", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")),
                TestFixtures.MakeCert("cert-002", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: null)),  // empty
                TestFixtures.MakeCert("cert-003", extendedCertSearch: null),  // no ExtendedCertSearch at all
            };

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(3, certs));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("not found"));

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            buffer.Count.Should().Be(1, because: "only cert-001 had a populated field1");
            buffer.Should().Contain(c => c.CARequestID == "cert-001");
        }

        // ── Field routing (field1 through field6) ─────────────────────────────

        [Theory]
        [InlineData("field1", "ProcFromField1", null, null, null, null, null)]
        [InlineData("field2", null, "ProcFromField2", null, null, null, null)]
        [InlineData("field3", null, null, "ProcFromField3", null, null, null)]
        [InlineData("field4", null, null, null, "ProcFromField4", null, null)]
        [InlineData("field5", null, null, null, null, "ProcFromField5", null)]
        [InlineData("field6", null, null, null, null, null, "ProcFromField6")]
        public async Task Synchronize_ReadsProductIdFromCorrectField(
            string configuredField,
            string f1, string f2, string f3, string f4, string f5, string f6)
        {
            var expectedProcId = f1 ?? f2 ?? f3 ?? f4 ?? f5 ?? f6;
            var cert = TestFixtures.MakeCert("cert-001",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(f1, f2, f3, f4, f5, f6));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(1, new List<JsonCertificate> { cert }));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("not found"));

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync(configuredField));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            buffer.Count.Should().Be(1);
            buffer.Should().Contain(c => c.ProductID == expectedProcId,
                because: $"ProductID should come from {configuredField}");
        }

        [Fact]
        public async Task Synchronize_UnrecognisedFieldName_AllCertsSkipped()
        {
            var certs = new List<JsonCertificate>
            {
                TestFixtures.MakeCert("cert-001", extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA")),
            };

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(1, certs));

            var reader = new Mock<ICertificateDataReader>();
            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field99"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, false, CancellationToken.None);

            buffer.Count.Should().Be(0, because: "field99 is not a recognised ExtendedCertSearch field name");
        }

        // ── Incremental vs full sync ──────────────────────────────────────────

        [Fact]
        public async Task Synchronize_CertAlreadyInDbWithSameStatus_NotBufferedOnIncrementalSync()
        {
            var cert = TestFixtures.MakeCert("cert-001", status: "active",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA"));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(1, new List<JsonCertificate> { cert }));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID("cert-001"))
                  .ReturnsAsync((int)EndEntityStatus.GENERATED); // cert is already known with same status

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, fullSync: false, CancellationToken.None);

            buffer.Count.Should().Be(0, because: "cert status hasn't changed and fullSync is false");
        }

        [Fact]
        public async Task Synchronize_CertAlreadyInDbWithSameStatus_IsBufferedOnFullSync()
        {
            var cert = TestFixtures.MakeCert("cert-001", status: "active",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA"));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(1, new List<JsonCertificate> { cert }));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID("cert-001"))
                  .ReturnsAsync((int)EndEntityStatus.GENERATED);

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, fullSync: true, CancellationToken.None);

            buffer.Count.Should().Be(1, because: "fullSync=true forces inclusion regardless of status match");
        }

        [Fact]
        public async Task Synchronize_CertStatusChangedInDb_IsBufferedOnIncrementalSync()
        {
            var cert = TestFixtures.MakeCert("cert-001", status: "revoked",
                reason: "key compromise",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA"));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateList(It.IsAny<ListCertificatesRequest>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertListPage(1, new List<JsonCertificate> { cert }));
            client.Setup(c => c.DownloadCertificate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetStatusByRequestID("cert-001"))
                  .ReturnsAsync((int)EndEntityStatus.GENERATED); // DB says active, CA says revoked

            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, fullSync: false, CancellationToken.None);

            buffer.Count.Should().Be(1, because: "the cert's status changed from active to revoked");
            buffer.Should().Contain(c => c.Status == (int)EndEntityStatus.REVOKED && c.RevocationReason.HasValue);
        }

        // ── Cancellation ──────────────────────────────────────────────────────

        [Fact]
        public async Task Synchronize_CancellationRequested_ThrowsOperationCanceledException()
        {
            var cts = new CancellationTokenSource();
            cts.Cancel();

            var client = new Mock<INexusCertManagerClient>();
            var reader = new Mock<ICertificateDataReader>();
            var plugin = TestFixtures.BuildPlugin(client.Object, reader.Object, TestFixtures.ConfigWithSync("field1"));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Invoking(p => p.Synchronize(buffer, null, false, cts.Token))
                .Should().ThrowAsync<OperationCanceledException>();
        }
    }
}
