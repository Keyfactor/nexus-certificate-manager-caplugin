// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
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
    /// Tests for <see cref="NexusCertManagerCAPlugin.Enroll"/>.
    ///
    /// Covers:
    ///   - Happy path: enroll returns a populated EnrollmentResult
    ///   - ProductID is passed as the procedure name to the client
    ///   - Client exception is propagated
    /// </summary>
    public class EnrollTests
    {
        [Fact]
        public async Task Enroll_HappyPath_ReturnsGeneratedStatus()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.Enroll(It.IsAny<string>(), "MyProcedure", It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse("cert-001"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var result = await plugin.Enroll(
                csr: "-----BEGIN CERTIFICATE REQUEST-----\nFAKE\n-----END CERTIFICATE REQUEST-----",
                subject: "CN=test.example.com, O=Acme",
                san: new Dictionary<string, string[]>(),
                productInfo: TestFixtures.MakeProductInfo("MyProcedure"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            result.CARequestID.Should().Be("cert-001");
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.StatusMessage.Should().Contain("test.example.com");
        }

        [Fact]
        public async Task Enroll_PassesProcedureNameAsProductId()
        {
            string capturedProcName = null;

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.Enroll(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .Callback<string, string, CancellationToken>((_, procName, __) => capturedProcName = procName)
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse());

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Enroll("csr", "CN=test", new Dictionary<string, string[]>(),
                TestFixtures.MakeProductInfo("SpecificProcedureName"),
                RequestFormat.PKCS10, EnrollmentType.New);

            capturedProcName.Should().Be("SpecificProcedureName",
                because: "the ProductID must be forwarded directly as the Nexus CA procedure name");
        }

        [Fact]
        public async Task Enroll_ClientThrows_ExceptionPropagates()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.Enroll(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new CmApiException(-1, "General error"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Invoking(p => p.Enroll("csr", "CN=test", new Dictionary<string, string[]>(),
                    TestFixtures.MakeProductInfo("ProcA"),
                    RequestFormat.PKCS10, EnrollmentType.New))
                .Should().ThrowAsync<CmApiException>();
        }
    }

    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.Revoke"/>.
    ///
    /// Covers:
    ///   - Happy path: returns REVOKED status
    ///   - Reason code is forwarded to client
    ///   - Client exception propagates
    /// </summary>
    public class RevokeTests
    {
        [Fact]
        public async Task Revoke_HappyPath_ReturnsRevokedStatus()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.RevokeCertificate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                  .Returns(Task.CompletedTask);

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var result = await plugin.Revoke("cert-001", "AABBCC", (uint)RevocationReason.KeyCompromise);

            result.Should().Be((int)EndEntityStatus.REVOKED);
        }

        [Fact]
        public async Task Revoke_ForwardsReasonCodeToClient()
        {
            int capturedReason = -1;

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.RevokeCertificate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                  .Callback<string, int, CancellationToken>((_, reason, __) => capturedReason = reason)
                  .Returns(Task.CompletedTask);

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Revoke("cert-001", "AABBCC", (uint)RevocationReason.Superseded);

            capturedReason.Should().Be((int)RevocationReason.Superseded);
        }

        [Fact]
        public async Task Revoke_ClientThrows_ExceptionPropagates()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.RevokeCertificate(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new CmApiException(-15, "Privilege error"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Invoking(p => p.Revoke("cert-001", "AABBCC", 0))
                .Should().ThrowAsync<CmApiException>();
        }
    }

    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.GetSingleRecord"/>.
    ///
    /// Covers:
    ///   - Active cert: ProductID resolved from configured field
    ///   - Active cert: ProductID is null when SyncProcedureField is not configured
    ///   - Revoked cert: RevocationReason and RevocationDate are populated
    ///   - Client exception propagates
    /// </summary>
    public class GetSingleRecordTests
    {
        [Fact]
        public async Task GetSingleRecord_ActiveCert_WithSyncFieldConfigured_ProductIdResolved()
        {
            var certJson = TestFixtures.MakeCert("cert-001", status: "active",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field2: "ProcFromField2"));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateDetails("cert-001", It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertDetailsResponse(certJson));
            client.Setup(c => c.DownloadCertificate("cert-001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse("cert-001"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithSync("field2"));

            var result = await plugin.GetSingleRecord("cert-001");

            result.ProductID.Should().Be("ProcFromField2");
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
        }

        [Fact]
        public async Task GetSingleRecord_ActiveCert_WithoutSyncFieldConfigured_ProductIdIsNull()
        {
            var certJson = TestFixtures.MakeCert("cert-001", status: "active",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA"));

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateDetails("cert-001", It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertDetailsResponse(certJson));
            client.Setup(c => c.DownloadCertificate("cert-001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse("cert-001"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var result = await plugin.GetSingleRecord("cert-001");

            result.ProductID.Should().BeNull(
                because: "without SyncProcedureField configured the ProductID cannot be resolved");
        }

        [Fact]
        public async Task GetSingleRecord_RevokedCert_RevocationFieldsArePopulated()
        {
            var revocationTime = new DateTime(2025, 6, 1, 12, 0, 0, DateTimeKind.Utc);
            var certJson = TestFixtures.MakeCert("cert-001", status: "revoked", reason: "key compromise",
                extendedCertSearch: TestFixtures.MakeExtendedSearch(field1: "ProcA"));
            certJson.RevocationTime = revocationTime;

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateDetails("cert-001", It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeCertDetailsResponse(certJson));
            client.Setup(c => c.DownloadCertificate("cert-001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ReturnsAsync(TestFixtures.MakeBinaryResponse("cert-001"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithSync("field1"));

            var result = await plugin.GetSingleRecord("cert-001");

            result.Status.Should().Be((int)EndEntityStatus.REVOKED);
            result.RevocationDate.Should().Be(revocationTime);
            result.RevocationReason.Should().Be((int)RevocationReason.KeyCompromise);
        }

        [Fact]
        public async Task GetSingleRecord_ClientThrows_ExceptionPropagates()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetCertificateDetails(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                  .ThrowsAsync(new CmApiException(-1, "General error"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithSync("field1"));

            await plugin.Invoking(p => p.GetSingleRecord("cert-001"))
                .Should().ThrowAsync<CmApiException>();
        }
    }

    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.GetProductIds"/>.
    ///
    /// Covers:
    ///   - Returns list of procedure names from client
    ///   - Returns empty list (not throw) when client fails
    /// </summary>
    public class GetProductIdsTests
    {
        [Fact]
        public void GetProductIds_ReturnsProcedureNamesFromClient()
        {
            var procedures = new List<string> { "ProcA", "ProcB", "ProcC" };

            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetProceduresByMediaType(It.IsAny<string>()))
                  .ReturnsAsync(procedures);

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var result = plugin.GetProductIds();

            result.Should().BeEquivalentTo(procedures);
        }

        [Fact]
        public void GetProductIds_WhenClientThrows_ReturnsEmptyListWithoutThrowing()
        {
            var client = new Mock<INexusCertManagerClient>();
            client.Setup(c => c.GetProceduresByMediaType(It.IsAny<string>()))
                  .ThrowsAsync(new Exception("connection failed"));

            var plugin = TestFixtures.BuildPlugin(client.Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var result = plugin.GetProductIds();

            result.Should().BeEmpty(because: "failures during GetProductIds should degrade gracefully");
        }
    }

    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.ValidateProductInfo"/>.
    ///
    /// Covers:
    ///   - Valid ProductID completes without throwing
    ///   - Null/empty/whitespace ProductID throws AnyCAValidationException
    /// </summary>
    public class ValidateProductInfoTests
    {
        [Fact]
        public async Task ValidateProductInfo_WithValidProductId_DoesNotThrow()
        {
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Invoking(p => p.ValidateProductInfo(
                    TestFixtures.MakeProductInfo("ValidProcedure"),
                    new Dictionary<string, object>()))
                .Should().NotThrowAsync();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task ValidateProductInfo_WithEmptyProductId_ThrowsAnyCAValidationException(string productId)
        {
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            await plugin.Invoking(p => p.ValidateProductInfo(
                    TestFixtures.MakeProductInfo(productId),
                    new Dictionary<string, object>()))
                .Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ProductID*");
        }
    }

    /// <summary>
    /// Tests for <see cref="NexusCertManagerCAPlugin.GetCAConnectorAnnotations"/>.
    ///
    /// Covers:
    ///   - All expected keys are present
    ///   - SyncProcedureField is not marked Hidden
    ///   - AuthCertPassword is marked Hidden
    /// </summary>
    public class GetCAConnectorAnnotationsTests
    {
        [Fact]
        public void GetCAConnectorAnnotations_ContainsAllExpectedKeys()
        {
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var annotations = plugin.GetCAConnectorAnnotations();

            annotations.Should().ContainKey(Constants.HOST);
            annotations.Should().ContainKey(Constants.AUTHCERTPATH);
            annotations.Should().ContainKey(Constants.AUTHCERTPASSWORD);
            annotations.Should().ContainKey(Constants.ENABLED);
            annotations.Should().ContainKey(Constants.SYNC_PROCEDURE_FIELD);
        }

        [Fact]
        public void GetCAConnectorAnnotations_AuthCertPasswordIsHidden()
        {
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var annotations = plugin.GetCAConnectorAnnotations();

            annotations[Constants.AUTHCERTPASSWORD].Hidden.Should().BeTrue();
        }

        [Fact]
        public void GetCAConnectorAnnotations_SyncProcedureFieldIsNotHidden()
        {
            var plugin = TestFixtures.BuildPlugin(
                new Mock<INexusCertManagerClient>().Object,
                new Mock<ICertificateDataReader>().Object,
                TestFixtures.ConfigWithoutSync());

            var annotations = plugin.GetCAConnectorAnnotations();

            annotations[Constants.SYNC_PROCEDURE_FIELD].Hidden.Should().BeFalse();
        }
    }
}
