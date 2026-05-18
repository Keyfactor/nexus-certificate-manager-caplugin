// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.NexusCertManager.models;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager.Tests
{
    /// <summary>
    /// Tests for <see cref="Helpers.GetStatusCodeFromNexusCADescription"/>.
    ///
    /// Covers all known Nexus status string mappings and the unknown-status fallback.
    /// </summary>
    public class StatusMappingTests
    {
        [Theory]
        [InlineData("issued")]
        [InlineData("approved")]
        [InlineData("expired")]
        [InlineData("active")]
        public void GetStatusCode_ActiveStatuses_ReturnGenerated(string status)
        {
            Helpers.GetStatusCodeFromNexusCADescription(status)
                .Should().Be((int)EndEntityStatus.GENERATED);
        }

        [Theory]
        [InlineData("processing")]
        [InlineData("reissue_pending")]
        [InlineData("pending")]
        [InlineData("waiting_pickup")]
        [InlineData("needs_approval")]
        public void GetStatusCode_PendingStatuses_ReturnExternalValidation(string status)
        {
            Helpers.GetStatusCodeFromNexusCADescription(status)
                .Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
        }

        [Theory]
        [InlineData("denied")]
        [InlineData("rejected")]
        [InlineData("canceled")]
        public void GetStatusCode_FailureStatuses_ReturnFailed(string status)
        {
            Helpers.GetStatusCodeFromNexusCADescription(status)
                .Should().Be((int)EndEntityStatus.FAILED);
        }

        [Fact]
        public void GetStatusCode_Revoked_ReturnRevoked()
        {
            Helpers.GetStatusCodeFromNexusCADescription("revoked")
                .Should().Be((int)EndEntityStatus.REVOKED);
        }

        [Theory]
        [InlineData("unknown_value")]
        [InlineData("")]
        [InlineData(null)]
        public void GetStatusCode_UnknownOrEmptyStatus_ReturnNew(string status)
        {
            Helpers.GetStatusCodeFromNexusCADescription(status)
                .Should().Be((int)EndEntityStatus.NEW,
                    because: "unknown statuses should default to NEW for manual triage");
        }
    }

    /// <summary>
    /// Tests for <see cref="Helpers.GetRevocationReasonCodeFromNexusCADescription"/>.
    ///
    /// Covers all known Nexus revocation reason strings and the unspecified fallback.
    /// </summary>
    public class RevocationReasonMappingTests
    {
        [Theory]
        [InlineData("key compromise",          RevocationReason.KeyCompromise)]
        [InlineData("affiliation changed",      RevocationReason.AffiliationChanged)]
        [InlineData("superseded",               RevocationReason.Superseded)]
        [InlineData("cessation of operation",   RevocationReason.CessationOfOperation)]
        [InlineData("certificate hold",         RevocationReason.CertificateHold)]
        [InlineData("privilege withdrawn",      RevocationReason.PrivilegeWithdrawn)]
        public void GetRevocationReason_KnownReasons_ReturnCorrectCode(string reason, int expected)
        {
            Helpers.GetRevocationReasonCodeFromNexusCADescription(reason)
                .Should().Be(expected);
        }

        [Theory]
        [InlineData("KEY COMPROMISE")]  // case insensitivity
        [InlineData("Key Compromise")]
        public void GetRevocationReason_CaseInsensitive(string reason)
        {
            Helpers.GetRevocationReasonCodeFromNexusCADescription(reason)
                .Should().Be((int)RevocationReason.KeyCompromise);
        }

        [Theory]
        [InlineData("unknown reason")]
        [InlineData("")]
        [InlineData(null)]
        public void GetRevocationReason_UnknownOrEmpty_ReturnUnspecified(string reason)
        {
            Helpers.GetRevocationReasonCodeFromNexusCADescription(reason)
                .Should().Be(RevocationReason.Unspecified);
        }
    }

    /// <summary>
    /// Tests for <see cref="Helpers.ParseSubject"/>.
    ///
    /// Covers CN extraction from various subject formats.
    /// </summary>
    public class ParseSubjectTests
    {
        [Fact]
        public void ParseSubject_SimpleCN_ExtractedCorrectly()
        {
            Helpers.ParseSubject("CN=test.example.com, O=Acme", "CN=")
                .Should().Be("test.example.com");
        }

        [Fact]
        public void ParseSubject_CNWithEscapedComma_PreservesComma()
        {
            // Escaped commas in the CN value should survive round-trip
            Helpers.ParseSubject(@"CN=Last\, First, O=Acme", "CN=")
                .Should().Be("Last, First");
        }

        [Fact]
        public void ParseSubject_MissingRdn_ThrowsException()
        {
            var act = () => Helpers.ParseSubject("O=Acme, C=US", "CN=");
            act.Should().Throw<System.Exception>().WithMessage("*CN=*");
        }

        [Fact]
        public void ParseSubject_ExtractsOrgUnit()
        {
            Helpers.ParseSubject("CN=test, OU=Engineering, O=Acme", "OU=")
                .Should().Be("Engineering");
        }
    }

    /// <summary>
    /// Tests for <see cref="CmApiException"/>.
    ///
    /// Covers error code descriptions and exception message plumbing.
    /// </summary>
    public class CmApiExceptionTests
    {
        [Theory]
        [InlineData(0, "Success")]
        [InlineData(-1, "General error")]
        [InlineData(-7, "Missing field")]
        [InlineData(-8, "Encoding error")]
        [InlineData(-12, "Not initialized")]
        [InlineData(-14, "Bad field value")]
        [InlineData(-15, "Privilege error")]
        [InlineData(-17, "Bad signature")]
        [InlineData(-18, "Connection error")]
        [InlineData(-19, "Signature required")]
        [InlineData(-40, "Too many requests")]
        [InlineData(-999, "Unknown error")]
        public void GetErrorDescription_KnownCodes_ReturnExpectedDescription(int code, string expected)
        {
            var ex = new CmApiException(code, "test");
            ex.GetErrorDescription().Should().Be(expected);
        }

        [Fact]
        public void CmApiException_MessageIsPreserved()
        {
            var ex = new CmApiException(-1, "Something went wrong");
            ex.Message.Should().Be("Something went wrong");
            ex.ErrorCode.Should().Be(-1);
        }
    }

    /// <summary>
    /// Tests for <see cref="ListCertificatesRequest"/> — the query parameter model
    /// used to paginate and filter certificate list requests.
    ///
    /// Covers that key pagination fields are set correctly when constructing requests.
    /// </summary>
    public class ListCertificatesRequestTests
    {
        [Fact]
        public void ListCertificatesRequest_PaginationFields_SetCorrectly()
        {
            var req = new ListCertificatesRequest
            {
                SearchLimit = 500,
                SearchOffset = 1000
            };

            req.SearchLimit.Should().Be(500);
            req.SearchOffset.Should().Be(1000);
        }

        [Fact]
        public void ListCertificatesRequest_ExtendedSearchFields_SetCorrectly()
        {
            var req = new ListCertificatesRequest { Field1 = "ProcA", Field3 = "Something" };

            req.Field1.Should().Be("ProcA");
            req.Field2.Should().BeNull();
            req.Field3.Should().Be("Something");
        }

        [Fact]
        public void ListCertificatesRequest_AllFieldsNullByDefault()
        {
            var req = new ListCertificatesRequest();

            req.SearchLimit.Should().BeNull();
            req.SearchOffset.Should().BeNull();
            req.Field1.Should().BeNull();
            req.OrderBy.Should().BeNull();
        }
    }
}
