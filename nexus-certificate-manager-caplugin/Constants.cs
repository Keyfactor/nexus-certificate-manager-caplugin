
//  Copyright 2025 Keyfactor
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public static class Constants
    {
        // config property names
        public const string HOST = "Host";
        public const string AUTHCERTPATH = "AuthCertificatePath";
        public const string ENABLED = "Enabled";
        public const string AUTHCERTPASSWORD = "AuthCertPassword";
        public const string SYNC_PROCEDURE_FIELD = "SyncProcedureField";

        // API / HTTP values
        public const string APIPATH = "pgwy/api";
        public const string PKCS7MIMETYPE = "application/pkcs7-mime";
        public const string PEMCHAIN = "application/pem-certificate-chain";

        // procedure media types
        public const string MEDIATYPE_PKCS10 = "pkcs10";
        public const string MEDIATYPE_PKCS12 = "pkcs12";
        public const string MEDIATYPE_SMARTCARD = "smartcard";
        public const string MEDIATYPE_ATTRIBUTECERT = "attributecertificate";
        public const string MEDIATYPE_DATA = "data";

        // pagination
        public const int SYNC_PAGE_SIZE = 500;
    }

    public static class ApiEndpoints 
    {
        public const string LISTCERTS = "/certificates"; //get
        public static string DOWNLOADCERT(string certId) => $"/certificates/{certId}/download"; //get 
        public static string CERTDETAILS(string certId) => $"/certificates/{certId}/details"; //get

        public const string REVOKE = "/certificates/revoke"; //post

        public const string ENROLL = "/certificates/pkcs10"; //post

        public const string LISTPROCEDURES = "/procedures";
    }
}
