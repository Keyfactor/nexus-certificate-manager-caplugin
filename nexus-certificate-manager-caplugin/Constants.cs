namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public static class Constants
    {
        public const string HOST = "Host";
        public const string AUTHCERTPATH = "AuthCertificatePath";
        public const string ENABLED = "Enabled";
        public const string APIPATH = "pgwy/api";
        public const string AUTHCERTPASSWORD = "AuthCertPassword";
    }

    public static class ApiEndpoints 
    {
        public const string LISTCERTS = "/certificates"; //get
        public static string DOWNLOADCERT(string certId) => $"/certificates/{certId}/download"; //get

        public const string REVOKE = "/certificates/revoke"; //post

        public const string ENROLL = "/certificates/pkcs10";
    }
}
