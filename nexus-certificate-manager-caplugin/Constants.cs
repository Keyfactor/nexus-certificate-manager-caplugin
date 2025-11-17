namespace Keyfactor.Extensions.CAPlugin.NexusCertManager
{
    public static class Constants
    {
        //names
        public const string HOST = "Host";
        public const string AUTHCERTPATH = "AuthCertificatePath";
        public const string ENABLED = "Enabled";        
        public const string AUTHCERTPASSWORD = "AuthCertPassword";


        //values
        public const string APIPATH = "pgwy/api";
        public const string PRODUCTID = "NexusCM";
        public const string PKCS7MIMETYPE = "application/pkcs7-mime";
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
