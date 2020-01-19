using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GMSAPasswordReader
{
    internal static class Extensions
    {
        public static byte[] GetPropertyAsBytes(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(byte[]));
            if (lookups.Length == 0)
                return null;

            if (!(lookups[0] is byte[] bytes) || bytes.Length == 0)
                return null;

            return bytes;
        }
    }
    internal class GMSAReader
    {
        static void Main(string[] args)
        {

        }

        private static string GetDomainName(string domain=null)
        {
            var result = DsGetDcName(null, domain, null, null, DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED | DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME,
                out var pDCI);

            try
            {
                if (result == 0)
                {
                    var dci = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(pDCI);
                    var domainName = dci.DomainName;
                    return domainName;
                }
                else
                {
                    return Environment.UserDomainName;
                }
            }
            finally
            {
                if (pDCI != IntPtr.Zero)
                    NetApiBufferFree(pDCI);
            }
            
        }

        private static byte[] SearchLdap(string accountName, string target, int port=389)
        {
            var identifier = new LdapDirectoryIdentifier(target, port, false, false); 
            var connection = new LdapConnection(identifier);
            var cso = connection.SessionOptions;

            //Necessary to get password blobs back
            cso.Signing = true;
            cso.Sealing = true;

            var filter = $"(&(|(samaccountname={accountName}$)(samaccountname={accountName}))(objectClass=msDS-ManagedServiceAccount))";
            var searchRequest = new SearchRequest(null, filter, SearchScope.Subtree, "sAMAccountName", "msDS-ManagedPassword");
            try
            {
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                var entries = searchResponse?.Entries;
                if (entries == null || entries.Count == 0)
                {
                    Console.WriteLine("GMSA Account Not Found!");
                    return null;
                }

                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    var passwordBlob = entry.GetPropertyAsBytes("msDS-ManagedPassword");
                    if (passwordBlob != null)
                    {
                        return passwordBlob;
                    }
                }

                //We didn't get a password blob
                Console.WriteLine("Unable to get a password blob, maybe not enough permissions?");
                return null;
            }
            finally
            {
                connection.Dispose();
            }
        }


        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
        (
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)]
            string DomainName,
            [In] GuidClass DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)]
            string SiteName,
            DSGETDCNAME_FLAGS Flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
        );

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }


        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);
    }
}
