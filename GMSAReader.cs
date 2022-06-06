using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using CommandLine;

namespace GMSAPasswordReader
{
    internal class GMSAReader
    {
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        static void Main(string[] args)
        {
            Options options = null;

            var parser = new Parser(with =>
            {
                with.CaseSensitive = false;
                with.HelpWriter = Console.Error;
            });

            parser.ParseArguments<Options>(args)
                .WithParsed<Options>(o => { options = o; });

            parser.Dispose();

            if (options == null)
                return;

            string domainName = null, target = null;

            if (options.DomainName == null)
            {
                domainName = GetDomainName(options.DomainName);
            }
	    else 
	    {
                domainName = options.DomainName;
	    }

            target = options.DomainController ?? domainName;

            domainName = $"DC={domainName.Replace(".", ",DC=")}";

            

            var gmsa = SearchLdap(options.AccountName, domainName, target, options.LdapPort);
            if (gmsa == null)
            {
                Console.WriteLine("Unable to retrieve password blob. Check permissions/account name");
                return;
            }

            var managedPassword = new MsDsManagedPassword(gmsa.PasswordBlob);

            if (managedPassword.OldPassword != null)
            {
                Console.WriteLine("Calculating hashes for Old Value");
                Extensions.ComputeAllKerberosPasswordHashes(managedPassword.OldPassword, gmsa.AccountName, gmsa.DomainName);
            }
            
            Console.WriteLine("Calculating hashes for Current Value");
            Extensions.ComputeAllKerberosPasswordHashes(managedPassword.CurrentPassword, gmsa.AccountName, gmsa.DomainName);

        }

        private static string CreateNTLMHash(string password)
        {
            if (password == null)
                return null;

            var hash = Extensions.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, password);
            return hash;
        }

        private static string GetDomainName(string domain)
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

        private static string ConvertDNToDomain(string distinguishedName)
        {
            var temp = distinguishedName.Substring(distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase));
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }

        private static GMSA SearchLdap(string accountName, string domainName, string target, int port)
        {
            var identifier = new LdapDirectoryIdentifier(target, port, false, false);
            var connection = new LdapConnection(identifier) {AuthType = AuthType.Negotiate};

            var cso = connection.SessionOptions;

            //Necessary to get password blobs back
            cso.Signing = true;
            cso.Sealing = true;
            cso.RootDseCache = true;

            var filter = $"(&(|(sAMAccountName={accountName}$)(sAMAccountName={accountName}))(msds-groupmsamembership=*))";
            var searchRequest = new SearchRequest(domainName, filter, SearchScope.Subtree, "sAMAccountName", "msDS-ManagedPassword");
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
                        var newDomainName = ConvertDNToDomain(entry.DistinguishedName);
                        var newAccountName = entry.GetProperty("samaccountname");
                        return new GMSA
                        {
                            AccountName = newAccountName,
                            DomainName = newDomainName,
                            PasswordBlob = passwordBlob
                        };
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
