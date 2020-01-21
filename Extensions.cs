using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

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

        public static string GetProperty(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(string));
            if (lookups.Length == 0)
                return null;

            if (!(lookups[0] is string prop) || prop.Length == 0)
                return null;

            return prop;
        }

        /// <summary>
        /// Taken from https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Crypto.cs#L50
        /// </summary>
        /// <param name="password"></param>
        /// <param name="userName"></param>
        /// <param name="domainName"></param>
        public static void ComputeAllKerberosPasswordHashes(string password, string userName = "", string domainName = "")
        {
            // use KerberosPasswordHash() to calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5 hashes for a given password

            if (string.IsNullOrEmpty(password))
            {
                return;
            }
            
            var salt = $"{domainName.ToUpper()}{userName}";

            if (!string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("[*] Input username             : {0}", userName);
                Console.WriteLine("[*] Input domain               : {0}", domainName);
                Console.WriteLine("[*] Salt                       : {0}", salt);
            }

            var rc4Hash = KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, password);
            Console.WriteLine("[*]       rc4_hmac             : {0}", rc4Hash);

            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("\r\n[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!");
            }
            else
            {
                var aes128Hash = KerberosPasswordHash(Interop.KERB_ETYPE.aes128_cts_hmac_sha1, password, salt);
                Console.WriteLine("[*]       aes128_cts_hmac_sha1 : {0}", aes128Hash);

                var aes256Hash = KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, password, salt);
                Console.WriteLine("[*]       aes256_cts_hmac_sha1 : {0}", aes256Hash);

                var desHash = KerberosPasswordHash(Interop.KERB_ETYPE.des_cbc_md5, $"{password}{salt}", salt);
                Console.WriteLine("[*]       des_cbc_md5          : {0}", desHash);
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Taken from https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Crypto.cs#L50
        /// </summary>
        /// <param name="etype"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static string KerberosPasswordHash(Interop.KERB_ETYPE etype, string password, string salt = "", int count = 4096)
        {
            // use the internal KERB_ECRYPT HashPassword() function to calculate a password hash of a given etype
            // adapted from @gentilkiwi's Mimikatz "kerberos::hash" implementation

            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system for the hash type we want
            int status = Interop.CDLocateCSystem(etype, out pCSystemPtr);

            pCSystem = (Interop.KERB_ECRYPT)System.Runtime.InteropServices.Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "Error on CDLocateCSystem");

            // get the delegate for the password hash function
            Interop.KERB_ECRYPT_HashPassword pCSystemHashPassword = (Interop.KERB_ECRYPT_HashPassword)System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(pCSystem.HashPassword, typeof(Interop.KERB_ECRYPT_HashPassword));
            Interop.UNICODE_STRING passwordUnicode = new Interop.UNICODE_STRING(password);
            Interop.UNICODE_STRING saltUnicode = new Interop.UNICODE_STRING(salt);

            byte[] output = new byte[pCSystem.KeySize];

            int success = pCSystemHashPassword(passwordUnicode, saltUnicode, count, output);

            if (status != 0)
                throw new Win32Exception(status);

            return System.BitConverter.ToString(output).Replace("-", "");
        }
    }

}
