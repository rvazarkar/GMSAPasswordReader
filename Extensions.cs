using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace GMSAPasswordReader
{
    internal static class Extensions
    {
        private static readonly Regex DCReplaceRegex = new Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

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

        internal static string DistinguishedNameToDomain(string distinguishedName)
        {
            var temp = distinguishedName.Substring(distinguishedName.IndexOf("DC=",
                StringComparison.CurrentCultureIgnoreCase));
            temp = DCReplaceRegex.Replace(temp, "").Replace(",", ".").ToUpper();
            return temp;
        }
    }

    static class Ext
    {
        public static HashAlgorithm MD4Singleton;

        static Ext()
        {
            MD4Singleton = System.Security.Cryptography.MD4.Create();
        }

        public static byte[] MD4(this string s)
        {
            return MD4Singleton.ComputeHash(System.Text.Encoding.Unicode.GetBytes(s));
        }

        public static string AsHexString(this byte[] bytes)
        {
            return String.Join("", bytes.Select(h => h.ToString("X2")));
        }
    }
}
