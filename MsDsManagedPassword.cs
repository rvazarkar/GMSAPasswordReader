using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMSAPasswordReader
{
    /// <summary>
    /// Adapted entirely from Mark Gamache's script found here: https://github.com/markgamache/gMSA/blob/master/PSgMSAPwd
    /// All the hard work and credit goes to him
    /// </summary>

    internal class MsDsManagedPassword
    {
        internal short Version { get; set; }
        internal string CurrentPassword { get; set; }
        internal string OldPassword { get; set; }
        internal DateTime NextQueryTime { get; set; }
        internal DateTime PasswordGoodUntil { get; set; }

        internal MsDsManagedPassword(byte[] blob)
        {
            using (var stream = new MemoryStream(blob))
            {
                using (var reader = new BinaryReader(stream))
                {
                    Version = reader.ReadInt16();
                    reader.ReadInt16();

                    var length = reader.ReadInt32();

                    if (length != blob.Length)
                    {
                        throw new Exception("Missized blob");
                    }

                    var curPwdOffset = reader.ReadInt16();
                    CurrentPassword = GetUnicodeString(blob, curPwdOffset);

                    var oldPwdOffset = reader.ReadInt16();
                    if (oldPwdOffset > 0)
                    {
                        OldPassword = GetUnicodeString(blob, oldPwdOffset);
                    }

                    var queryPasswordIntervalOffset = reader.ReadInt16();
                    var queryPasswordIntervalTicks = BitConverter.ToInt64(blob, queryPasswordIntervalOffset);
                    NextQueryTime = DateTime.Now + TimeSpan.FromTicks(queryPasswordIntervalTicks);

                    var unchangedPasswordIntervalOffset = reader.ReadInt16();
                    var unchangedPasswordIntervalTicks = BitConverter.ToInt64(blob, unchangedPasswordIntervalOffset);
                    PasswordGoodUntil = DateTime.Now + TimeSpan.FromTicks(unchangedPasswordIntervalTicks);
                }
            }
        }

        private string GetUnicodeString(byte[] blob, int index)
        {
            var stOut = "";

            for (var i = index; i < blob.Length; i += 2)
            {
                var ch = BitConverter.ToChar(blob, i);
                if (ch == char.MinValue)
                {
                    //found the end  .    A null-terminated WCHAR string
                    return stOut;
                }
                stOut += ch;
            }

            return null;
        }
    }
}
