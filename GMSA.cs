using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMSAPasswordReader
{
    internal class GMSA
    {
        public string AccountName { get; set; }
        public string DomainName { get; set; }
        public byte[] PasswordBlob { get; set; }

    }
}
