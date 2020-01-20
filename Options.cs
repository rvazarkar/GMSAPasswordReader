using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace GMSAPasswordReader
{
    internal class Options
    {
        [Option(Default = null)]
        public string DomainName { get; set; }

        [Option(Default = null)]
        public string DomainController { get; set; }

        [Option(Default = 389)]
        public int LdapPort { get; set; }

        [Option(Required = true)]
        public string AccountName { get; set; }
    }
}
