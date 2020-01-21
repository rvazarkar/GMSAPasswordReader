using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;

namespace GMSAPasswordReader
{
    internal class Options
    {
        [Option(Default = null, HelpText = "Domain name the account belongs too.")]
        public string DomainName { get; set; }

        [Option(Default = null, HelpText = "Hostname of a domain controller to query from")]
        public string DomainController { get; set; }

        [Option(Default = 389, HelpText = "Override port used to connect to LDAP")]
        public int LdapPort { get; set; }

        [Option(Required = true, HelpText = "Account Name of the GMSA")]
        public string AccountName { get; set; }

        [Usage(ApplicationAlias = "GMSAPasswordReader")]
        public static IEnumerable<Example> Examples =>
            new List<Example>
            {
                new Example("Retrieve password for the account jkohler in your current domain", new Options{ AccountName = "jkohler"}),
                new Example("Retrieve password for the account arobbins in the domain testlab", new Options
                {
                    AccountName = "arobbins",
                    DomainName = "testlab.local"
                })
            };
    }
}
