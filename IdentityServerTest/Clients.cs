namespace IdentityServerTest
{
    using System.Collections;
    using System.Collections.Generic;

    using IdentityServer3.Core.Models;

    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
                       {
                           new Client
                               {
                                   Enabled = true,
                                   ClientName = "MVC Client",
                                   ClientId = "mvc",
                                   Flow = Flows.Implicit,
                                   RedirectUris = new List<string> { "https://localhost:44301/" },
                                   AllowAccessToAllScopes = true
                               }
                       };
        }
    }
}