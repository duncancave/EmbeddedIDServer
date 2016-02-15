namespace IdentityServerTest
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using System.Web.Helpers;

    using IdentityServer3.Core;
    using IdentityServer3.Core.Configuration;
    using IdentityServer3.Core.Models;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OpenIdConnect;

    using Owin;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.Map(
                "/identity",
                idsrvApp =>
                    {
                        idsrvApp.UseIdentityServer(
                            new IdentityServerOptions
                                {
                                    SiteName = "Embedded IdentityServer",
                                    SigningCertificate = LoadCertificate(),
                                    Factory =
                                        new IdentityServerServiceFactory().UseInMemoryUsers(
                                            Users.Get())
                                        .UseInMemoryClients(Clients.Get())
                                        .UseInMemoryScopes(Scopes.Get())
                                });
                    });

            app.UseCookieAuthentication(new CookieAuthenticationOptions { AuthenticationType = "Cookies" });

            // Point the OpenID Connect middleware (also in Startup.cs) to our embedded version of IdentityServer and use the previously configured client configuration
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                    {
                        Authority = "https://localhost:44301/identity",
                        ClientId = "mvc",
                        Scope = "openid profile roles",
                        RedirectUri = "https://localhost:44301/",
                        ResponseType = "id_token",
                        SignInAsAuthenticationType = "Cookies",
                        UseTokenLifetime = false,

                        // Do the claims transformations
                        Notifications = new OpenIdConnectAuthenticationNotifications
                                            {
                                                SecurityTokenValidated = async n =>
                                                    {
                                                        var id = n.AuthenticationTicket.Identity;

                                                        // we want to keep first name, last name, subject and roles
                                                        var givenName = id.FindFirst(Constants.ClaimTypes.GivenName);
                                                        var familyName = id.FindFirst(Constants.ClaimTypes.FamilyName);
                                                        var sub = id.FindFirst(Constants.ClaimTypes.Subject);
                                                        var roles = id.FindAll(Constants.ClaimTypes.Role);

                                                        // create new identity and set name and role claim type
                                                        var nid = new ClaimsIdentity(
                                                            id.AuthenticationType,
                                                            Constants.ClaimTypes.GivenName,
                                                            Constants.ClaimTypes.Role);

                                                        nid.AddClaim(givenName);
                                                        nid.AddClaim(familyName);
                                                        nid.AddClaim(sub);
                                                        nid.AddClaims(roles);

                                                        // add some other app specific claim
                                                        n.AuthenticationTicket = new AuthenticationTicket(
                                                            nid,
                                                            n.AuthenticationTicket.Properties);
                                                    }
                                            }
                    });

            app.UseResourceAuthorization(new AuthorizationManager());
        }

        X509Certificate2 LoadCertificate()
        {
            return
                new X509Certificate2(
                    string.Format(@"{0}\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory),
                    "idsrv3test");
        }
    }
}