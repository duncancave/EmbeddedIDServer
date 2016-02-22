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
    using Microsoft.IdentityModel.Protocols;
    using System.Threading.Tasks;
    using Microsoft.Owin.Security.Facebook;
    using IdentityModel.Client;
    using System.Linq;
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
                                        .UseInMemoryScopes(Scopes.Get()),

                                    // Use this for Facebook login 
                                    //AuthenticationOptions = new IdentityServer3.Core.Configuration.AuthenticationOptions
                                    //{
                                    //    IdentityProviders = ConfigureIdentityProviders
                                    //}
                                });
                    });

            app.UseCookieAuthentication(new CookieAuthenticationOptions { AuthenticationType = "Cookies" });

            // Point the OpenID Connect middleware (also in Startup.cs) to our embedded version of IdentityServer and use the previously configured client configuration
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                    {
                        Authority = "https://localhost:44301/identity",
                        ClientId = "mvc",
                        Scope = "openid profile roles sampleApi",
                        RedirectUri = "https://localhost:44301/",
                        ResponseType = "id_token token",
                        SignInAsAuthenticationType = "Cookies",
                        UseTokenLifetime = false,

                        // Do the claims transformations
                        Notifications = new OpenIdConnectAuthenticationNotifications
                                            {
                            
                            SecurityTokenValidated = async n =>
                                                    {
                                                        var nid = new ClaimsIdentity(
                                                            n.AuthenticationTicket.Identity.AuthenticationType,
                                                            Constants.ClaimTypes.GivenName,
                                                            Constants.ClaimTypes.Role);

                                                        // get userinfo data
                                                        var userInfoClient = new UserInfoClient(
                                                            new Uri(n.Options.Authority + "/connect/userinfo"),
                                                            n.ProtocolMessage.AccessToken);

                                                        var userInfo = await userInfoClient.GetAsync();
                                                        userInfo.Claims.ToList().ForEach(ui => nid.AddClaim(new Claim(ui.Item1, ui.Item2)));

                                                        // keep the id_token for Logout - the client has to prove its identity to the 
                                                        // logout endpoint to make sure we redirect to the right URL (and not some spammer/phishing page).
                                                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                                                        // add access token for sample API
                                                        nid.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));

                                                        // keep track of access token expiration
                                                        nid.AddClaim(new Claim("expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));

                                                        // add some other app specific claim
                                                        nid.AddClaim(new Claim("app_specific", "some data"));

                                                        n.AuthenticationTicket = new AuthenticationTicket(
                                                            nid,
                                                            n.AuthenticationTicket.Properties);
                                                    },

                            // attach the id_token when the user logs out and we make the roundtrip to IdentityServer.
                            RedirectToIdentityProvider = n =>
                                                    {
                                                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                                                        {
                                                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                                                            if (idTokenHint != null)
                                                            {
                                                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                                            }
                                                        }

                                                        return Task.FromResult(0);
                                                    }
                        }
                    });

            app.UseResourceAuthorization(new AuthorizationManager());
        }

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            app.UseFacebookAuthentication(new FacebookAuthenticationOptions
            {
                AuthenticationType = "Facebook",
                Caption = "Sign-in with Facebook",
                SignInAsAuthenticationType = signInAsType,
                AppId = "",
                AppSecret = ""
            });
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