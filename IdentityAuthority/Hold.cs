using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityAuthority
{
    internal class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new List<Client> {
                new Client {
                ClientId = "oauthClient",
                ClientName = "OAuth Client Application",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {
                    new Secret("superSecretPassword".Sha256())},
                AllowedScopes = new List<string> {"SLCore.read"}
            },
            new Client {
                ClientId = "openIdConnectClient",
                ClientName = "Implicit OIDC Client Application",
                AllowedGrantTypes = GrantTypes.Implicit,
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "role",
                    "SLCore.write"
                },
                RedirectUris = new List<string> { "https://localhost:44396/signin-oidc" }, 
                PostLogoutRedirectUris = new List<string> { "https://localhost:44396" }
            }};
        }
    }

    internal class Resources
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource> {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource {
                    Name = "role",
                    UserClaims = new List<string> {"role"}
                }
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource> {
                new ApiResource {
                    Name = "SLCore",
                    DisplayName = "SLCore API",
                    Description = "SLCore API Access",
                    UserClaims = new List<string> {"role"},
                    ApiSecrets = new List<Secret> {new Secret("789f7607-9136-4254-afcd-10b2cd0c4056".Sha256())},
                    Scopes = new List<Scope> {
                        new Scope("SLCore.read"),
                        new Scope("SLCore.write")
                    }
                }
            };
        }
    }
}
