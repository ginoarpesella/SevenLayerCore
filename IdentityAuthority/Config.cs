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
                ClientId = "openIdConnectClient",
                ClientName = "Hybrid OIDC Client Application",
                AllowedGrantTypes = GrantTypes.Hybrid,
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId, // this means return the open id (subjectId)
                    IdentityServerConstants.StandardScopes.Profile, // this means return all claims
                    IdentityServerConstants.StandardScopes.Email, // and receive email address
                    IdentityServerConstants.StandardScopes.Address,
                    "roles",
                    "clientApiTest"
                },
                ClientSecrets = new List<Secret>() { new Secret("oidcSecret".Sha256()) }, // this needs to be here to that the client can call the token endpoint
                RedirectUris = new List<string> { "https://localhost:44396/signin-oidc" }, // this needs to be the web apis address
                PostLogoutRedirectUris = new List<string> { "https://localhost:44396/signout-callback-oidc" }
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
                new IdentityResources.Address(),
                new IdentityResources.Email(),
                new IdentityResource { Name = "roles", DisplayName = "Your role(s)", UserClaims = new List<string> {"role"} }
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource> {
                new ApiResource("clientApiTest", "Client Api Test")
            };
        }
    }

    internal class TestUsers
    {
        public static List<TestUser> Get()
        {
            return new List<TestUser>() {
                new TestUser {
                    SubjectId = "test-user-subject-id-1",
                    Username = "gino1",
                    Password = "1234",
                    Claims = new List<Claim>
                    {
                        new Claim("given_name", "Gino 1"),
                        new Claim("family_name", "Family Name 1"),
                        new Claim("address", "my personal address 1"),
                        new Claim("role", "FreeUser")
                    }
                },
                new TestUser {
                    SubjectId = "test-user-subject-id-2",
                    Username = "gino2",
                    Password = "1234",
                    Claims = new List<Claim>
                    {
                        new Claim("given_name", "Gino 2"),
                        new Claim("family_name", "Family Name 2"),
                        new Claim("address", "my personal address 2"),
                        new Claim("role", "PayingUser")
                    }
                }
            };
        }
    }
}
