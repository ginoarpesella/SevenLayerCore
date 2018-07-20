using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace ClientApplicationTest.Services
{
    public class ApiHttpClient : IApiHttpClient
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private HttpClient _httpClient = new HttpClient();

        public ApiHttpClient(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<HttpClient> GetClient()
        {
            string accessToken = string.Empty;

            HttpContext currentContext = _httpContextAccessor.HttpContext;

            accessToken = await currentContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            // add the access token as a beaere token. Give access to the bearer of this token.
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                _httpClient.SetBearerToken(accessToken);
            }

            _httpClient.BaseAddress = new Uri("https://localhost:44336/"); // the api address
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json")
                );

            return _httpClient;
        }
    }
}
