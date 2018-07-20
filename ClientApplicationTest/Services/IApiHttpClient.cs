using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace ClientApplicationTest.Services
{
    public interface IApiHttpClient
    {
        Task<HttpClient> GetClient();
    }
}
