﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ClientApplicationTest.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using ClientApplicationTest.Services;
using System.Net.Http;
using Newtonsoft.Json;

namespace ClientApplicationTest.Controllers
{
    public class HomeController : Controller
    {
        private readonly IApiHttpClient _apiHttpClient;

        public HomeController(IApiHttpClient apiHttpClient)
        {
            _apiHttpClient = apiHttpClient;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";
            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public async Task Logout()
        {
            await HttpContext.SignOutAsync("Cookies"); // removes the local cookies
            await HttpContext.SignOutAsync("oidc"); // signs out of the IdenServer
        }

        [Authorize]
        public IActionResult Login()
        {
            return RedirectToAction("Index");
        }

        [Authorize]
        public async Task<IActionResult> GetUserInfo()
        {
            DiscoveryClient discoveryClient = new DiscoveryClient("https://localhost:44395/");
            DiscoveryResponse metaDataResponse = await discoveryClient.GetAsync();

            UserInfoClient userInfoClient = new UserInfoClient(metaDataResponse.UserInfoEndpoint);
            string accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);

            UserInfoResponse response = await userInfoClient.GetAsync(accessToken);

            if (response.IsError)
            {
                throw new Exception("Problem accessing the UserInfo endpoint", response.Exception);
            }

            GetUserInfoViewModel model = new GetUserInfoViewModel();
            model.Address = response.Claims.FirstOrDefault(x => x.Type == "address")?.Value;
            model.GivenName = response.Claims.FirstOrDefault(x => x.Type == "given_name")?.Value;
            model.FamilyName = response.Claims.FirstOrDefault(x => x.Type == "family_name")?.Value;
            model.Role = response.Claims.FirstOrDefault(x => x.Type == "role")?.Value;

            return View(model);
        }

        [Authorize(Roles = "PayingUser")]
        public async Task<IActionResult> Collections()
        {
            UserCollectionsViewModel model = new UserCollectionsViewModel();

            HttpClient httpClient = await _apiHttpClient.GetClient();
            HttpResponseMessage response = await httpClient.GetAsync("api/collections").ConfigureAwait(false);

            if(response.IsSuccessStatusCode)
            {
                string collection =  await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                model.MyCollections = JsonConvert.DeserializeObject<List<string>>(collection);
            }

            return View(model);
        }
    }
}
