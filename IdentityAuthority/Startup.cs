using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthority
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddIdentityServer()
                .AddInMemoryClients(Clients.Get())
                .AddInMemoryIdentityResources(Resources.GetIdentityResources())
                .AddInMemoryApiResources(Resources.GetApiResources())
                .AddTestUsers(Users.Get())
                .AddDeveloperSigningCredential();

            services.AddAuthentication()
            .AddGoogle("Google", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClientId = "281475367621-1i0fn8jeiurhgjm4uveg8bq4na85qbpv.apps.googleusercontent.com"; // https://console.developers.google.com go create your own
                        options.ClientSecret = "n9BtAuOOYetv6Vbh1il9BjYO";
                })
                .AddOpenIdConnect("oidc", "IdentityServer", options =>
                    {
                        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                        options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                        options.Authority = "https://localhost:44395/";
                        options.ClientId = "implicit";
                        options.ResponseType = "id_token";
                        options.SaveTokens = true;
                        options.CallbackPath = new PathString("/signin-idsrv");
                        options.SignedOutCallbackPath = new PathString("/signout-callback-idsrv");
                        options.RemoteSignOutPath = new PathString("/signout-idsrv");

                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            NameClaimType = "name",
                            RoleClaimType = "role"
                        };
                    });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseIdentityServer();
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("We are live!");
            });
        }
    }
}
