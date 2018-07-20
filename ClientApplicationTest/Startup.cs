using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;

namespace ClientApplicationTest
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;

            // this will stop the middleware from mapping claims to its internal dictionary
            // and keep the claims as is from the Identity Server
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddAuthentication(options => {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("Cookies", cookieOptions => {
                cookieOptions.AccessDeniedPath = "/Authorization/AccessDenied";
            })
            .AddOpenIdConnect("oidc", oidcOptions => {
                oidcOptions.SignInScheme = "Cookies";
                oidcOptions.Authority = "https://localhost:44395/";
                oidcOptions.ClientId = "openIdConnectClient";
                oidcOptions.ResponseType = "code id_token";

                oidcOptions.Scope.Add("openid"); // this is the default if not included
                oidcOptions.Scope.Add("profile"); // also default
                oidcOptions.Scope.Add("address"); // this is manual
                oidcOptions.Scope.Add("roles"); // when getting roles the IdenSer will return a list<role>. We map this on the line below
                oidcOptions.ClaimActions.MapUniqueJsonKey("role", "role"); // this will map incoming 'role' claims to 'role' key

                // this explains how the validation of a token should be handled
                oidcOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtClaimTypes.GivenName,
                    RoleClaimType = JwtClaimTypes.Role,
                };

                oidcOptions.SaveTokens = true; // creates less round trips
                oidcOptions.ClientSecret = "oidcSecret"; // this NEEDS to match the ClientSecret on the IdenSer
                oidcOptions.GetClaimsFromUserInfoEndpoint = true;
                oidcOptions.ClaimActions.Remove("amr"); // keeps the claim in the collection. Has nothing to do woth removing

                
                
                // this will keep the JWT small
                //options.ClaimActions.DeleteClaim("sid");
                //options.ClaimActions.DeleteClaim("idp");

                //options.ClaimActions.DeleteClaim("address");
                //options.CallbackPath = new PathString("..."); 
            });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        } 

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
