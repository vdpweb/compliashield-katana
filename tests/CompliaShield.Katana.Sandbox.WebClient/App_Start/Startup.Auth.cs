
namespace CompliaShield.Katana.Sandbox.WebClient
{
    using System;
    using System.Configuration;
    using System.IdentityModel.Claims;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Web.Helpers;
    using Microsoft.AspNet.Identity;
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security;
    using System.Web;
    using CompliaShield.Owin.Security.OAuth2Service;
    using CompliaShield.Owin.Extensions;
    using Owin;
    using global::Owin;

    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
            });

            //Enable External Sign In Cookie
            app.SetDefaultSignInAsAuthenticationType("Application");

            // Enable CompliaShield OAuth2 sign in
            var cookieOptions = new CookieAuthenticationOptions
            {
                AuthenticationType = CompliaShield.Owin.Security.OAuth2Service.Constants.DefaultAuthenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                //CookieName = CookieAuthenticationDefaults.CookiePrefix + "CompliaShield",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
                LoginPath = new PathString("/Account/Login"),
                //LogoutPath = new PathString("/Account/Logout"),
            };

            app.UseCookieAuthentication(cookieOptions);
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);


            var options = new CompliaShieldOAuth2AuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["csoauth:client_id"],
                ClientSecret = ConfigurationManager.AppSettings["csoauth:client_secret"],
                RolesDesignations = new string[] { "role", "urn:oauth:role" },
                OnGetResellerKey = GetResellerKey
            };

            if (!string.IsNullOrEmpty(AntiForgeryConfig.UniqueClaimTypeIdentifier))
            {
                options.AddDefaultUniqueNameDesignation(AntiForgeryConfig.UniqueClaimTypeIdentifier);
            }

            //// make this match
            //AntiForgeryConfig.UniqueClaimTypeIdentifier =  // options.UniqueNameDesignation;

            var scope = ConfigurationManager.AppSettings["csoauth:scope"];
            if (!string.IsNullOrEmpty(scope))
            {
                scope.Split(' ').ToList().ForEach(x => options.Scope.Add(x));
            }

            var approval_prompt = ConfigurationManager.AppSettings["csoauth:approval_prompt"];
            if (!string.IsNullOrEmpty(approval_prompt))
            {
                options.ApprovalPrompt = approval_prompt;
            }

            // configure app to use CompliaShield OAuth2
            app.UseCompliaShieldAuthentication(options);



            //// alternative simple implementation
            //app.UseCompliaShieldAuthentication(
            //    clientId: ConfigurationManager.AppSettings["csoauth:client_id"],
            //    clientSecret: ConfigurationManager.AppSettings["csoauth:client_secret"]);

            //app.UseGoogleAuthentication(
            //     "483812179322-1smrcm7fjj59aoq1hejk55o2kv8o4ars.apps.googleusercontent.com",
            //     "ay-da2uQqvqumJdU0ybcflw3");

        }

        private Task<string> GetResellerKey()
        {
            var rsl = ConfigurationManager.AppSettings["forceResellerKey"];
            if(string.IsNullOrEmpty(rsl))
            {
                rsl = HttpContext.Current.Request.QueryString["rsl"];
            }
            // could get a cookie or any other value; tied to app settings in this example
            return Task.FromResult<string>(rsl);
        }
    }
}