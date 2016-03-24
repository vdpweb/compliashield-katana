
namespace CompliaShield.Katana.Sandbox.WebClient
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Principal;
    using System.Web;
    using System.Web.Http;
    using System.Web.Mvc;
    using System.Web.Optimization;
    using System.Web.Routing;
    using System.Web.Security;
    using CompliaShield.Katana.Sandbox.WebClient.Code;
    using System.IO;

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            //GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }



        void Application_BeginRequest(object sender, EventArgs e)
        {
            //if (HttpContext.Current.Request.Url.AbsolutePath.Contains("signin-"))
            //{
            //    var fileName = Guid.NewGuid().ToString("N");
            //    var requestRaw = HttpContext.Current.Request.ToRaw();
            //    var fi = new FileInfo(@"C:\temp\RequestDebug\" + fileName + ".txt");
            //    if (!fi.Directory.Exists)
            //    {
            //        fi.Directory.Create();
            //    }
            //    File.WriteAllText(fi.FullName, requestRaw);
            //}
        }

        //protected void Application_AuthenticateRequest(Object sender, EventArgs e)
        //{
        //    HttpCookie authCookie = Request.Cookies[FormsAuthentication.FormsCookieName];
        //    if (authCookie != null)
        //    {

        //        //Extract the forms authentication cookie
        //        FormsAuthenticationTicket authTicket = FormsAuthentication.Decrypt(authCookie.Value);

        //        var token = new JwtSecurityToken(jwt); //TokenHelper.GetJWTokenFromCookie(authCookie);

        //        // Create the IIdentity instance
        //        IIdentity id = new FormsIdentity(authTicket);

        //        // Create the IPrinciple instance
        //        IPrincipal principal = new GenericPrincipal(id, TokenHelper.GetRolesFromToken(jwTok).ToArray());

        //        // Set the context user
        //        Context.User = principal;
        //    }
        //}


        //private void SetCookie(JwtSecurityToken token)
        //{
        //    var ticket = new FormsAuthenticationTicket(1, model.Email, DateTime.Now, ConvertUnitToDateTime(token.expires_in), true, token.RawData);
        //    string encryptedTicket = FormsAuthentication.Encrypt(ticket);
        //    var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
        //    cookie.HttpOnly = true;
        //    Response.Cookies.Add(cookie);
        //}

    }
}
