using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace CompliaShield.Katana.Sandbox.WebClient.Controllers
{
    [Authorize(Roles = "OAuth2 Grant User")]
    public class OAuthTestController : Controller
    {
        // GET: OAuthTest
        public ActionResult Index()
        {

            var identity = User.Identity as ClaimsIdentity;
            var list = new Dictionary<string, object>();

            foreach (var claim in identity.Claims)
            {
                list = this.AddValue(list, claim.Type, claim.Value);
            }

            return View();
        }


        [Authorize(Roles = "OAuth2 Grant User asdkfajsdfXXXXX")]
        public ActionResult Denied()
        {

            var identity = User.Identity as ClaimsIdentity;
            var list = new Dictionary<string, object>();

            foreach (var claim in identity.Claims)
            {
                list = this.AddValue(list, claim.Type, claim.Value);
            }

            return View();
        }

        #region helpers

        private Dictionary<string, object> AddValue(Dictionary<string, object> dic, string key, string value)
        {
            List<string> items = null;
            if (dic.ContainsKey(key))
            {
                var existing = dic[key];
                if (existing is string)
                {
                    items = new List<string>();
                    items.Add((string)existing);
                    items.Add(value);
                }
                else if (existing is string[])
                {
                    items = ((string[])existing).ToList();
                    items.Add(value);
                }
                dic.Remove(key);
                dic[key] = items.ToArray();
            }
            else
            {
                dic[key] = value;
            }
            return dic;
        }

        #endregion

    }
}