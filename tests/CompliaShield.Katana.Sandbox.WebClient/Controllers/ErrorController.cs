using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CompliaShield.Katana.Sandbox.WebClient.Controllers
{
    public class ErrorController : Controller
    {
        // GET: Error
        public ActionResult Index(string id)
        {
            if(id == "NotFound")
            {
                this.Response.StatusCode = 404;
                return View("NotFound");
            }
            return View();
        }
    }
}