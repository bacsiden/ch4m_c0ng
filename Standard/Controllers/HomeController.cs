using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Standard.Controllers
{
    //[CustomAuthorize]
    public class HomeController : BaseController
    {
        public ActionResult Index()
        {
            return View(Content("Home/Index"));
        }
    }
}