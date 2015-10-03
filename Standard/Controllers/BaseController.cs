using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using WebLib;

namespace Standard.Controllers
{
    public class BaseController : Controller
    {
        public molEntities db = new molEntities();

        protected override void OnActionExecuted(ActionExecutedContext filterContext)
        {
            base.OnActionExecuted(filterContext);
        }
        public ActionResult AccessDenied()
        {
            return View("_AccessDenied");
        }
        public void ShowMessage(string message, bool isSuccess = true)
        {
            if (isSuccess)
            {
                SessionUtilities.Set(Constant.SESSION_MessageSuccess, message);
            }
            else
            {
                SessionUtilities.Set(Constant.SESSION_MessageError, message);
            }

        }
    }
}