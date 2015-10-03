using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Standard.Models;
using WebLib.Models;
using WebLib.DAL;
using System.Security.Principal;

namespace Standard.Controllers
{
    [CustomAuthorize]
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                if (new WebLib.DAL.fwUserDAL().Login(model.UserName, model.Password))
                    if (string.IsNullOrEmpty(returnUrl))
                        return RedirectToAction("Index", "Home");
                    else
                        return Redirect(returnUrl);
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Sai mật khẩu hoặc tên đăng nhập.");
            return View(model);
        }
        public ActionResult Logout()
        {
            WebLib.DAL.fwUserDAL.Logout();
            return RedirectToAction("Login", "Account");
        }
        public ActionResult ChangePassword()
        {
            return PartialView("_ChangePasswordPartial");
        }

        [HttpPost]
        public ActionResult ChangePassword(ManageUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = DB.CurrentUser;
                if (DB.CurrentUser.Pass == model.OldPassword)
                {
                    user.Pass = model.NewPassword;
                    new fwUserDAL().Update(user);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Mật khẩu cũ không đúng");
                }
            }
            return PartialView("_ChangePasswordPartial", model);
        }
    }
}