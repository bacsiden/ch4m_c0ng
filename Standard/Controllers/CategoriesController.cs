using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Standard;

namespace Standard.Controllers
{
    public class CategoriesController : Controller
    {
        private molEntities db = new molEntities();

        // GET: /Categories/
        [Route("danh-muc/{id}")]
        public async Task<ActionResult> Index(string id)
        {
            var list = await db.Categories.Where(m => m.Type == id).ToListAsync();
            if (list.Count > 0)
            {
                ViewBag.Type = id;
                return View(list);
            }
            return HttpNotFound();
        }

        // POST: /Categories/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        public async Task<bool> NewOrEdit(string listCate, string type)
        {
            try
            {
                System.Web.Script.Serialization.JavaScriptSerializer serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                var list = serializer.Deserialize<List<Categories>>(listCate);
                foreach (var item in list)
                {

                }
                return true;
            }
            catch (Exception)
            {

                return false;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
