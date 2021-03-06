﻿using Standard;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Linq.Expressions;

namespace Standard
{
    public class DB
    {
        public static List<string> lstTinh = new List<string> { "ViengChan", "Phongsaly", "Luangnamtha", "Oudomxay", 
                "Bokeo", "Luangprabang", "Huaphanh", "Xayabury", "Xiengkhuang" };
        public static int GetTinhCode(string tinh)
        {
            return lstTinh.FindIndex(m => m == tinh) + 1;
        }
        public static WebLib.Models.fwUser CurrentUser
        { get { return WebLib.DAL.fwUserDAL.GetCurrentUser(); } }
        public static molEntities Entities
        {
            get
            {
                return new molEntities();
            }
        }

        public static molEntities GetEntities(string dbName)
        {
            var db = new molEntities();
            string s = db.Database.Connection.ConnectionString.Replace("catalog=outsa;", string.Format("catalog=outsa_{0};", dbName));
            db.Database.Connection.ConnectionString = s;
            return db;
        }
        public class BaseClass<T> where T : class
        {
            molEntities _db;

            public BaseClass(molEntities entity)
            {
                _db = entity;
            }

            public List<T> Find(Expression<Func<T, bool>> predicate)
            {
                return _db.Set<T>().Where(predicate).ToList();
            }

            public List<T> GetAll()
            {
                return _db.Set<T>().ToList();
            }

            public T GetById(object id)
            {
                return _db.Set<T>().Find(id);
            }

            public T GetByUserName(object name)
            {
                return _db.Set<T>().Find(name);
            }

            public void Insert(T obj)
            {
                _db.Set<T>().Add(obj);
                _db.SaveChanges();
            }

            public void Insert(List<T> lst)
            {
                _db.Set<T>().AddRange(lst);
                _db.SaveChanges();
            }

            public void Update(T obj)
            {
                _db.Set<T>().Attach(obj);
                _db.Entry(obj).State = EntityState.Modified;
                _db.SaveChanges();
            }

            public void Delete(object id)
            {
                T obj = _db.Set<T>().Find(id);
                _db.Set<T>().Remove(obj);
                _db.SaveChanges();
            }

            public void Delete(T entity)
            {
                _db.Set<T>().Attach(entity);
                _db.Set<T>().Remove(entity);
                _db.SaveChanges();
            }

            public void Delete(List<T> lst)
            {
                
                foreach (var obj in lst)
                {
                    _db.Set<T>().Attach(obj);
                    _db.Set<T>().Remove(obj);
                }                
                _db.SaveChanges();
            }

            public void Delete(List<int> lstId)
            {
                var removes = _db.Set<T>();
                foreach (var id in lstId)
                {
                    T obj = _db.Set<T>().Find(id);
                    removes.Remove(obj);
                }                
                _db.SaveChanges();
            }
        }
    }

    public class BaseEntity
    {
        public int ID { get; set; }
        public string Name { get; set; }
        public BaseEntity()
        {
        }

        public BaseEntity(int id, string name)
        {
            this.ID = id;
            this.Name = name;
        }
    }
}