using System;
using System.Security.Cryptography;

namespace Viegrid.Security
{
    public class MD5
    {
        #region Hash Algorithms

        public string GetMD5String(bool base64, params object[] data)
        {
            //   Gop DL thanh một khối
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            foreach (var item in data)
                sb.Append(item);
            byte[] buffer = GetMD5ByteArray(sb.ToString());
            if (base64)
                return System.Convert.ToBase64String(buffer);
            else
            {
                System.Text.StringBuilder s = new System.Text.StringBuilder();
                foreach (byte b in buffer)
                {
                    s.Append(b.ToString("x2"));
                }
                return s.ToString();
            }
        }

        public byte[] GetMD5ByteArray(string st)
        {
            System.Security.Cryptography.MD5CryptoServiceProvider x = new System.Security.Cryptography.MD5CryptoServiceProvider();
            byte[] bs = System.Text.Encoding.UTF8.GetBytes(st);
            return x.ComputeHash(bs);
        }

        public string GetSHA1String(bool base64, params object[] data)
        {
            //   Gop DL thanh một khối
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            foreach (var item in data)
                sb.Append(item);
            byte[] buffer = GetSHA1ByteArray(sb.ToString());
            if (base64)
                return System.Convert.ToBase64String(buffer);
            else
            {
                System.Text.StringBuilder s = new System.Text.StringBuilder();
                foreach (byte b in buffer)
                {
                    s.Append(b.ToString("x2"));
                }
                return s.ToString();
            }
        }

        public byte[] GetSHA1ByteArray(string st)
        {
            System.Security.Cryptography.SHA1CryptoServiceProvider x = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            byte[] bs = System.Text.Encoding.UTF8.GetBytes(st);
            return x.ComputeHash(bs);
        }

        #endregion
    }
}
