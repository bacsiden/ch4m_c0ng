using System;
using System.IO;
using System.Security.Cryptography;

namespace Viegrid.Security
{
    public class RSA
    {
        #region Key Pair
        private const int KEY_SIZE = 1024;// In bit
        private const int DATA_BLOCK = 128;//In byte = KEY_SIZE / 8 
        /*    Direct Encryption (PKCS#1 v1.5)
        Microsoft Windows 2000 or later with the high encryption pack installed.
        Modulus size - 11. (11 bytes is the minimum padding possible.) 
         * Tại sao lại - 11, tìm hiểu thêm trên: http://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacryptoserviceprovider.encrypt.aspx
         */
        private const int DECRYPT_BLOCK = 117;//In byte = KEY_SIZE / 8 - 11

        /// <summary>
        /// <CheckOut Private key, Size = 1024/>
        /// </summary>
        private byte[] privateKey = new byte[] {
7, 2, 0, 0, 0, 164, 0, 0, 82, 83, 65, 50, 0, 4, 0, 0, 1, 0, 1, 0,
133, 233, 87, 201, 251, 100, 149, 168, 232, 254, 238, 85, 151, 99, 29, 209, 120, 15, 246, 227,
138, 42, 240, 157, 219, 8, 226, 89, 126, 128, 179, 239, 206, 15, 50, 132, 229, 108, 226, 252,
4, 249, 75, 154, 3, 78, 65, 51, 250, 195, 218, 219, 141, 194, 105, 229, 158, 159, 99, 188,
37, 133, 89, 133, 27, 244, 10, 64, 188, 170, 244, 41, 69, 214, 20, 38, 94, 73, 20, 49,
169, 119, 66, 228, 77, 130, 92, 174, 151, 201, 49, 160, 95, 208, 229, 194, 96, 216, 2, 58,
17, 222, 113, 201, 153, 111, 109, 220, 122, 183, 35, 136, 16, 5, 4, 10, 190, 60, 219, 178,
20, 106, 35, 151, 101, 196, 53, 160, 217, 52, 85, 145, 172, 38, 85, 217, 36, 178, 147, 213,
75, 210, 183, 225, 129, 191, 10, 192, 3, 83, 23, 228, 145, 13, 170, 183, 218, 39, 80, 76,
222, 77, 12, 129, 4, 106, 239, 23, 231, 26, 108, 77, 162, 185, 25, 167, 178, 65, 142, 112,
164, 139, 16, 210, 82, 251, 124, 29, 241, 140, 5, 217, 141, 126, 63, 172, 158, 95, 70, 185,
159, 0, 159, 254, 233, 7, 108, 202, 44, 224, 227, 28, 185, 103, 38, 7, 203, 116, 147, 182,
214, 244, 219, 240, 181, 45, 155, 239, 64, 87, 181, 209, 211, 183, 248, 204, 168, 161, 88, 15,
133, 196, 209, 134, 152, 162, 246, 38, 115, 57, 83, 47, 51, 18, 252, 188, 81, 116, 167, 74,
210, 46, 232, 242, 234, 152, 42, 4, 152, 182, 65, 145, 237, 17, 119, 121, 187, 33, 107, 226,
219, 154, 254, 162, 113, 53, 45, 27, 232, 73, 197, 115, 204, 109, 41, 226, 38, 97, 37, 76,
113, 47, 24, 77, 45, 102, 156, 171, 75, 171, 20, 167, 23, 137, 207, 73, 29, 243, 207, 202,
141, 176, 228, 86, 30, 108, 180, 105, 75, 132, 217, 96, 3, 214, 179, 246, 251, 146, 185, 254,
145, 199, 109, 44, 33, 209, 71, 94, 85, 142, 28, 140, 9, 226, 195, 79, 97, 240, 16, 28,
11, 248, 191, 15, 132, 85, 212, 131, 194, 48, 218, 30, 191, 44, 64, 33, 37, 222, 207, 231,
164, 16, 4, 7, 144, 230, 224, 206, 141, 41, 251, 161, 173, 112, 170, 166, 103, 66, 61, 246,
199, 248, 117, 8, 32, 56, 41, 56, 124, 139, 54, 110, 3, 213, 54, 143, 190, 218, 13, 56,
120, 141, 123, 62, 194, 53, 121, 254, 253, 247, 184, 31, 11, 75, 33, 29, 160, 162, 255, 178,
48, 181, 163, 92, 121, 219, 94, 126, 129, 44, 159, 80, 248, 193, 54, 128, 109, 253, 205, 5,
45, 239, 119, 213, 1, 203, 241, 234, 32, 223, 95, 148, 215, 49, 124, 155, 191, 41, 157, 102,
253, 251, 202, 172, 142, 203, 230, 214, 67, 174, 46, 225, 251, 98, 166, 1, 255, 75, 248, 130,
174, 132, 128, 46, 164, 170, 132, 147, 134, 50, 17, 58, 154, 217, 225, 109, 186, 213, 178, 173,
16, 31, 229, 117, 185, 125, 13, 249, 231, 233, 50, 12, 119, 141, 123, 156, 115, 144, 74, 215,
134, 9, 143, 11, 74, 76, 197, 181, 124, 170, 98, 48, 240, 245, 76, 189, 216, 70, 129, 138,
128, 156, 147, 255, 35, 85, 87, 85, 4, 197, 41, 145, 201, 104, 246, 47};


        /// <summary>
        /// <vtcafes Public key, Size = 1024/>
        /// </summary>
        private byte[] vtcafesPublicKey = new byte[] {
6, 2, 0, 0, 0, 164, 0, 0, 82, 83, 65, 49, 0, 4, 0, 0, 1, 0, 1, 0,
63, 56, 102, 245, 245, 187, 145, 194, 227, 67, 73, 102, 153, 102, 7, 169, 239, 105, 172, 91,
127, 179, 103, 188, 51, 242, 150, 209, 20, 227, 2, 95, 147, 111, 30, 21, 1, 133, 254, 73,
11, 224, 43, 154, 99, 23, 27, 67, 4, 246, 85, 46, 239, 169, 33, 227, 192, 45, 162, 222,
58, 24, 81, 111, 24, 236, 115, 112, 85, 103, 170, 221, 185, 119, 210, 81, 166, 148, 6, 41,
17, 157, 251, 240, 58, 170, 203, 165, 107, 251, 151, 208, 236, 107, 194, 220, 111, 27, 141, 226,
131, 222, 211, 125, 124, 159, 200, 142, 111, 2, 33, 6, 77, 249, 28, 117, 7, 208, 26, 163,
183, 59, 239, 79, 36, 215, 209, 135};

        /// <summary>
        /// <check Out Public key, Size = 1024/>
        /// </summary>
        private byte[] checkOutPublicKey = new byte[] {
6, 2, 0, 0, 0, 164, 0, 0, 82, 83, 65, 49, 0, 4, 0, 0, 1, 0, 1, 0,
7, 105, 10, 2, 211, 45, 205, 132, 125, 171, 116, 229, 229, 239, 102, 140, 168, 36, 227, 87,
73, 169, 75, 240, 204, 84, 52, 105, 229, 35, 185, 213, 226, 150, 134, 42, 221, 211, 82, 100,
61, 200, 142, 250, 25, 161, 70, 164, 195, 235, 116, 188, 176, 102, 1, 154, 6, 82, 115, 75,
37, 22, 111, 175, 200, 211, 96, 152, 201, 248, 10, 138, 128, 87, 35, 58, 217, 52, 0, 157,
186, 135, 89, 123, 215, 151, 24, 46, 114, 134, 88, 156, 128, 174, 252, 200, 63, 115, 206, 133,
154, 127, 248, 91, 35, 67, 203, 114, 42, 254, 235, 41, 150, 91, 75, 141, 63, 87, 76, 88,
56, 174, 116, 197, 184, 235, 241, 156};

        /// <summary>
        /// <Viegrid.Security Public key, Size = 1024/>
        /// </summary>
        private byte[] ViebooksPublicKey = new byte[] {
6, 2, 0, 0, 0, 164, 0, 0, 82, 83, 65, 49, 0, 4, 0, 0, 1, 0, 1, 0,
133, 233, 87, 201, 251, 100, 149, 168, 232, 254, 238, 85, 151, 99, 29, 209, 120, 15, 246, 227,
138, 42, 240, 157, 219, 8, 226, 89, 126, 128, 179, 239, 206, 15, 50, 132, 229, 108, 226, 252,
4, 249, 75, 154, 3, 78, 65, 51, 250, 195, 218, 219, 141, 194, 105, 229, 158, 159, 99, 188,
37, 133, 89, 133, 27, 244, 10, 64, 188, 170, 244, 41, 69, 214, 20, 38, 94, 73, 20, 49,
169, 119, 66, 228, 77, 130, 92, 174, 151, 201, 49, 160, 95, 208, 229, 194, 96, 216, 2, 58,
17, 222, 113, 201, 153, 111, 109, 220, 122, 183, 35, 136, 16, 5, 4, 10, 190, 60, 219, 178,
20, 106, 35, 151, 101, 196, 53, 160};

        /// <summary>
        /// <OtherSystem Public key, Size = 1024/>
        /// </summary>
        public byte[] OtherSystemPublicKey { get; set; }
        #endregion

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

        #region Encrypt and Decrypt

        //Mã hóa một string trả về Base64String
        public string EncryptToBase64String(string data, Viegrid.Security.PublicKeySystem publicKeySystem)
        {
            byte[] plainbuffer = System.Text.Encoding.UTF8.GetBytes(data);

            byte[] encryptbuffer = Encrypt(plainbuffer, publicKeySystem);

            return System.Convert.ToBase64String(encryptbuffer);
        }

        //Mã hóa dữ liệu nhiều khối
        public byte[] Encrypt(byte[] data, Viegrid.Security.PublicKeySystem publicKeySystem)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //Chose where place to send data
            if (publicKeySystem == Viegrid.Security.PublicKeySystem.CheckOut)
                rsa.ImportCspBlob(checkOutPublicKey);
            else
                if (publicKeySystem == Viegrid.Security.PublicKeySystem.vtcafes)
                    rsa.ImportCspBlob(vtcafesPublicKey);
                else
                    if (publicKeySystem == Viegrid.Security.PublicKeySystem.OtherSystem)
                        rsa.ImportCspBlob(OtherSystemPublicKey);
                    else
                        rsa.ImportCspBlob(ViebooksPublicKey);

            int block = (data.Length % DECRYPT_BLOCK != 0) ? data.Length / DECRYPT_BLOCK + 1 : data.Length / DECRYPT_BLOCK;
            int length = (block == 0) ? DATA_BLOCK : block * DATA_BLOCK;
            byte[] eData = new byte[length];
            int i1 = 0, i2 = 0;
            for (int i = 0; i < block - 1; i++)
            {
                byte[] t = new byte[DECRYPT_BLOCK];
                for (int j = 0; j < DECRYPT_BLOCK; j++)
                {
                    t[j] = data[i1++];
                }
                foreach (byte item in rsa.Encrypt(t, false))
                {
                    eData[i2++] = item;
                }
            }
            byte[] t1 = new byte[data.Length % DECRYPT_BLOCK];
            for (int i = 0; i < t1.Length; i++)
            {
                t1[i] = data[i1++];
            }
            // Encrypt the last block
            byte[] lastBlock = rsa.Encrypt(t1, false);
            for (int i = 0; i < lastBlock.Length; i++)
            {
                eData[i2++] = lastBlock[i];
            }

            return eData;
        }

        //Giải nén dữ liệu từ Base64String về string
        public string DecryptFromBase64String(string base64)
        {
            //get byte array from base64 string
            byte[] edata = System.Convert.FromBase64String(base64);

            //Decrypt edata
            byte[] pdata = Decrypt(edata);
            //Convert byte array to string and return string
            return System.Text.Encoding.UTF8.GetString(pdata);
        }

        //Giải nén dữ liệu gồm nhiều khối
        public byte[] Decrypt(byte[] data)
        {
            try
            {
                //Khởi tạo và nạp khóa
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportCspBlob(privateKey);
                // Nếu độ dài dữ liệu ko là số nguyên lần của DATA_BLOCK
                if (data.Length % DATA_BLOCK != 0)
                {
                    throw new Exception("Can't decrypt, invalid data length.");
                }

                //Khởi tạo số block
                int block = data.Length / DATA_BLOCK;
                // biến chỉ số index của byte đang thao tác của data. 
                // Ban đầu lấy chỉ số đầu của block cuối cùng
                int index = (block - 1) * DATA_BLOCK;
                //Mảng tạm t chứa dữ liệu trong mỗi khối. Dùng màng này để là biến chứa dữ liệu mã hóa trong mỗi khối.
                byte[] t = new byte[DATA_BLOCK];

                for (int i = 0; i < DATA_BLOCK; i++)
                    t[i] = data[index++];


                byte[] plain;
                // Độ dài mảng byte chứa dữ liệu sau khi giải nén.
                int length = DECRYPT_BLOCK * (block - 1) + rsa.Decrypt(t, false).Length;
                // plain: lưu dữ liệu sau khi giải nén
                plain = new byte[length];
                index = 0;
                int index_1 = 0; // bien chay cho plain
                // Giải nén từng block một
                for (int i = 0; i < block; i++)
                {
                    // truyen gia tri cho bien tam t
                    for (int j = 0; j < DATA_BLOCK; j++)
                        t[j] = data[index++];
                    // luu block khi da giai nen vao plain
                    foreach (byte item in rsa.Decrypt(t, false))
                    {
                        plain[index_1++] = item;
                    }
                }
                return plain;
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region Sign

        // Ký và trả về chữ ký dạng base64string
        public string Base64Sign(params object[] pars)
        {
            //Group data
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            foreach (var item in pars)
            {
                sb.Append(item);
            }
            byte[] data = new System.Text.UTF8Encoding().GetBytes(sb.ToString());

            //Make sign for data
            byte[] buffer = Sign(data);
            return System.Convert.ToBase64String(buffer);
        }

        // Ký và trả về chữ ký dạng byte[]
        public byte[] Sign(byte[] data)
        {
            //Initiate Crypto Service
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(privateKey);
            return rsa.SignData(data, new SHA1CryptoServiceProvider());
        }
        #endregion

        #region Verify
        public bool Verify(byte[] sign, Viegrid.Security.PublicKeySystem publicKeySystem, byte[] data)
        {
            try
            {
                //Initiate Crypto Service
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                if (publicKeySystem == Viegrid.Security.PublicKeySystem.CheckOut)
                    rsa.ImportCspBlob(checkOutPublicKey);
                else
                    if (publicKeySystem == Viegrid.Security.PublicKeySystem.vtcafes)
                        rsa.ImportCspBlob(vtcafesPublicKey);
                    else
                        if (publicKeySystem == Viegrid.Security.PublicKeySystem.OtherSystem)
                            rsa.ImportCspBlob(OtherSystemPublicKey);
                        else
                            rsa.ImportCspBlob(ViebooksPublicKey);
                //xac thuc
                return rsa.VerifyData(data, new SHA1CryptoServiceProvider(), sign);
            }
            catch
            {
                return false;
            }
        }

        //Xác thực tham số dữ liệu
        public bool Verify(string Base64sign, Viegrid.Security.PublicKeySystem publicKeySystem, params object[] data)
        {
            try
            {
                //Gop DL thanh một khối
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                foreach (var item in data)
                    sb.Append(item);
                //Chuyển về byte array
                byte[] dataBuffer = new System.Text.UTF8Encoding().GetBytes(sb.ToString());
                //Chuyển chữ ký về mảng byte
                byte[] signBuffer = System.Convert.FromBase64String(Base64sign);
                //xác thực
                return Verify(signBuffer, publicKeySystem, dataBuffer);
            }
            catch
            {
                return false;
            }
        }
        #endregion

        public string ExportPublicKey()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(privateKey);
            var base64 = Convert.ToBase64String(rsa.ExportCspBlob(false));
            return base64;
        }
    }
}
