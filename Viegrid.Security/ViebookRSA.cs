using System;
using System.Security.Cryptography;
namespace Viegrid.Security
{
    public class ViebookRSA
    {
        #region Key này để mã hóa các sách trong file server
        private static byte[] ViebookKey = new byte[] { 27, 31, 35, 58, 61, 155, 172, 210, 179, 218, 216, 119, 223, 215, 16, 196, 192, 146, 71, 73, 91, 96, 193, 138, 189, 211, 64, 54, 70, 84, 50, 25, 250, 109, 203, 36, 155, 59, 51, 36, 196, 124, 180, 77, 88, 38, 233, 227, 134, 192, 227, 114, 253, 241, 107, 186, 93, 152, 124, 104, 90, 118, 139, 94, 168, 191, 124, 113, 12, 235, 41, 132, 94, 35, 131, 222, 170, 115, 49, 151, 232, 92, 174, 133, 111, 190, 27, 8, 2, 17, 198, 2, 190, 201, 200, 78, 240, 86, 163, 152, 168, 120, 214, 154, 151, 94, 19, 218, 110, 140, 15, 232, 102, 227, 126, 253, 198, 6, 237, 233, 163, 115, 110, 250, 37, 38, 197, 148, 89, 53, 236, 84, 207, 151, 237, 112, 132, 19, 236, 17, 170, 64, 153, 116, 1, 220, 155, 217, 74, 202, 134, 233, 103, 185, 244, 52, 9, 219, 117, 113, 151, 126, 128, 57, 158, 186, 25, 205, 244, 13, 121, 178, 24, 220, 62, 99, 217, 249, 248, 71, 138, 235, 73, 142, 173, 2, 235, 22, 162, 184, 103, 168, 157, 123, 120, 44, 190, 96, 213, 70, 194, 204, 227, 60, 81, 210, 208, 138, 122, 144, 89, 15, 225, 45, 229, 171, 52, 241, 138, 155, 205, 3, 43, 60, 165, 207, 21, 156, 100, 18, 163, 121, 35, 178, 132, 188, 8, 13, 60, 217, 49, 96, 154, 17, 95, 88, 198, 111, 148, 203, 246, 204, 212, 57, 119, 191, 161, 167, 150, 128, 189, 52, 38, 104, 236, 223, 234, 46, 168, 41, 163, 39, 180, 175, 106, 109, 104, 25, 220, 76, 9, 165, 7, 151, 26, 214, 164, 233, 58, 195, 27, 95, 117, 187, 28, 251, 58, 49, 36, 126, 109, 151, 197, 107, 40, 207, 23, 36, 205, 10, 87, 135, 202, 74, 118, 24, 44, 141, 78, 22, 58, 0, 242, 227, 13, 67, 176, 247, 147, 109, 50, 55, 244, 93, 221, 113, 222, 155, 111, 73, 190, 127, 27, 48, 108, 146, 148, 43, 68, 4, 207, 171, 225, 13, 68, 109, 163, 224, 93, 228, 30, 30, 144, 95, 214, 32, 146, 109, 107, 5, 57, 144, 30, 4, 87, 186, 227, 194, 119, 122, 173, 133, 178, 143, 157, 134, 84, 230, 24, 112, 204, 252, 61, 138, 43, 159, 237, 187, 88, 76, 254, 39, 191, 63, 202, 63, 141, 220, 181, 136, 136, 223, 105, 226, 54, 152, 106, 1, 192, 80, 202, 170, 84, 249, 55, 59, 82, 147, 216, 182, 203, 40, 105, 43, 122, 134, 196, 115, 196, 94, 247, 119, 49, 143, 231, 236, 147, 90, 83, 145, 52, 236, 249, 8, 128, 83, 210, 196, 8, 142, 235, 248, 3, 253, 187, 95, 117, 61, 104, 175, 210, 246, 60, 98, 87, 83, 121, 196, 17, 74, 167, 246, 63, 71, 130, 222, 46, 97, 169, 38, 178, 254, 107, 53, 113, 254, 115, 51, 210, 136, 118, 85, 240, 163, 189, 61, 175, 150, 175, 45, 217, 14, 179, 188, 230, 244, 185, 187, 123, 220, 48, 19, 147, 66, 251, 211, 139, 6, 239, 88, 222, 70, 240, 136, 210, 81, 5, 155, 136, 68, 46, 150, 177, 124, 75, 164, 75, 173, 78, 124, 69, 183, 182, 244, 87, 98, 193, 174, 166, 233, 177, 169, 166, 86, 78, 147, 28, 42, 232, 148, 238, 29, 50, 54, 173, 153, 97, 22, 245, 87, 135, 220, 183, 114, 19, 38, 142, 251, 49, 112, 143, 86, 243, 158, 146, 132, 238, 90, 45, 183, 136, 33, 195, 185, 141, 39, 132, 128, 71, 188, 1, 170, 184, 79, 97, 211, 240, 52, 67, 39, 4, 32, 247, 120, 4, 151, 40, 147, 162, 40, 169, 6, 231, 61, 205, 102, 25, 253, 227, 234, 160, 13, 179, 115, 111, 227, 156, 164, 60, 190, 147, 186, 23, 6, 178, 103, 40, 75, 180, 244, 254, 240, 221, 30, 19, 249, 193, 122, 128, 250, 186, 242, 79, 87, 133, 246, 107, 132, 8, 32, 250, 130, 87, 226, 148, 237, 238, 225, 137, 102, 61, 204, 72, 238, 235, 175, 47, 148, 96, 117, 34, 33, 35, 64, 4, 159, 107, 190, 127, 187, 251, 163, 66, 148, 249, 123, 152, 249, 137, 36, 10, 223, 239, 26, 188, 236, 169, 96, 107, 213, 198, 213, 35, 146, 252, 216, 95, 22, 222, 243, 130, 47, 97, 205, 105, 153, 138, 179, 243, 112, 22, 53, 11, 59, 106, 65, 48, 9, 130, 22, 244, 10, 83, 169, 244, 37, 127, 174, 150, 32, 28, 130, 26, 148, 161, 218, 125, 34, 175, 35, 98, 245, 107, 249, 190, 145, 202, 231, 40, 186, 167, 85, 147, 199, 254, 119, 219, 182, 216, 68, 25, 218, 29, 210, 84, 147, 26, 117, 153, 142, 195, 14, 88, 95, 179, 254, 158, 88, 234, 99, 90, 150, 133, 218, 120, 197, 237, 81, 149, 41, 254, 197, 73, 107, 9, 134, 216, 151, 165, 42, 118, 84, 78, 153, 246, 153, 252, 52, 20, 254, 216, 130, 203, 116, 232, 129, 85, 65, 90, 141, 164, 199, 223, 111, 143, 252, 195, 235, 85, 45, 38, 6, 178, 191, 235, 6, 72, 235, 227, 221, 200, 185, 61, 149, 79, 123, 249, 211, 129, 134, 49, 150, 60, 24, 133, 173, 115, 221, 9, 249, 212, 16, 221, 230, 216, 210, 207, 11, 136, 226, 57, 104, 93, 124, 196, 233, 138, 73, 32, 19, 2, 239, 105, 205, 250, 142, 200, 153, 58, 62, 145, 105, 226, 233, 8, 183, 219, 86, 188, 124, 171, 238, 75, 158, 77, 199, 57, 191, 83, 154, 34, 41, 189, 244, 246, 228, 165, 16, 234, 74, 9, 53, 208, 73, 81, 206, 133, 115, 115, 12, 14, 51, 140, 162, 103, 19, 163, 202, 127, 51, 84, 8, 70, 158, 27, 103, 171, 236, 241, 35, 18, 202, 107, 114, 114, 118, 29, 1, 76, 125, 66, 197, 76, 70, 140, 237, 155, 26, 141, 226, 64, 217, 143, 182, 244, 0, 237, 49, 45, 232, 35, 151, 128, 79 };
        #endregion
        public static byte[] Encrypt(byte[] keyData, byte[] plainData)
        {
            if (keyData == null || plainData == null)
                throw new Exception("keyData or sourceDate can not be null");

            for (int i = 0; i < plainData.Length; i++)
                plainData[i] = (byte)((int)(plainData[i] + keyData[i % keyData.Length]) % ((int)byte.MaxValue + 1));
            return plainData;
        }
        public static byte[] Decrypt(byte[] keyData, byte[] encryptedData)
        {
            if (keyData == null || encryptedData == null)
                throw new Exception("keyData or sourceDate can not be null");

            for (int i = 0; i < encryptedData.Length; i++)
                encryptedData[i] = (byte)((int)((int)byte.MaxValue + 1 + encryptedData[i] - keyData[i % keyData.Length]) % ((int)byte.MaxValue + 1));

            return encryptedData;
        }

        public static byte[] Decrypt(byte[] encryptedData)
        {
            return Decrypt(ViebookKey, encryptedData);
        }

        public static byte[] Encrypt(byte[] encryptedData)
        {
            return Encrypt(ViebookKey, encryptedData);
        }
    }

    public class CryptLib
    {
        /*****************************************************************
         * CrossPlatform CryptLib
         * 
         * <p>
         * This cross platform CryptLib uses AES 256 for encryption. This library can
         * be used for encryptoion and de-cryption of string on iOS, Android and Windows
         * platform.<br/>
         * Features: <br/>
         * 1. 256 bit AES encryption
         * 2. Random IV generation. 
         * 3. Provision for SHA256 hashing of key. 
         * </p>
         * 
         * @since 1.0
         * @author viegrid
         *****************************************************************/
        System.Text.UTF8Encoding _enc;
        RijndaelManaged _rcipher;
        byte[] _key, _pwd, _ivBytes, _iv;

        /***
         * Encryption mode enumeration
         */
        private enum EncryptMode { ENCRYPT, DECRYPT };

        static readonly char[] CharacterMatrixForRandomIVStringGeneration = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
		};

        /**
         * This function generates random string of the given input length.
         * 
         * @param _plainText
         *            Plain text to be encrypted
         * @param _key
         *            Encryption Key. You'll have to use the same key for decryption
         * @return returns encrypted (cipher) text
         */
        public static string GenerateRandomIV(int length)
        {
            char[] _iv = new char[length];
            byte[] randomBytes = new byte[length];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes); //Fills an array of bytes with a cryptographically strong sequence of random values. 
            }

            for (int i = 0; i < _iv.Length; i++)
            {
                int ptr = randomBytes[i] % CharacterMatrixForRandomIVStringGeneration.Length;
                _iv[i] = CharacterMatrixForRandomIVStringGeneration[ptr];
            }

            return new string(_iv);
        }

        public CryptLib()
        {
            _enc = new System.Text.UTF8Encoding();
            _rcipher = new RijndaelManaged();
            _rcipher.Mode = CipherMode.CBC;
            _rcipher.Padding = PaddingMode.PKCS7;
            _rcipher.KeySize = 256;
            _rcipher.BlockSize = 128;
            _key = new byte[32];
            _iv = new byte[_rcipher.BlockSize / 8]; //128 bit / 8 = 16 bytes
            _ivBytes = new byte[16];
        }

        /**
         * 
         * @param _inputText
         *            Text to be encrypted or decrypted
         * @param _encryptionKey
         *            Encryption key to used for encryption / decryption
         * @param _mode
         *            specify the mode encryption / decryption
         * @param _initVector
         * 			  initialization vector
         * @return encrypted or decrypted string based on the mode
        */
        private byte[] doEncryptDecrypt(byte[] _inputText, string _encryptionKey, EncryptMode _mode, string _initVector)
        {

            byte[] _out = _inputText;// output string
            //_encryptionKey = MD5Hash (_encryptionKey);
            _pwd = System.Text.Encoding.UTF8.GetBytes(_encryptionKey);
            _ivBytes = System.Text.Encoding.UTF8.GetBytes(_initVector);

            int len = _pwd.Length;
            if (len > _key.Length)
            {
                len = _key.Length;
            }
            int ivLenth = _ivBytes.Length;
            if (ivLenth > _iv.Length)
            {
                ivLenth = _iv.Length;
            }

            Array.Copy(_pwd, _key, len);
            Array.Copy(_ivBytes, _iv, ivLenth);
            _rcipher.Key = _key;
            _rcipher.IV = _iv;

            if (_mode.Equals(EncryptMode.ENCRYPT))
            {
                //encrypt
                //byte[] plainText = _rcipher.CreateEncryptor().TransformFinalBlock(_enc.GetBytes(_inputText), 0, _inputText.Length);
                _out = _rcipher.CreateEncryptor().TransformFinalBlock(_inputText, 0, _inputText.Length);
                //_out = Convert.ToBase64String(plainText);
            }
            if (_mode.Equals(EncryptMode.DECRYPT))
            {
                //decrypt
                //byte[] plainText = _rcipher.CreateDecryptor().TransformFinalBlock(Convert.FromBase64String(_inputText), 0, Convert.FromBase64String(_inputText).Length);
                _out = _rcipher.CreateDecryptor().TransformFinalBlock(_inputText, 0, _inputText.Length);
                //_out = _enc.GetString(plainText);
            }
            _rcipher.Dispose();
            return _out;// return encrypted/decrypted string
        }

        /**
         * This function encrypts the plain text to cipher text using the key
         * provided. You'll have to use the same key for decryption
         * 
         * @param _plainText
         *            Plain text to be encrypted
         * @param _key
         *            Encryption Key. You'll have to use the same key for decryption
         * @return returns encrypted (cipher) text
         */
        public string encrypt(string _plainText, string _key, string _initVector)
        {
            return Convert.ToBase64String(doEncryptDecrypt(new System.Text.UTF8Encoding().GetBytes(_plainText), _key, EncryptMode.ENCRYPT, _initVector));
        }
        public byte[] encrypt(byte[] _plainText, string _key, string _initVector)
        {
            return doEncryptDecrypt(_plainText, _key, EncryptMode.ENCRYPT, _initVector);
        }

        /***
         * This funtion decrypts the encrypted text to plain text using the key
         * provided. You'll have to use the same key which you used during
         * encryprtion
         * 
         * @param _encryptedText
         *            Encrypted/Cipher text to be decrypted
         * @param _key
         *            Encryption key which you used during encryption
         * @return encrypted value
         */
        public string decrypt(string _encryptedText, string _key, string _initVector)
        {
            return new System.Text.UTF8Encoding().GetString(doEncryptDecrypt(Convert.FromBase64String(_encryptedText), _key, EncryptMode.DECRYPT, _initVector));
        }
        public byte[] decrypt(byte[] _encryptedText, string _key, string _initVector)
        {
            return doEncryptDecrypt(_encryptedText, _key, EncryptMode.DECRYPT, _initVector);
        }

        /***
         * This function decrypts the encrypted text to plain text using the key
         * provided. You'll have to use the same key which you used during
         * encryption
         * 
         * @param _encryptedText
         *            Encrypted/Cipher text to be decrypted
         * @param _key
         *            Encryption key which you used during encryption
         */
        public static string getHashSha256(string text, int length)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x); //covert to hex string
            }
            if (length > hashString.Length)
                return hashString;
            else
                return hashString.Substring(0, length);
        }

        //this function is no longer used.
        private static string MD5Hash(string text)
        {
            System.Security.Cryptography.MD5 md5 = new MD5CryptoServiceProvider();

            //compute hash from the bytes of text
            md5.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(text));

            //get hash result after compute it
            byte[] result = md5.Hash;

            System.Text.StringBuilder strBuilder = new System.Text.StringBuilder();
            for (int i = 0; i < result.Length; i++)
            {
                //change it into 2 hexadecimal digits
                //for each byte
                strBuilder.Append(result[i].ToString("x2"));
            }
            Console.WriteLine("md5 hash of they key=" + strBuilder.ToString());
            return strBuilder.ToString();
        }

    }
}