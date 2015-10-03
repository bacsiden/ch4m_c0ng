using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Viegrid.Security
{
    public static class RSAJava
    {
        private static string _jarRSALibsFullFilePath = "JavaLibs";

        public static bool CreateKey(string privateKeyFilePath, string publicKeyFilePath)
        {
            try
            {
                ExecuteJar(0, privateKeyFilePath, publicKeyFilePath, "", "", "", "");
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }

        public static bool Encrypt(string publicKeyFilePath, string sourceFilePath, string destinationFilePath)
        {
            try
            {
                ExecuteJar(1, "", publicKeyFilePath, sourceFilePath, destinationFilePath, "", "");
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }

        public static bool Decrypt(string privateKeyFilePath, string sourceFilePath, string destinationFilePath)
        {
            try
            {
                ExecuteJar(2, privateKeyFilePath, "", sourceFilePath, destinationFilePath, "", "");
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }

        public static bool Sign(string privateKeyFilePath, string dataToSignFilePath, string dataSignedFilePath)
        {
            try
            {
                ExecuteJar(3, privateKeyFilePath, "", "", "", dataToSignFilePath, dataSignedFilePath);
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }

        /// <summary>
        /// 0. Sinh cặp file khóa
        ///C:\>java -jar v_rsalib.jar 0 [private.key] [public.key]
        ///1.Mã hóa
        ///C:\>java -Dfile.encoding=UTF-8 -jar [v_rsalib.jar] 1 [dữ liệu vào.txt] [file mã hóa.enc] [private.key]
        ///2.Giải mã.
        ///C:\>java -Dfile.encoding=UTF-8 -jar [v_rsalib.jar] 2 [file mã hóa.enc] [file giải mã.txt] [private.key]
        ///3.Ký
        ///C:\>java -jar [v_rsalib.jar] 3 [file_cần_ký.txt] [private.key] [file_lưu_kết_quả.xml]
        ///4.Xác thực
        ///C:\>java -jar [v_rsalib.jar] 4 [public.key] [file_lưu_kết_quả_.xml]        
        /// </summary>
        private static void ExecuteJar(int command, string privateKeyFilePath, string publicKeyFilePath, string sourceFilePath, string destinationFilePath, string dataToSignFilePath, string dataSignedFilePath)
        {
            string argument = string.Empty;
            switch (command)
            {
                case 0:// - gen key
                    ///C:\>java -jar v_rsalib.jar 0 [private.key] [public.key]
                    argument = string.Format(" -jar {0} {1} {2} {3}", _jarRSALibsFullFilePath, command, publicKeyFilePath, privateKeyFilePath);
                    break;
                case 1:// - encrypt                    
                    ///C:\>java -Dfile.encoding=UTF-8 -jar [v_rsalib.jar] 1 [dữ liệu vào.txt] [file mã hóa.enc] [private.key]
                    argument = string.Format(" -Dfile.encoding=UTF-8 -jar {0} {1} {2} {3} {4}", _jarRSALibsFullFilePath, command, sourceFilePath, destinationFilePath, publicKeyFilePath);
                    break;
                case 2:// - decrypt                    
                    ///C:\>java -Dfile.encoding=UTF-8 -jar [v_rsalib.jar] 2 [file mã hóa.enc] [file giải mã.txt] [private.key]
                    argument = string.Format(" -Dfile.encoding=UTF-8 -jar {0} {1} {2} {3} {4}", _jarRSALibsFullFilePath, command, sourceFilePath, destinationFilePath, privateKeyFilePath);
                    break;
                case 3://Sign
                    ///C:\>java -jar [v_rsalib.jar] 3 [file_cần_ký.txt] [private.key] [file_lưu_kết_quả.xml]
                    argument = string.Format(" -jar {0} {1} {2} {3} {4}", _jarRSALibsFullFilePath,
                        command, dataToSignFilePath, privateKeyFilePath, dataSignedFilePath);
                    break;
                case 4://Verify
                    ///C:\>java -jar [v_rsalib.jar] 4 [public.key] [file_lưu_kết_quả_.xml]
                    break;
                default:
                    return;
            }
            System.Diagnostics.Process proc = new System.Diagnostics.Process();
            proc.StartInfo.FileName = "java";
            proc.StartInfo.Arguments = argument;
            proc.Start();

            while (!proc.HasExited) ;//Chờ cho tiến trình thực hiện xong

        }

        /*5. Cat file 
         * @param int command
         * @param size of file split
         * @param String source file
         * @param String destination file1 (Encryption)
         * @param String destination file2
         * @param String Public Key
         */
        public static bool SplitFile(string publicKeyFilePath, string sourceDataFilePath, string destinationEncryptFilePath, string destinationDataFilePath, int splitSize)
        {
            try
            {
                string argument = string.Empty;
                int command = 5;

                ///C:\>java -jar [*.jar file] [command] [split size] [source data file] [destination encrypt file] [destination data file] [public key file]
                argument = string.Format(" -jar {0} {1} {2} {3} {4} {5} {6}",
                    _jarRSALibsFullFilePath,
                    command,
                    splitSize,
                    sourceDataFilePath,
                    destinationEncryptFilePath,
                    destinationDataFilePath,
                    publicKeyFilePath);

                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo.FileName = "java";
                proc.StartInfo.Arguments = argument;
                proc.Start();
                while (!proc.HasExited) ;//Chờ cho tiến trình thực hiện xong
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }

        /*6. Ghep file
         * @param int command
         * @param String Source file1 (Encryption)
         * @param String Source file2
         * @param String Destination file
         * @param String Private Key
         */
        public static bool JoinFile(string privateKeyFilePath, string sourceDataFilePath, string sourceEncryptFilePath, string destinationDataFilePath)
        {
            try
            {
                string argument = string.Empty;
                int command = 6;

                ///C:\>java -jar [*.jar file] [command = 6] [source encrypt file] [source data file] [destination data file] [private key file]
                argument = string.Format(" -jar {0} {1} {2} {3} {4} {5}",
                    _jarRSALibsFullFilePath,
                    command,
                    sourceEncryptFilePath,
                    sourceDataFilePath,
                    destinationDataFilePath,
                    privateKeyFilePath);

                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo.FileName = "java";
                proc.StartInfo.Arguments = argument;
                proc.Start();
                while (!proc.HasExited) ;//Chờ cho tiến trình thực hiện xong
                return true;
            }
            catch (Exception ex)
            {
                return false;
                throw ex;
            }
        }
    }
}