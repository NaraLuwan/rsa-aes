using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace RsaAndAes
{
    public class RsaUtils
    {
        // 2010
        private static string PRIVATE_KEY = @"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC1f0xSc8UyzldsIA2v9OHNfKGwtRzt7oOfMyXplPqQQopcq92Y
VEoSs0FXhlRDMDpPgc603TDmg2h7OId3VrNu98S+TDdX0fl57EamcmSlxX5yNvqq
+KKhCg7/I9Wj0DaGRi3lHS2W2s7r9d/k3eeB7hejsZ9s1YoGEp5iRLfoRwIDAQAB
AoGAKFpMMszQnFIqN70MrgFpLtG19V7fNrtgAkZR+JQJ/Yb90krX8uVSrsOyFG6m
T2XqoQDAX5AKLkYrNbJE1DCvpez75drG+e5WT8jUG/cGRdNts5g0GTviPduBhZj1
jn7PFMizEXzu/2s4uFmjwSEA8kzf7WioF/iz91cUcHnqLjkCQQDwpXj+GExPoZWi
p/HDG09QzVPTbsR0wHDkNPzoqIrv1U/JkbQ4bsreMPbO6sEln5Mp+qlMlJQM7MyA
y4cHjcQ7AkEAwRO7Cq0huoZypdwdFAYV7frfoi+VoIxMDVYCifiXs6N5Jd+0tvyZ
UELi/zbeqOga8CMxTjqSNkOoGKc0cuWnZQJBAIz0L4mNy+z8tXv/qSFh9rRagFYg
1FuaeMWCr/zK9A6EwGZNvOUtKBC7V2VdpeKWtIlrNA0SHiHv9d0e2am4BQ8CQGhO
TXS2FYucCKHb6QWhSAWZy2jmBhKG2Ks3tQVufB37CX7RfOKCUh0PFWzE6sMbKTpj
+MYHVGfmYxB2fBo6QRUCQDCqUuXTOo718rU9SLECyG+LOVlQK4HGleePGc1K3X0m
zeNi/BHGLEwIDY0GBbvIFrOzlSyiv5EmMqnP+JvP3xQ=
-----END RSA PRIVATE KEY-----";

        /**
         * 私钥解密
         */
        public static string DecryptWithPrivate(string base64Input)
        {
            return DecryptWithPrivate(base64Input, PRIVATE_KEY);
        }

        /**
         * 私钥加密
         */
        public static string EncryptWithPrivate(string base64Input)
        {
            return EncryptWithPrivate(base64Input, PRIVATE_KEY);
        }

        /**
        * 私钥解密,需注意的是这里的PEM 私钥文件是PKCS1格式，而Java中的是PKCS8格式
        */
        public static string DecryptWithPrivate(string base64Input, string privateKey)
        {
            string priXml = RsaKeyConvert.PrivateKeyPkcs1ToXml(privateKey);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] cipherbytes;
            rsa.FromXmlString(priXml);
            cipherbytes = rsa.Decrypt(Convert.FromBase64String(base64Input), false);

            return Encoding.UTF8.GetString(cipherbytes);
        }

        /// <summary>
        /// 用私钥给数据进行RSA加密
        /// </summary>
        /// <param name="xmlPrivateKey"> 私钥(XML格式字符串)</param>
        /// <param name="strEncryptString"> 要加密的数据 </param>
        /// <returns> 加密后的数据 </returns>
        public static string EncryptWithPrivate(string strEncryptString, string privateKey)
        {
            string priXml = RsaKeyConvert.PrivateKeyPkcs1ToXml(privateKey);
            //加载私钥
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider();
            privateRsa.FromXmlString(priXml);

            //转换密钥
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding"); //使用RSA/ECB/PKCS1Padding格式
                                                                                   //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥

            c.Init(true, keyPair.Private);
            byte[] DataToEncrypt = Encoding.UTF8.GetBytes(strEncryptString);
            byte[] outBytes = c.DoFinal(DataToEncrypt);//加密
            string strBase64 = Convert.ToBase64String(outBytes);

            return strBase64;
        }
    }
}
