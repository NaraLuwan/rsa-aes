using System;

namespace RsaAndAes
{
    class Program
    {
        static void Main(string[] args)
        {
            // testAes();

             testRsa();

            // testRsaKeyConvert();

            Console.Read();
        }

        public static void testAes()
        {
            try
            {
                string originalStr = "Hello AES!";
                string aesKey = "testKey!testKey!";
                Console.WriteLine("originalStr:   {0}", originalStr);

                byte[] encrypted = AesUtils.EncryptStringToBytes(originalStr, aesKey);
                string decryptStr = AesUtils.DecryptStringFromBytes(encrypted, aesKey);

                Console.WriteLine("decryptStr: {0}", decryptStr);
            }

            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        public static void testRsa()
        {
            string originalStr = "Hello RSA!";
            string encryptStr = RsaUtils.EncryptWithPrivate(originalStr);
            Console.WriteLine(encryptStr);

            //string decryptStr = RsaUtils.DecryptWithPrivate(encryptStr);
            //Console.WriteLine(decryptStr);
        }

        public static void testRsaKeyConvert() 
        {
            string publicKeySC8 = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1f0xSc8UyzldsIA2v9OHNfKGw
tRzt7oOfMyXplPqQQopcq92YVEoSs0FXhlRDMDpPgc603TDmg2h7OId3VrNu98S +
TDdX0fl57EamcmSlxX5yNvqq + KKhCg7 / I9Wj0DaGRi3lHS2W2s7r9d / k3eeB7hej
sZ9s1YoGEp5iRLfoRwIDAQAB
---- - END PUBLIC KEY-----";
            string privateKeySC8 = @"-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALV/TFJzxTLOV2wg
Da/04c18obC1HO3ug58zJemU+pBCilyr3ZhUShKzQVeGVEMwOk+BzrTdMOaDaHs4
h3dWs273xL5MN1fR+XnsRqZyZKXFfnI2+qr4oqEKDv8j1aPQNoZGLeUdLZbazuv1
3+Td54HuF6Oxn2zVigYSnmJEt+hHAgMBAAECgYAoWkwyzNCcUio3vQyuAWku0bX1
Xt82u2ACRlH4lAn9hv3SStfy5VKuw7IUbqZPZeqhAMBfkAouRis1skTUMK+l7Pvl
2sb57lZPyNQb9wZF022zmDQZO+I924GFmPWOfs8UyLMRfO7/azi4WaPBIQDyTN/t
aKgX+LP3VxRweeouOQJBAPCleP4YTE+hlaKn8cMbT1DNU9NuxHTAcOQ0/Oioiu/V
T8mRtDhuyt4w9s7qwSWfkyn6qUyUlAzszIDLhweNxDsCQQDBE7sKrSG6hnKl3B0U
BhXt+t+iL5WgjEwNVgKJ+Jezo3kl37S2/JlQQuL/Nt6o6BrwIzFOOpI2Q6gYpzRy
5adlAkEAjPQviY3L7Py1e/+pIWH2tFqAViDUW5p4xYKv/Mr0DoTAZk285S0oELtX
ZV2l4pa0iWs0DRIeIe/13R7ZqbgFDwJAaE5NdLYVi5wIodvpBaFIBZnLaOYGEobY
qze1BW58HfsJftF84oJSHQ8VbMTqwxspOmP4xgdUZ+ZjEHZ8GjpBFQJAMKpS5dM6
jvXytT1IsQLIb4s5WVArgcaV548ZzUrdfSbN42L8EcYsTAgNjQYFu8gWs7OVLKK/
kSYyqc/4m8/fFA==
-----END PRIVATE KEY-----";

            string privateKeySC1 = RsaKeyConvert.PrivateKeyPkcs8ToPkcs1(privateKeySC8);
            Console.WriteLine(privateKeySC1);
        }
    }
}
