using System;

namespace RsaAndAes
{
    class Program
    {
        static void Main(string[] args)
        {
            testAes();

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
    }
}
