using System;
using System.Security.Cryptography.X509Certificates;

namespace Hash.PBKDF2
{
    class Program
    {
        static void Main(string[] args)
        {
            var hasher = new Pbkdf2Hasher(1000);

            string salt = "";
            do
            {
                Console.Write("Salt (8 digit): ");
                salt = Console.ReadLine();

            } while (salt != null && salt.Length != 8);


            Console.Write("Word : ");
            var word = Console.ReadLine();
            Console.Write("Hashed value {0}", hasher.Hash(word, salt));
        }
    }
}
