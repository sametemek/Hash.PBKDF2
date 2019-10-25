using System;

namespace Hash.PBKDF2
{
    class Program
    {
        static void Main(string[] args)
        {
            var hasher = new Pbkdf2Hasher(1000);

            var hashedValue = hasher.Hash("samet","samplesalt");

            var isEqual = hasher.Validate("samet", "samplesalt", hashedValue);
        }
    }
}
