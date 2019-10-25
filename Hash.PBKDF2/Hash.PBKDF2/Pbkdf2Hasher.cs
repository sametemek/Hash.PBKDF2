using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hash.PBKDF2
{
    public interface IHasher
    {
        string Hash(string salt, string word);
        bool Validate(string salt, string word, string hash);
    }

    public class Pbkdf2Hasher : IHasher
    {
        private readonly int _saltByteSize;
        private readonly int _hashByteSize; // to match the size of the PBKDF2-HMAC-SHA-1 hash 
        private readonly int _pbkdf2Iterations;

        public Pbkdf2Hasher(int pbkdf2Iterations = 1000)
        {
            this._pbkdf2Iterations = pbkdf2Iterations;
            this._saltByteSize = 24;
            this._hashByteSize = 20;
        }

        public string Hash(string salt, string word)
        {
            byte[] saltBytes;
            if (salt == null)
            {
                var cryptoProvider = new RNGCryptoServiceProvider();
                saltBytes = new byte[_saltByteSize];
                cryptoProvider.GetBytes(saltBytes);
            }
            else
            {
                saltBytes = Encoding.ASCII.GetBytes(salt);
            }

            var hash = GetPbkdf2Bytes(word, saltBytes, _pbkdf2Iterations, _hashByteSize);
            return Convert.ToBase64String(hash);
        }

        public bool Validate(string salt, string word, string hash)
        {
            var saltBytes = Encoding.ASCII.GetBytes(salt);
            var hashBytes = Convert.FromBase64String(hash);
            var testHash = GetPbkdf2Bytes(word, saltBytes, _pbkdf2Iterations, hashBytes.Length);
            return SlowEquals(hashBytes, testHash);
        }

        private bool SlowEquals(IReadOnlyList<byte> a, IReadOnlyList<byte> b)
        {
            var diff = (uint)a.Count ^ (uint)b.Count;
            for (int i = 0; i < a.Count && i < b.Count; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        private byte[] GetPbkdf2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt) { IterationCount = iterations };
            return pbkdf2.GetBytes(outputBytes);
        }
    }
}
