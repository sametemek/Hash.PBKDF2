using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hash.PBKDF2
{
    public class Pbkdf2Hasher : IHasher
    {
        private readonly int _defaultSaltByteSize;
        private readonly int _hashByteSize; // to match the size of the PBKDF2-HMAC-SHA-1 hash 
        private readonly int _pbkdf2Iterations;

        public Pbkdf2Hasher(int pbkdf2Iterations = 1000, int hastByteSize = 20, int defaultDefaultSaltByteSize = 24)
        {
            this._pbkdf2Iterations = pbkdf2Iterations;
            this._defaultSaltByteSize = defaultDefaultSaltByteSize;
            this._hashByteSize = hastByteSize;
        }

        public string Hash(string word, string salt)
        {
            var saltBytes = salt == null ? GenerateSalt() : Encoding.ASCII.GetBytes(salt);
            var hash = GetPbkdf2Bytes(word, saltBytes, _pbkdf2Iterations, _hashByteSize);
            return Convert.ToBase64String(hash);
        }

        public bool Validate(string word, string salt, string hash)
        {
            var saltBytes = Encoding.ASCII.GetBytes(salt);
            var hashBytes = Convert.FromBase64String(hash);
            var testHash = GetPbkdf2Bytes(word, saltBytes, _pbkdf2Iterations, hashBytes.Length);
            return SlowEquals(hashBytes, testHash);
        }

        private byte[] GenerateSalt()
        {
            var cryptoProvider = new RNGCryptoServiceProvider();
            var saltBytes = new byte[_defaultSaltByteSize];
            cryptoProvider.GetBytes(saltBytes);
            return saltBytes;
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
