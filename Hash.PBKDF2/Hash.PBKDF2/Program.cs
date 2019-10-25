﻿using System;

namespace Hash.PBKDF2
{
    class Program
    {
        static void Main(string[] args)
        {
            var hasher = new Pbkdf2Hasher(1000);

            var hashedValue = hasher.Hash("samplesalt","samet");

            var isEqual = hasher.Validate("samplesalt", "samet", hashedValue);
        }
    }
}