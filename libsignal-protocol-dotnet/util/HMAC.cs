/** 
 * Copyright (C) 2016 smndtrl, langboost
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
namespace libsignal.util
{
    public class Sign
    {
        public static byte[] sha256sum(byte[] key, byte[] message)
        {
            using (var mac = new HMACSHA256(key))
            {
                return mac.ComputeHash(message);
            }
        }
    }

    /// <summary>
    /// Encryption helpers
    /// </summary>
    public class Encrypt
    {
        /// <summary>
        /// Computes PKCS5 for the message
        /// </summary>
        /// <param name="message">plaintext</param>
        /// <returns>PKCS5 of the message</returns>
        public static byte[] aesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                using (var encrypt = aes.CreateEncryptor())
                {
                    return encrypt.TransformFinalBlock(message, 0, message.Length);
                }
            }
        }
    }

    /// <summary>
    /// Decryption helpers
    /// </summary>
    public class Decrypt
    {
        public static byte[] aesCbcPkcs5(byte[] message, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;
                if (message.Length % (aes.BlockSize/8) != 0) throw new Exception("Invalid ciphertext length");
                using (var decrypt = aes.CreateDecryptor())
                {
                    return decrypt.TransformFinalBlock(message, 0, message.Length);
                }
            }
        }
    }

    public static class CryptoHelper
    {
        /// <summary>
        /// TODO: dead code?
        /// </summary>
        public static void Shuffle<T>(this IList<T> list)
        {
            Random rng = new Random();
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }
}
