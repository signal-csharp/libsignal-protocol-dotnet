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

using libsignal.util;
using System;
using System.IO;

namespace libsignal.kdf
{
    public abstract class HKDF
    {

        private static readonly int HASH_OUTPUT_SIZE = 32;

        public static HKDF createFor(uint messageVersion)
        {
            switch (messageVersion)
            {
                case 2: return new HKDFv2();
                case 3: return new HKDFv3();
                default: throw new Exception("Unknown version: " + messageVersion);
            }
        }

        public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength)
        {
            byte[] salt = new byte[HASH_OUTPUT_SIZE];
            return deriveSecrets(inputKeyMaterial, salt, info, outputLength);
        }

        public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength)
        {
            byte[] prk = extract(salt, inputKeyMaterial);
            return expand(prk, info, outputLength);
        }

        private byte[] extract(byte[] salt, byte[] inputKeyMaterial)
        {
            try
            {
                return Sign.sha256sum(salt, inputKeyMaterial);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private byte[] expand(byte[] prk, byte[] info, int outputSize)
        {
            try
            {
                int iterations = (int)Math.Ceiling((double)outputSize / (double)HASH_OUTPUT_SIZE);
                byte[] mixin = new byte[0];
                MemoryStream results = new MemoryStream();
                int remainingBytes = outputSize;

                for (int i = getIterationStartOffset(); i < iterations + getIterationStartOffset(); i++)
                {
                    MemoryStream msg = new MemoryStream();
                    msg.Write(mixin, 0, mixin.Length);
                    if (info != null)
                    {
                        msg.Write(info, 0, info.Length);
                    }
                    byte[] ib = BitConverter.GetBytes(i);
                    msg.Write(ib, 0, 1);

                    byte[] stepResult = Sign.sha256sum(prk, msg.ToArray());
                    int stepSize = Math.Min(remainingBytes, stepResult.Length);

                    results.Write(stepResult, 0, stepSize);

                    mixin = stepResult;
                    remainingBytes -= stepSize;
                }

                return results.ToArray();
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        protected abstract int getIterationStartOffset();

    }
}
