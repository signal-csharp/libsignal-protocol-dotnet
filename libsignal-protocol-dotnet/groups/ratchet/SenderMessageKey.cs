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

using System.Text;
using libsignal.kdf;
using libsignal.util;

namespace libsignal.groups.ratchet
{
    /// <summary>
    /// The final symmetric material (IV and Cipher Key) used for encrypting individual SenderKey messages.
    /// </summary>
    public class SenderMessageKey
    {

        private readonly uint iteration;
        private readonly byte[] iv;
        private readonly byte[] cipherKey;
        private readonly byte[] seed;

        public SenderMessageKey(uint iteration, byte[] seed)
        {
            byte[] derivative = new HKDFv3().deriveSecrets(seed, Encoding.UTF8.GetBytes("WhisperGroup"), 48);
            byte[][] parts = ByteUtil.split(derivative, 16, 32);

            this.iteration = iteration;
            this.seed = seed;
            this.iv = parts[0];
            this.cipherKey = parts[1];
        }

        public uint getIteration()
        {
            return iteration;
        }

        public byte[] getIv()
        {
            return iv;
        }

        public byte[] getCipherKey()
        {
            return cipherKey;
        }

        public byte[] getSeed()
        {
            return seed;
        }
    }
}
