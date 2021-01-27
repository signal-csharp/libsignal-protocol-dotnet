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

namespace libsignal.kdf
{
    public class DerivedMessageSecrets
    {

        public static readonly int SIZE = 80;
        private static readonly int CIPHER_KEY_LENGTH = 32;
        private static readonly int MAC_KEY_LENGTH = 32;
        private static readonly int IV_LENGTH = 16;

        private readonly byte[] cipherKey;
        private readonly byte[] macKey;
        private readonly byte[] iv;

        public DerivedMessageSecrets(byte[] okm)
        {
            //try
            //{
            byte[][] keys = ByteUtil.split(okm, CIPHER_KEY_LENGTH, MAC_KEY_LENGTH, IV_LENGTH);

            this.cipherKey = keys[0];
            this.macKey = keys[1];
            this.iv = keys[2];
            /*}
            catch (ParseException e)
            {
                throw new AssertionError(e);
            }*/
        }

        public byte[] getCipherKey()
        {
            return cipherKey;
        }

        public byte[] getMacKey()
        {
            return macKey;
        }

        public byte[] getIv()
        {
            return iv;
        }
    }
}
