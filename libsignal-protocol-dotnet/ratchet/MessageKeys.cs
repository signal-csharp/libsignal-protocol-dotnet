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

namespace libsignal.ratchet
{
    public class MessageKeys
    {

        private readonly byte[] cipherKey;
        private readonly byte[] macKey;
        private readonly byte[] iv;
        private readonly uint counter;

        public MessageKeys(byte[] cipherKey, byte[] macKey, byte[] iv, uint counter)
        {
            this.cipherKey = cipherKey;
            this.macKey = macKey;
            this.iv = iv;
            this.counter = counter;
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

        public uint getCounter()
        {
            return counter;
        }
    }
}
