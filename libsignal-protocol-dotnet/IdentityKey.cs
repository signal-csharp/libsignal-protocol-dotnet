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

using libsignal.ecc;
using System;

namespace libsignal
{
    /**
     * A class for representing an identity key.
     * 
     * @author Moxie Marlinspike
     */

    public class IdentityKey
    {

        private ECPublicKey publicKey;

        public IdentityKey(ECPublicKey publicKey)
        {
            this.publicKey = publicKey;
        }

        public IdentityKey(byte[] bytes, int offset)
        {
            this.publicKey = Curve.decodePoint(bytes, offset);
        }

        public ECPublicKey getPublicKey()
        {
            return publicKey;
        }

        public byte[] serialize()
        {
            return publicKey.serialize();
        }

        public String getFingerprint()
        {
            return publicKey.serialize().ToString(); //Hex
        }

        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is IdentityKey)) return false;

            return publicKey.Equals(((IdentityKey)other).getPublicKey());
        }


        public override int GetHashCode()
        {
            return publicKey.GetHashCode();
        }
    }
}
