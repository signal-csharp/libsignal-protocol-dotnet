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
using System.Linq;
using libsignal.util;

namespace libsignal.ecc
{
    public class DjbECPublicKey : ECPublicKey
    {
        private readonly byte[] publicKey;

        public DjbECPublicKey(byte[] publicKey)
        {
            this.publicKey = publicKey;
        }


        public byte[] serialize()
        {
            byte[] type = { (byte)Curve.DJB_TYPE };
            return ByteUtil.combine(type, publicKey);
        }


        public int getType()
        {
            return Curve.DJB_TYPE;
        }


        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is DjbECPublicKey)) return false;

            DjbECPublicKey that = (DjbECPublicKey)other;
            return Enumerable.SequenceEqual(this.publicKey, that.publicKey);
        }


        public override int GetHashCode()
        {
            return string.Join(",", publicKey).GetHashCode();
        }


        public int CompareTo(Object another)
        {
            byte[] theirs = ((DjbECPublicKey)another).publicKey;
            String theirString = string.Join(",", theirs.Select(y => y.ToString()));
            String ourString = string.Join(",", publicKey.Select(y => y.ToString()));
            return ourString.CompareTo(theirString);
        }

        public byte[] getPublicKey()
        {
            return publicKey;
        }

    }
}
