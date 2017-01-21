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

namespace libsignal
{
    public class SignalProtocolAddress
    {

        private readonly String name;
        private readonly uint deviceId;

        public SignalProtocolAddress(String name, uint deviceId)
        {
            this.name = name;
            this.deviceId = deviceId;
        }

        public String getName()
        {
            return name;
        }

        public uint getDeviceId()
        {
            return deviceId;
        }

        public override String ToString()
        {
            return name + ":" + deviceId;
        }

        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is SignalProtocolAddress)) return false;

            SignalProtocolAddress that = (SignalProtocolAddress)other;
            return this.name.Equals(that.name) && this.deviceId == that.deviceId;
        }


        public override int GetHashCode()
        {
            return this.name.GetHashCode() ^ (int)this.deviceId;
        }
    }
}
