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

namespace libsignal.groups
{
    /**
     * A representation of a (groupId + senderId + deviceId) tuple.
     */
    public class SenderKeyName
    {

        private readonly String groupId;
        private readonly SignalProtocolAddress sender;

        public SenderKeyName(String groupId, SignalProtocolAddress sender)
        {
            this.groupId = groupId;
            this.sender = sender;
        }

        public String getGroupId()
        {
            return groupId;
        }

        public SignalProtocolAddress getSender()
        {
            return sender;
        }

        public String serialize()
        {
            return groupId + "::" + sender.getName() + "::" + sender.getDeviceId();
        }


        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is SenderKeyName)) return false;

            SenderKeyName that = (SenderKeyName)other;

            return
                this.groupId.Equals(that.groupId) &&
                this.sender.Equals(that.sender);
        }

        public override int GetHashCode()
        {
            return this.groupId.GetHashCode() ^ this.sender.GetHashCode();
        }

    }
}
