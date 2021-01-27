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

namespace libsignal.groups.state
{
    public interface SenderKeyStore
    {
        /// <summary>
        /// Commit to storage the <see cref="SenderKeyRecord"/> for a given (groupId + senderId + deviceId) tuple.
        /// </summary>
        /// <param name="senderKeyName">the (groupId + senderId + deviceId) tuple.</param>
        /// <param name="record">the current SenderKeyRecord for the specified senderKeyName.</param>
        void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record);

        /// <summary>
        /// Returns a copy of the <see cref="SenderKeyRecord"/> corresponding to the (groupId + senderId + deviceId)
        /// tuple, or a new SenderKeyRecord if one does not currently exist.
        /// 
        /// It is important that implementations return a copy of the current durable information. The returned
        /// SenderKeyRecord may be modified, but those changes should not have an effect on the durable session state
        /// (what is returned by subsequent calls to this method) without the store method being called here first.
        /// </summary>
        /// <param name="senderKeyName">The (groupId + senderId + deviceId) tuple.</param>
        /// <returns>a copy of the SenderKeyRecord corresponding to the (groupId + senderId + deviceId tuple, or a new
        /// SenderKeyRecord if one does not currently exist.</returns>
        SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName);
    }
}
