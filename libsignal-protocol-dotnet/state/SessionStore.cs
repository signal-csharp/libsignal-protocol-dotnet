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

namespace libsignal.state
{
    /// <summary>
    /// The interface to the durable store of session state information for remote clients.
    /// </summary>
    public interface SessionStore
    {
        /// <summary>
        /// Returns a copy of the <see cref="SessionRecord"/> corresponding to the recipientId + deviceId tuple, or a
        /// new SessionRecord if one does not currently exist.
        /// 
        /// It is important that implementations return a copy of the current durable information. The returned
        /// SessionRecord may be modified, but those changes should not have an effect on the durable session state
        /// (what is returned by subsequent calls to this method) without the store method being called here first.
        /// </summary>
        /// <param name="address">The name and device ID of the remote client.</param>
        /// <returns>a copy of the SessionRecord corresponding to the recipientId + deviceId tuple, or a new
        /// SessionRecord if one does not currently exist.</returns>
        SessionRecord LoadSession(SignalProtocolAddress address);

        /// <summary>
        /// Returns all known devices with active sessions for a recipient
        /// </summary>
        /// <param name="name">the name of the client.</param>
        /// <returns>all known sub-devices with active sessions.</returns>
        List<uint> GetSubDeviceSessions(String name);

        /// <summary>
        /// Commit to storage the <see cref="SessionRecord"/> for a given recipientId + deviceId tuple.
        /// </summary>
        /// <param name="address">the address of the remote client.</param>
        /// <param name="record">the current SessionRecord for the remote client.</param>
        void StoreSession(SignalProtocolAddress address, SessionRecord record);

        /// <summary>
        /// Determine whether there is a committed <see cref="SessionRecord"/> for a recipientId + deviceId tuple.
        /// </summary>
        /// <param name="address">the address of the remote client.</param>
        /// <returns>true if a <see cref="SessionRecord"/> exists, false otherwise.</returns>
        bool ContainsSession(SignalProtocolAddress address);

        /// <summary>
        /// Remove a <see cref="SessionRecord"/> for a recipientId + deviceId tuple.
        /// </summary>
        /// <param name="address">the address of the remote client.</param>
        void DeleteSession(SignalProtocolAddress address);

        /// <summary>
        /// Remove the <see cref="SessionRecord"/>s corresponding to all devices of a recipientId.
        /// </summary>
        /// <param name="name">the name of the remote client.</param>
        void DeleteAllSessions(String name);

    }
}
