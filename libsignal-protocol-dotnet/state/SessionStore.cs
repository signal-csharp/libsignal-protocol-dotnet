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
    /**
     * The interface to the durable store of session state information
     * for remote clients.
     *
     * @author
     */
    public interface SessionStore
    {

        /**
         * Returns a copy of the {@link SessionRecord} corresponding to the recipientId + deviceId tuple,
         * or a new SessionRecord if one does not currently exist.
         * <p>
         * It is important that implementations return a copy of the current durable information.  The
         * returned SessionRecord may be modified, but those changes should not have an effect on the
         * durable session state (what is returned by subsequent calls to this method) without the
         * store method being called here first.
         *
         * @param address The name and device ID of the remote client.
         * @return a copy of the SessionRecord corresponding to the recipientId + deviceId tuple, or
         *         a new SessionRecord if one does not currently exist.
         */
        SessionRecord LoadSession(SignalProtocolAddress address);

        /**
         * Returns all known devices with active sessions for a recipient
         *
         * @param name the name of the client.
         * @return all known sub-devices with active sessions.
         */
        List<uint> GetSubDeviceSessions(String name);

        /**
         * Commit to storage the {@link SessionRecord} for a given recipientId + deviceId tuple.
         * @param address the address of the remote client.
         * @param record the current SessionRecord for the remote client.
         */
        void StoreSession(SignalProtocolAddress address, SessionRecord record);

        /**
         * Determine whether there is a committed {@link SessionRecord} for a recipientId + deviceId tuple.
         * @param address the address of the remote client.
         * @return true if a {@link SessionRecord} exists, false otherwise.
         */
         bool ContainsSession(SignalProtocolAddress address);

        /**
         * Remove a {@link SessionRecord} for a recipientId + deviceId tuple.
         *
         * @param address the address of the remote client.
         */
         void DeleteSession(SignalProtocolAddress address);

        /**
         * Remove the {@link SessionRecord}s corresponding to all devices of a recipientId.
         *
         * @param name the name of the remote client.
         */
        void DeleteAllSessions(String name);

    }
}
