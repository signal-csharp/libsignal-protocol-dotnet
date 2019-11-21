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

namespace libsignal.state
{
    public enum Direction
    {
        SENDING, RECEIVING
    }
    /**
     * Provides an interface to identity information.
     *
     * @author
     */
    public interface IdentityKeyStore
    {

        /**
         * Get the local client's identity key pair.
         *
         * @return The local client's persistent identity key pair.
         */
        IdentityKeyPair GetIdentityKeyPair();

        /**
         * Return the local client's registration ID.
         * <p>
         * Clients should maintain a registration ID, a random number
         * between 1 and 16380 that's generated once at install time.
         *
         * @return the local client's registration ID.
         */
        uint GetLocalRegistrationId();

        /**
         * Save a remote client's identity key
         * <p>
         * Store a remote client's identity key as trusted.
         *
         * @param address        The address of the remote client.
         * @param identityKey The remote client's identity key.
         * 
         * @return True if the identity key replaces a previous identity, false if not
         */
        bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey);


        /**
         * Verify a remote client's identity key.
         * <p>
         * Determine whether a remote client's identity is trusted.  Convention is
         * that the Signal Protocol is 'trust on first use.'  This means that
         * an identity key is considered 'trusted' if there is no entry for the recipient
         * in the local store, or if it matches the saved key for a recipient in the local
         * store.  Only if it mismatches an entry in the local store is it considered
         * 'untrusted.'
         *
         * Clients may wish to make a distinction as to how keys are trusted based on the
         * direction of travel. For instance, clients may wish to accept all 'incoming' identity
         * key changes, while only blocking identity key changes when sending a message.

         * @param address        The address of the remote client.
         * @param identityKey The identity key to verify.
         * @param direction   The direction (sending or receiving) this identity is being used for.
         * @return true if trusted, false if untrusted.
         */
        bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction);

        /// <summary>
        /// Return the saved public identity key for a remote client
        /// </summary>
        /// <param name="address">The address of the remote client</param>
        /// <returns>The public identity key, or null if absent</returns>
        IdentityKey GetIdentity(SignalProtocolAddress address);

    }
}
