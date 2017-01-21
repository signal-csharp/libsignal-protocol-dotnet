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
         */
        bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey);


        /**
         * Verify a remote client's identity key.
         * <p>
         * Determine whether a remote client's identity is trusted.  Convention is
         * that the TextSecure protocol is 'trust on first use.'  This means that
         * an identity key is considered 'trusted' if there is no entry for the recipient
         * in the local store, or if it matches the saved key for a recipient in the local
         * store.  Only if it mismatches an entry in the local store is it considered
         * 'untrusted.'
         *
         * @param address        The address of the remote client.
         * @param identityKey The identity key to verify.
         * @return true if trusted, false if untrusted.
         */
        bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey);

    }
}
