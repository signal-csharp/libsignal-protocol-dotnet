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

namespace libsignal.state
{
    public enum Direction
    {
        SENDING, RECEIVING
    }

    /// <summary>
    /// Provides an interface to identity information.
    /// </summary>
    public interface IdentityKeyStore
    {
        /// <summary>
        /// Get the local client's identity key pair.
        /// </summary>
        /// <returns>The local client's persistent identity key pair.</returns>
        IdentityKeyPair GetIdentityKeyPair();

        /// <summary>
        /// Return the local client's registration ID.
        /// 
        /// Clients should maintain a registration ID, a random number between 1 and 16380 that's generated once at
        /// install time.
        /// </summary>
        /// <returns>the local client's registration ID.</returns>
        uint GetLocalRegistrationId();

        /// <summary>
        /// Save a remote client's identity key
        /// 
        /// Store a remote client's identity key as trusted.
        /// </summary>
        /// <param name="address">The address of the remote client.</param>
        /// <param name="identityKey">The remote client's identity key.</param>
        /// <returns>True if the identity key replaces a previous identity, false if not</returns>
        bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey);

        /// <summary>
        /// Verify a remote client's identity key.
        /// 
        /// Determine whether a remote client's identity is trusted. Convention is that the Signal Protocol is
        /// 'trust on first use.' This means that an identity key is considered 'trusted' if there is no entry for the
        /// recipient in the local store, or if it matches the saved key for a recipient in the local store. Only if it
        /// mismatches an entry in the local store is it considered 'untrusted.'
        /// 
        /// Clients may wish to make a distinction as to how keys are trusted based on the direction of travel. For
        /// instance, clients may wish to accept all 'incoming' identity key changes, while only blocking identity key
        /// changes when sending a message.
        /// </summary>
        /// <param name="address">The address of the remote client.</param>
        /// <param name="identityKey">The identity key to verify.</param>
        /// <param name="direction">The direction (sending or receiving) this identity is being used for.</param>
        /// <returns>true if trusted, false if untrusted.</returns>
        bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction);

        /// <summary>
        /// Return the saved public identity key for a remote client
        /// </summary>
        /// <param name="address">The address of the remote client</param>
        /// <returns>The public identity key, or null if absent</returns>
        IdentityKey GetIdentity(SignalProtocolAddress address);
    }
}
