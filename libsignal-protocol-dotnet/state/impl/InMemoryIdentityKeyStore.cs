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

namespace libsignal.state.impl
{
    /// <summary>
    /// In-memory / testing implementation of IdentityKeyStore
    /// </summary>
    public class InMemoryIdentityKeyStore : IdentityKeyStore
    {

        private readonly IDictionary<SignalProtocolAddress, IdentityKey> trustedKeys = new Dictionary<SignalProtocolAddress, IdentityKey>();

        private readonly IdentityKeyPair identityKeyPair;
        private readonly uint localRegistrationId;

        /// <summary>
        /// .ctor
        /// </summary>
        public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, uint localRegistrationId)
        {
            this.identityKeyPair = identityKeyPair;
            this.localRegistrationId = localRegistrationId;
        }

        public IdentityKeyPair GetIdentityKeyPair()
        {
            return identityKeyPair;
        }


        public uint GetLocalRegistrationId()
        {
            return localRegistrationId;
        }

        public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            IdentityKey existing;
            trustedKeys.TryGetValue(address, out existing);

            if (!identityKey.Equals(existing))
            {
                trustedKeys[address] = identityKey;
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction)
        {
            IdentityKey trusted;
            trustedKeys.TryGetValue(address, out trusted); // get(name)
            return (trusted == null || trusted.Equals(identityKey));
        }

        public IdentityKey GetIdentity(SignalProtocolAddress address)
        {
            trustedKeys.TryGetValue(address, out var identity);
            return identity;
        }
    }
}
