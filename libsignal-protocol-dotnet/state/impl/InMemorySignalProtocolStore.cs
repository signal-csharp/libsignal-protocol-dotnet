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
    public class InMemorySignalProtocolStore : SignalProtocolStore
    {

        private readonly InMemoryPreKeyStore preKeyStore = new InMemoryPreKeyStore();
        private readonly InMemorySessionStore sessionStore = new InMemorySessionStore();
        private readonly InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();

        private readonly InMemoryIdentityKeyStore identityKeyStore;

        public InMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, uint registrationId)
        {
            this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
        }


        public IdentityKeyPair GetIdentityKeyPair()
        {
            return identityKeyStore.GetIdentityKeyPair();
        }


        public uint GetLocalRegistrationId()
        {
            return identityKeyStore.GetLocalRegistrationId();
        }


        public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            return identityKeyStore.SaveIdentity(address, identityKey);
        }


        public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction)
        {
            return identityKeyStore.IsTrustedIdentity(address, identityKey, direction);
        }


        public PreKeyRecord LoadPreKey(uint preKeyId)
        {
            return preKeyStore.LoadPreKey(preKeyId);
        }


        public void StorePreKey(uint preKeyId, PreKeyRecord record)
        {
            preKeyStore.StorePreKey(preKeyId, record);
        }


        public bool ContainsPreKey(uint preKeyId)
        {
            return preKeyStore.ContainsPreKey(preKeyId);
        }


        public void RemovePreKey(uint preKeyId)
        {
            preKeyStore.RemovePreKey(preKeyId);
        }


        public SessionRecord LoadSession(SignalProtocolAddress address)
        {
            return sessionStore.LoadSession(address);
        }


        public List<uint> GetSubDeviceSessions(String name)
        {
            return sessionStore.GetSubDeviceSessions(name);
        }


        public void StoreSession(SignalProtocolAddress address, SessionRecord record)
        {
            sessionStore.StoreSession(address, record);
        }


        public bool ContainsSession(SignalProtocolAddress address)
        {
            return sessionStore.ContainsSession(address);
        }


        public void DeleteSession(SignalProtocolAddress address)
        {
            sessionStore.DeleteSession(address);
        }


        public void DeleteAllSessions(String name)
        {
            sessionStore.DeleteAllSessions(name);
        }


        public SignedPreKeyRecord LoadSignedPreKey(uint signedPreKeyId)
        {
            return signedPreKeyStore.LoadSignedPreKey(signedPreKeyId);
        }


        public List<SignedPreKeyRecord> LoadSignedPreKeys()
        {
            return signedPreKeyStore.LoadSignedPreKeys();
        }


        public void StoreSignedPreKey(uint signedPreKeyId, SignedPreKeyRecord record)
        {
            signedPreKeyStore.StoreSignedPreKey(signedPreKeyId, record);
        }


        public bool ContainsSignedPreKey(uint signedPreKeyId)
        {
            return signedPreKeyStore.ContainsSignedPreKey(signedPreKeyId);
        }


        public void RemoveSignedPreKey(uint signedPreKeyId)
        {
            signedPreKeyStore.RemoveSignedPreKey(signedPreKeyId);
        }
    }
}
