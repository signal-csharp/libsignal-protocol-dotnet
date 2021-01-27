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

using System.Diagnostics;
using libsignal.ecc;
using libsignal.exceptions;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using Strilanc.Value;

namespace libsignal
{
    /// <summary>
    /// SessionBuilder is responsible for setting up encrypted sessions.
    /// Once a session has been established, <see cref="SessionCipher"/> can be used to encrypt/decrypt messages in that
    /// session.
    /// 
    /// Sessions are built from one of three different possible vectors:
    /// <list type="number">
    ///     <item><description>A <see cref="PreKeyBundle"/> retrieved from a server.</description></item>
    ///     <item><description>A <see cref="PreKeySignalMessage"/> received from a client.</description></item>
    /// </list>
    /// 
    /// Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified by their
    /// recipientId, and each logical recipientId can have multiple physical devices.
    /// </summary>
    public class SessionBuilder
    {
        private readonly SessionStore sessionStore;
        private readonly PreKeyStore preKeyStore;
        private readonly SignedPreKeyStore signedPreKeyStore;
        private readonly IdentityKeyStore identityKeyStore;
        private readonly SignalProtocolAddress remoteAddress;

        /// <summary>
        /// Constructs a SessionBuilder.
        /// </summary>
        /// <param name="sessionStore">The <see cref="SessionStore"/> to store the constructed session in.</param>
        /// <param name="preKeyStore">The <see cref="PreKeyStore"/> where the client's local <see cref="PreKeyRecord"/>s
        /// are stored.</param>
        /// <param name="signedPreKeyStore"></param>
        /// <param name="identityKeyStore">The <see cref="IdentityKeyStore"/> containing the client's identity key
        /// information.</param>
        /// <param name="remoteAddress">The address of the remote user to build a session with.</param>
        public SessionBuilder(SessionStore sessionStore,
                              PreKeyStore preKeyStore,
                              SignedPreKeyStore signedPreKeyStore,
                              IdentityKeyStore identityKeyStore,
                              SignalProtocolAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.signedPreKeyStore = signedPreKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
        }

        /// <summary>
        /// Constructs a SessionBuilder
        /// </summary>
        /// <param name="store">The <see cref="SignalProtocolStore"/> to store all state information in.</param>
        /// <param name="remoteAddress">The address of the remote user to build a session with.</param>
        public SessionBuilder(SignalProtocolStore store, SignalProtocolAddress remoteAddress)
            : this(store, store, store, store, remoteAddress)
        {
        }

        /// <summary>
        /// Build a new session from a received <see cref="PreKeySignalMessage"/>
        /// 
        /// After a session is constructed in this way, the embedded <see cref="SignalMessage"/> can be decrypted.
        /// </summary>
        /// <param name="sessionRecord"></param>
        /// <param name="message">The received <see cref="PreKeySignalMessage"/>.</param>
        /// <returns></returns>
        /// <exception cref="InvalidKeyIdException">when there is no local <see cref="PreKeyRecord"/> that corresponds
        /// to the PreKey ID in the message.</exception>
        /// <exception cref="InvalidKeyException">when the message is formatted incorrectly.</exception>
        /// <exception cref="UntrustedIdentityException">when the <see cref="IdentityKey"/> of the sender is untrusted.</exception>
        internal May<uint> process(SessionRecord sessionRecord, PreKeySignalMessage message)
        {
            uint messageVersion = message.getMessageVersion();
            IdentityKey theirIdentityKey = message.getIdentityKey();

            if (!identityKeyStore.IsTrustedIdentity(remoteAddress, theirIdentityKey, Direction.RECEIVING))
            {
                throw new UntrustedIdentityException(remoteAddress.Name, theirIdentityKey);
            }

            May<uint> unsignedPreKeyId = processV3(sessionRecord, message);

            identityKeyStore.SaveIdentity(remoteAddress, theirIdentityKey);
            return unsignedPreKeyId;
        }

        private May<uint> processV3(SessionRecord sessionRecord, PreKeySignalMessage message)
        {

            if (sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().serialize()))
            {
                Debug.WriteLine("We've already setup a session for this V3 message, letting bundled message fall through...");
                return May<uint>.NoValue;
            }

            ECKeyPair ourSignedPreKey = signedPreKeyStore.LoadSignedPreKey(message.getSignedPreKeyId()).getKeyPair();

            BobSignalProtocolParameters.Builder parameters = BobSignalProtocolParameters.newBuilder();

            parameters.setTheirBaseKey(message.getBaseKey())
                      .setTheirIdentityKey(message.getIdentityKey())
                      .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                      .setOurSignedPreKey(ourSignedPreKey)
                      .setOurRatchetKey(ourSignedPreKey);

            if (message.getPreKeyId().HasValue)
            {
                parameters.setOurOneTimePreKey(new May<ECKeyPair>(preKeyStore.LoadPreKey(message.getPreKeyId().ForceGetValue()).getKeyPair()));
            }
            else
            {
                parameters.setOurOneTimePreKey(May<ECKeyPair>.NoValue);
            }

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
            sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId());
            sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().serialize());

            if (message.getPreKeyId().HasValue)
            {
                return message.getPreKeyId();
            }
            else
            {
                return May<uint>.NoValue;
            }
        }

        /// <summary>
        /// Build a new session from a <see cref="PreKeyBundle"/> retrieved from a server.
        /// </summary>
        /// <param name="preKey">A PreKey for the destination recipient, retrieved from a server.</param>
        /// <exception cref="InvalidKeyException">when the <see cref="PreKeyBundle"/> is badly formatted.</exception>
        /// <exception cref="UntrustedIdentityException">when the sender's <see cref="IdentityKey"/> is not trusted.</exception>
        public void process(PreKeyBundle preKey)
        {
            lock (SessionCipher.SESSION_LOCK)
            {
                if (!identityKeyStore.IsTrustedIdentity(remoteAddress, preKey.getIdentityKey(), Direction.SENDING))
                {
                    throw new UntrustedIdentityException(remoteAddress.Name, preKey.getIdentityKey());
                }

                if (preKey.getSignedPreKey() != null &&
                    !Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
                                           preKey.getSignedPreKey().serialize(),
                                           preKey.getSignedPreKeySignature()))
                {
                    throw new InvalidKeyException("Invalid signature on device key!");
                }

                if (preKey.getSignedPreKey() == null)
                {
                    throw new InvalidKeyException("No signed prekey!");
                }

                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                ECKeyPair ourBaseKey = Curve.generateKeyPair();
                ECPublicKey theirSignedPreKey = preKey.getSignedPreKey();
                ECPublicKey test = preKey.getPreKey();
                May<ECPublicKey> theirOneTimePreKey = (test == null) ? May<ECPublicKey>.NoValue : new May<ECPublicKey>(test);
                May<uint> theirOneTimePreKeyId = theirOneTimePreKey.HasValue ? new May<uint>(preKey.getPreKeyId()) :
                                                                                              May<uint>.NoValue;

                AliceSignalProtocolParameters.Builder parameters = AliceSignalProtocolParameters.newBuilder();

                parameters.setOurBaseKey(ourBaseKey)
                              .setOurIdentityKey(identityKeyStore.GetIdentityKeyPair())
                              .setTheirIdentityKey(preKey.getIdentityKey())
                              .setTheirSignedPreKey(theirSignedPreKey)
                              .setTheirRatchetKey(theirSignedPreKey)
                              .setTheirOneTimePreKey(theirOneTimePreKey);

                if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

                RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

                sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.getSignedPreKeyId(), ourBaseKey.getPublicKey());
                sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.GetLocalRegistrationId());
                sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId());
                sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().serialize());

                identityKeyStore.SaveIdentity(remoteAddress, preKey.getIdentityKey());

                sessionStore.StoreSession(remoteAddress, sessionRecord);
            }
        }
    }
}
