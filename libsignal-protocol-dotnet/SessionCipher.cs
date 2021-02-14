using System;
using System.Collections.Generic;
using libsignal.ecc;
using libsignal.exceptions;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using libsignal.util;
using Strilanc.Value;
using System.Threading.Tasks;

namespace libsignal
{
    /// <summary>
    /// The main entry point for Signal Protocol encrypt/decrypt operations.
    /// 
    /// Once a session has been established with <see cref="SessionBuilder"/>, this class can be used for all
    /// encrypt/decrypt operations within that session.
    /// </summary>
    public class SessionCipher
    {
        public static readonly object SESSION_LOCK = new object();

        private readonly SessionStore sessionStore;
        private readonly IdentityKeyStore identityKeyStore;
        private readonly SessionBuilder sessionBuilder;
        private readonly PreKeyStore preKeyStore;
        private readonly SignalProtocolAddress remoteAddress;

        /// <summary>
        /// Construct a SessionCipher for encrypt/decrypt operations on a session.
        /// In order to use SessionCipher, a session must have already been created and stored using <see cref="SessionBuilder"/>.
        /// </summary>
        /// <param name="sessionStore">The <see cref="SessionStore"/> that contains a session for this recipient.</param>
        /// <param name="preKeyStore"></param>
        /// <param name="signedPreKeyStore"></param>
        /// <param name="identityKeyStore"></param>
        /// <param name="remoteAddress">The remote address that messages will be encrypted to or decrypted from.</param>
        public SessionCipher(SessionStore sessionStore, PreKeyStore preKeyStore,
                             SignedPreKeyStore signedPreKeyStore, IdentityKeyStore identityKeyStore,
                             SignalProtocolAddress remoteAddress)
        {
            this.sessionStore = sessionStore;
            this.preKeyStore = preKeyStore;
            this.identityKeyStore = identityKeyStore;
            this.remoteAddress = remoteAddress;
            this.sessionBuilder = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                                     identityKeyStore, remoteAddress);
        }

        public SessionCipher(SignalProtocolStore store, SignalProtocolAddress remoteAddress)
            : this(store, store, store, store, remoteAddress)
        {

        }

        /// <summary>
        /// Encrypt a message.
        /// </summary>
        /// <param name="paddedMessage">The plaintext message bytes, optionally padded to a constant multiple.</param>
        /// <returns>A ciphertext message encrypted to the recipient+device tuple.</returns>
        public CiphertextMessage encrypt(byte[] paddedMessage)
        {
            lock (SESSION_LOCK)
            {
                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                SessionState sessionState = sessionRecord.getSessionState();
                ChainKey chainKey = sessionState.getSenderChainKey();
                MessageKeys messageKeys = chainKey.getMessageKeys();
                ECPublicKey senderEphemeral = sessionState.getSenderRatchetKey();
                uint previousCounter = sessionState.getPreviousCounter();
                uint sessionVersion = sessionState.getSessionVersion();

                byte[] ciphertextBody = getCiphertext(messageKeys, paddedMessage);
                CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.getMacKey(),
                                                                         senderEphemeral, chainKey.getIndex(),
                                                                         previousCounter, ciphertextBody,
                                                                         sessionState.getLocalIdentityKey(),
                                                                         sessionState.getRemoteIdentityKey());

                if (sessionState.hasUnacknowledgedPreKeyMessage())
                {
                    SessionState.UnacknowledgedPreKeyMessageItems items = sessionState.getUnacknowledgedPreKeyMessageItems();
                    uint localRegistrationId = sessionState.GetLocalRegistrationId();

                    ciphertextMessage = new PreKeySignalMessage(sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                                 items.getSignedPreKeyId(), items.getBaseKey(),
                                                                 sessionState.getLocalIdentityKey(),
                                                                 (SignalMessage)ciphertextMessage);
                }

                sessionState.setSenderChainKey(chainKey.getNextChainKey());

                if (!identityKeyStore.IsTrustedIdentity(remoteAddress, sessionState.getRemoteIdentityKey(), Direction.SENDING))
                {
                    throw new UntrustedIdentityException(remoteAddress.Name, sessionState.getRemoteIdentityKey());
                }

                identityKeyStore.SaveIdentity(remoteAddress, sessionState.getRemoteIdentityKey());

                sessionStore.StoreSession(remoteAddress, sessionRecord);
                return ciphertextMessage;
            }
        }

        /// <summary>
        /// Decrypt a message.
        /// </summary>
        /// <param name="ciphertext">The <see cref="PreKeySignalMessage"/> to decrypt.</param>
        /// <returns>The plaintext.</returns>
        /// <exception cref="InvalidMessageException">if the input is not valid ciphertext.</exception>
        /// <exception cref="DuplicateMessageException">if the input is a message that has already been received.</exception>
        /// <exception cref="LegacyMessageException">if the input is a message formatted by a protocol version that is
        /// no longer supported.</exception>
        /// <exception cref="InvalidKeyIdException">when there is no local <see cref="PreKeyRecord"/> that corresponds
        /// to the PreKey ID in the message.</exception>
        /// <exception cref="InvalidKeyException">when the message is formatted incorrectly.</exception>
        /// <exception cref="UntrustedIdentityException">when the <see cref="IdentityKey"/> of the sender is untrusted.</exception>
        public byte[] decrypt(PreKeySignalMessage ciphertext)
        {
            var tsk = (decrypt(ciphertext, new NullDecryptionCallback()));
            tsk.Wait();
            return tsk.Result;
        }

        /// <summary>
        /// Decrypt a message.
        /// </summary>
        /// <param name="ciphertext">The <see cref="PreKeySignalMessage"/> to decrypt.</param>
        /// <param name="callback">A callback that is triggered after decryption is complete, but before the updated
        /// session state has been committed to the session DB. This allows some implementations to store the committed
        /// plaintext to a DB first, in case they are concerned with a crash happening between the time the session
        /// state is updated but before they're able to store the plaintext to disk.</param>
        /// <returns>The plaintext.</returns>
        /// <exception cref="InvalidMessageException">if the input is not valid ciphertext.</exception>
        /// <exception cref="DuplicateMessageException">if the input is a message that has already been received.</exception>
        /// <exception cref="LegacyMessageException">if the input is a message formatted by a protocol version that is
        /// no longer supported.</exception>
        /// <exception cref="InvalidKeyIdException">when there is no local <see cref="PreKeyRecord"/> that corresponds
        /// 
        /// <exception cref="InvalidKeyException">when the message is formatted incorrectly.</exception>
        /// <exception cref="UntrustedIdentityException">when the <see cref="IdentityKey"/> of the sender is untrusted.</exception>
        public Task<byte[]> decrypt(PreKeySignalMessage ciphertext, DecryptionCallback callback)
        {
            lock (SESSION_LOCK)
            {
                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                May<uint> unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
                byte[] plaintext = decrypt(sessionRecord, ciphertext.getSignalMessage());

                identityKeyStore.SaveIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey());

                callback.handlePlaintext(plaintext, sessionRecord.getSessionState().getSessionVersion()).Wait();

                sessionStore.StoreSession(remoteAddress, sessionRecord);

                if (unsignedPreKeyId.HasValue)
                {
                    preKeyStore.RemovePreKey(unsignedPreKeyId.ForceGetValue());
                }

                return Task.FromResult(plaintext);
            }
        }

        /// <summary>
        /// Decrypt a message.
        /// </summary>
        /// <param name="ciphertext">The <see cref="SignalMessage"/> to decrypt.</param>
        /// <returns>The plaintext.</returns>
        /// <exception cref="InvalidMessageException">if the input is not valid ciphertext.</exception>
        /// <exception cref="DuplicateMessageException">if the input is a message that has already been received.</exception>
        /// <exception cref="LegacyMessageException">if the input is a message formatted by a protocol version that is
        /// no longer supported.</exception>
        /// <exception cref="NoSessionException">if there is no established session for this contact.</exception>
        public byte[] decrypt(SignalMessage ciphertext)
        {
            var tsk = decrypt(ciphertext, new NullDecryptionCallback());
            tsk.Wait();
            return tsk.Result;
        }

        /// <summary>
        /// Decrypt a message.
        /// </summary>
        /// <param name="ciphertext">The <see cref="SignalMessage"/> to decrypt.</param>
        /// <param name="callback">A callback that is triggered after decryption is complete, but before the updated
        /// session state has been committed to the session DB. This allows some implementations to store the committed
        /// plaintext to a DB first, in case they are concerned with a crash happening between the time the session
        /// state is updated but before they're able to store the plaintext to disk.</param>
        /// <returns>The plaintext.</returns>
        /// <exception cref="InvalidMessageException">if the input is not valid ciphertext.</exception>
        /// <exception cref="DuplicateMessageException">if the input is a message that has already been received.</exception>
        /// <exception cref="LegacyMessageException">if the input is a message formatted by a protocol version that is
        /// no longer supported.</exception>
        /// <exception cref="NoSessionException">if there is no established session for this contact.</exception>
        public Task<byte[]> decrypt(SignalMessage ciphertext, DecryptionCallback callback)
        {
            lock (SESSION_LOCK)
            {

                if (!sessionStore.ContainsSession(remoteAddress))
                {
                    throw new NoSessionException($"No session for: {remoteAddress}");
                }

                SessionRecord sessionRecord = sessionStore.LoadSession(remoteAddress);
                byte[] plaintext = decrypt(sessionRecord, ciphertext);

                if (!identityKeyStore.IsTrustedIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey(), Direction.RECEIVING))
                {
                    throw new UntrustedIdentityException(remoteAddress.Name, sessionRecord.getSessionState().getRemoteIdentityKey());
                }

                callback.handlePlaintext(plaintext, sessionRecord.getSessionState().getSessionVersion()).Wait();//no async in a lock

                sessionStore.StoreSession(remoteAddress, sessionRecord);

                return Task.FromResult(plaintext);
            }
        }

        private byte[] decrypt(SessionRecord sessionRecord, SignalMessage ciphertext)
        {
            lock (SESSION_LOCK)
            {
                IEnumerator<SessionState> previousStates = sessionRecord.getPreviousSessionStates().GetEnumerator(); //iterator
                LinkedList<Exception> exceptions = new LinkedList<Exception>();

                try
                {
                    SessionState sessionState = new SessionState(sessionRecord.getSessionState());
                    byte[] plaintext = decrypt(sessionState, ciphertext);

                    sessionRecord.setState(sessionState);
                    return plaintext;
                }
                catch (InvalidMessageException e)
                {
                    exceptions.AddLast(e); // add (java default behavioir addlast)
                }

                while (previousStates.MoveNext()) //hasNext();
                {
                    try
                    {
                        SessionState promotedState = new SessionState(previousStates.Current); //.next()
                        byte[] plaintext = decrypt(promotedState, ciphertext);

                        sessionRecord.getPreviousSessionStates().Remove(previousStates.Current); // previousStates.remove()
                        sessionRecord.promoteState(promotedState);

                        return plaintext;
                    }
                    catch (InvalidMessageException e)
                    {
                        exceptions.AddLast(e);
                    }
                }

                throw new InvalidMessageException("No valid sessions.", exceptions);
            }
        }

        private byte[] decrypt(SessionState sessionState, SignalMessage ciphertextMessage)
        {
            if (!sessionState.hasSenderChain())
            {
                throw new InvalidMessageException("Uninitialized session!");
            }

            if (sessionState.getStructure().SenderChain.SenderRatchetKey.Length <= 0)
            {
                throw new InvalidMessageException("SenderRatchetKey is empty!");
            }

            if (ciphertextMessage.getMessageVersion() != sessionState.getSessionVersion())
            {
                throw new InvalidMessageException($"Message version {ciphertextMessage.getMessageVersion()}, but session version {sessionState.getSessionVersion()}");
            }

            ECPublicKey theirEphemeral = ciphertextMessage.getSenderRatchetKey();
            uint counter = ciphertextMessage.getCounter();
            ChainKey chainKey = getOrCreateChainKey(sessionState, theirEphemeral);
            MessageKeys messageKeys = getOrCreateMessageKeys(sessionState, theirEphemeral,
                                                                      chainKey, counter);

            ciphertextMessage.verifyMac(sessionState.getRemoteIdentityKey(),
                                            sessionState.getLocalIdentityKey(),
                                            messageKeys.getMacKey());

            byte[] plaintext = getPlaintext(messageKeys, ciphertextMessage.getBody());

            sessionState.clearUnacknowledgedPreKeyMessage();

            return plaintext;
        }

        public uint getRemoteRegistrationId()
        {
            lock (SESSION_LOCK)
            {
                SessionRecord record = sessionStore.LoadSession(remoteAddress);
                return record.getSessionState().getRemoteRegistrationId();
            }
        }

        public uint getSessionVersion()
        {
            lock (SESSION_LOCK)
            {
                if (!sessionStore.ContainsSession(remoteAddress))
                {
                    throw new Exception($"No session for {remoteAddress}!"); // IllegalState
                }

                SessionRecord record = sessionStore.LoadSession(remoteAddress);
                return record.getSessionState().getSessionVersion();
            }
        }

        private ChainKey getOrCreateChainKey(SessionState sessionState, ECPublicKey theirEphemeral)
        {
            try
            {
                if (sessionState.hasReceiverChain(theirEphemeral))
                {
                    return sessionState.getReceiverChainKey(theirEphemeral);
                }
                else
                {
                    RootKey rootKey = sessionState.getRootKey();
                    ECKeyPair ourEphemeral = sessionState.getSenderRatchetKeyPair();
                    Pair<RootKey, ChainKey> receiverChain = rootKey.createChain(theirEphemeral, ourEphemeral);
                    ECKeyPair ourNewEphemeral = Curve.generateKeyPair();
                    Pair<RootKey, ChainKey> senderChain = receiverChain.first().createChain(theirEphemeral, ourNewEphemeral);

                    sessionState.setRootKey(senderChain.first());
                    sessionState.addReceiverChain(theirEphemeral, receiverChain.second());
                    sessionState.setPreviousCounter(Math.Max(sessionState.getSenderChainKey().getIndex() - 1, 0));
                    sessionState.setSenderChain(ourNewEphemeral, senderChain.second());

                    return receiverChain.second();
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private MessageKeys getOrCreateMessageKeys(SessionState sessionState,
                                                   ECPublicKey theirEphemeral,
                                                   ChainKey chainKey, uint counter)
        {
            if (chainKey.getIndex() > counter)
            {
                if (sessionState.hasMessageKeys(theirEphemeral, counter))
                {
                    return sessionState.removeMessageKeys(theirEphemeral, counter);
                }
                else
                {
                    throw new DuplicateMessageException($"Received message with old counter: {chainKey.getIndex()}  , {counter}");
                }
            }

            //Avoiding a uint overflow
            uint chainKeyIndex = chainKey.getIndex();
            if ((counter > chainKeyIndex) && (counter - chainKeyIndex > 2000))
            {
                throw new InvalidMessageException("Over 2000 messages into the future!");
            }

            while (chainKey.getIndex() < counter)
            {
                MessageKeys messageKeys = chainKey.getMessageKeys();
                sessionState.setMessageKeys(theirEphemeral, messageKeys);
                chainKey = chainKey.getNextChainKey();
            }

            sessionState.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey());
            return chainKey.getMessageKeys();
        }

        private byte[] getCiphertext(MessageKeys messageKeys, byte[] plaintext)
        {
            return Encrypt.aesCbcPkcs5(plaintext, messageKeys.getCipherKey(), messageKeys.getIv());
        }

        private byte[] getPlaintext(MessageKeys messageKeys, byte[] cipherText)
        {
            return Decrypt.aesCbcPkcs5(cipherText, messageKeys.getCipherKey(), messageKeys.getIv());
        }

        private class NullDecryptionCallback : DecryptionCallback
        {

            public Task handlePlaintext(byte[] plaintext, uint sessionVersion) => Task.CompletedTask;
        }
    }
}
