/** 
 * Copyright (C) 2016 langboost
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

using libsignal;
using libsignal.ecc;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using signal_protocol_tests;

namespace libsignal_test
{
    [TestClass]
    public class SessionCipherTest
    {
        [TestMethod, TestCategory("libsignal")]
        public void testBasicSessionV3()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
            runInteraction(aliceSessionRecord, bobSessionRecord);
        }

        [TestMethod, TestCategory("libsignal")]
        public void testMessageKeyLimits()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            List<CiphertextMessage> inflight = new List<CiphertextMessage>();

            for (int i = 0; i < 2010; i++)
            {
                inflight.Add(aliceCipher.encrypt(Encoding.UTF8.GetBytes("you've never been so hungry, you've never been so cold")));
            }

            bobCipher.decrypt(new SignalMessage(inflight[1000].serialize()));
            bobCipher.decrypt(new SignalMessage(inflight[inflight.Count - 1].serialize()));

            try
            {
                bobCipher.decrypt(new SignalMessage(inflight[0].serialize()));
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException)
            {
                // good
            }
        }

        private void runInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            byte[] alicePlaintext = Encoding.UTF8.GetBytes("This is a plaintext message.");
            CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
            byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

            CollectionAssert.AreEqual(alicePlaintext, bobPlaintext);

            byte[] bobReply = Encoding.UTF8.GetBytes("This is a message from Bob.");
            CiphertextMessage reply = bobCipher.encrypt(bobReply);
            byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

            CollectionAssert.AreEqual(bobReply, receivedReply);

            List<CiphertextMessage> aliceCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> alicePlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 50; i++)
            {
                alicePlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                aliceCiphertextMessages.Add(aliceCipher.encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            ulong seed = DateUtil.currentTimeMillis();

            HelperMethods.Shuffle(aliceCiphertextMessages, new Random((int)seed));
            HelperMethods.Shuffle(alicePlaintextMessages, new Random((int)seed));

            for (int i = 0; i < aliceCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages[i].serialize()));
                Assert.IsTrue(libsignal.util.ByteUtil.isEqual(receivedPlaintext, alicePlaintextMessages[i]));
            }

            List<CiphertextMessage> bobCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> bobPlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 20; i++)
            {
                bobPlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                bobCiphertextMessages.Add(bobCipher.encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            seed = DateUtil.currentTimeMillis();

            HelperMethods.Shuffle(bobCiphertextMessages, new Random((int)seed));
            HelperMethods.Shuffle(bobPlaintextMessages, new Random((int)seed));

            for (int i = 0; i < bobCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }

            for (int i = aliceCiphertextMessages.Count / 2; i < aliceCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            for (int i = bobCiphertextMessages.Count / 2; i < bobCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages[i].serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }
        }
        private void initializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
        {
            ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                                   aliceIdentityKeyPair.getPrivateKey());
            ECKeyPair aliceBaseKey = Curve.generateKeyPair();
            ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

            ECKeyPair alicePreKey = aliceBaseKey;

            ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                                 bobIdentityKeyPair.getPrivateKey());
            ECKeyPair bobBaseKey = Curve.generateKeyPair();
            ECKeyPair bobEphemeralKey = bobBaseKey;

            ECKeyPair bobPreKey = Curve.generateKeyPair();

            AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                .setOurBaseKey(aliceBaseKey)
                .setOurIdentityKey(aliceIdentityKey)
                .setTheirOneTimePreKey(May<ECPublicKey>.NoValue)
                .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                .create();

            BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
                .setOurRatchetKey(bobEphemeralKey)
                .setOurSignedPreKey(bobBaseKey)
                .setOurOneTimePreKey(May<ECKeyPair>.NoValue)
                .setOurIdentityKey(bobIdentityKey)
                .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                .setTheirBaseKey(aliceBaseKey.getPublicKey())
                .create();

            RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
            RatchetingSession.initializeSession(bobSessionState, bobParameters);
        }

        
    }
}
