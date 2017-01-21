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
using libsignal.exceptions;
using libsignal.protocol;
using libsignal.state;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignal_test
{

    [TestClass]
    public class SessionBuilderTest
    {
        private static readonly SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
        private static readonly SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);

        class BobDecryptionCallback : DecryptionCallback
        {
            readonly SignalProtocolStore bobStore;
            readonly String originalMessage;

            public BobDecryptionCallback(SignalProtocolStore bobStore, String originalMessage)
            {
                this.bobStore = bobStore;
                this.originalMessage = originalMessage;
            }

            public void handlePlaintext(byte[] plaintext)
            {
                Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
                Assert.IsFalse(bobStore.ContainsSession(ALICE_ADDRESS));
            }
        }

        [TestMethod, TestCategory("libsignal")]
        public void testBasicPreKeyV3()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                             bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessage.getType());

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new BobDecryptionCallback(bobStore, originalMessage));

            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, bobOutgoingMessage.getType());

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            runInteraction(aliceStore, bobStore);

            aliceStore = new TestInMemorySignalProtocolStore();
            aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);

            bobPreKeyPair = Curve.generateKeyPair();
            bobSignedPreKeyPair = Curve.generateKeyPair();
            bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().serialize());
            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(),
                                         1, 31338, bobPreKeyPair.getPublicKey(),
                                         23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                         bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(23, new SignedPreKeyRecord(23, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
            aliceSessionBuilder.process(bobPreKey);

            outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            try
            {
                plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
                throw new Exception("shouldn't be trusted!");
            }
            catch (UntrustedIdentityException)
            {
                bobStore.SaveIdentity(ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
            }

            plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                         31337, Curve.generateKeyPair().getPublicKey(),
                                         23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                         aliceStore.GetIdentityKeyPair().getPublicKey());

            try
            {
                aliceSessionBuilder.process(bobPreKey);
                throw new Exception("shoulnd't be trusted!");
            }
            catch (UntrustedIdentityException)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libsignal")]
        public void testBadSignedPreKeySignature()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());


            for (int i = 0; i < bobSignedPreKeySignature.Length * 8; i++)
            {
                byte[] modifiedSignature = new byte[bobSignedPreKeySignature.Length];
                Array.Copy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.Length);

                modifiedSignature[i / 8] ^= (byte)(0x01 << (i % 8));

                PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                          31337, bobPreKeyPair.getPublicKey(),
                                                          22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
                                                          bobIdentityKeyStore.GetIdentityKeyPair().getPublicKey());
                
                try
                {
                    aliceSessionBuilder.process(bobPreKey);
                    throw new Exception("Accepted modified device key signature!");
                }
                catch (InvalidKeyException)
                {
                    // good
                }
            }

            PreKeyBundle bobPreKey2 = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobIdentityKeyStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey2);
        }

        [TestMethod, TestCategory("libsignal")]
        public void testRepeatBundleMessageV3()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageOne.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageTwo.getType());

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            // The test

            PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.serialize());

            plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobOutgoingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));
            alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

        }

        [TestMethod, TestCategory("libsignal")]
        public void testBadMessageBundle()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.getPublicKey(),
                                                      22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, outgoingMessageOne.getType());

            byte[] goodMessage = outgoingMessageOne.serialize();
            byte[] badMessage = new byte[goodMessage.Length];
            Array.Copy(goodMessage, 0, badMessage, 0, badMessage.Length);

            badMessage[badMessage.Length - 10] ^= 0x01;

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(badMessage);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            byte[] plaintext = new byte[0];

            try
            {
                plaintext = bobSessionCipher.decrypt(incomingMessage);
                throw new Exception("Decrypt should have failed!");
            }
            catch (InvalidMessageException)
            {
                // good.
            }

            Assert.IsTrue(bobStore.ContainsPreKey(31337));

            plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
            Assert.IsFalse(bobStore.ContainsPreKey(31337));
        }

        [TestMethod, TestCategory("libsignal")]
        public void testOptionalOneTimePreKey()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
            ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                          bobSignedPreKeyPair.getPublicKey().serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      0, null,
                                                      22, bobSignedPreKeyPair.getPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().getPublicKey());

            aliceSessionBuilder.process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BOB_ADDRESS));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(outgoingMessage.getType(), CiphertextMessage.PREKEY_TYPE);

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
            Assert.IsFalse(incomingMessage.getPreKeyId().HasValue);

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

            Assert.IsTrue(bobStore.ContainsSession(ALICE_ADDRESS));
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
        }

        private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
        {
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            String originalMessage = "smert ze smert";
            CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceMessage.getType());

            byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, bobMessage.getType());

            plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            HashSet<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<Pair<String, CiphertextMessage>>();

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                aliceOutOfOrderMessages.Add(new Pair<String, CiphertextMessage>(loopingMessage, aliceLoopingMessage));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("You can only desire based on what you know: " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            foreach (Pair<String, CiphertextMessage> aliceOutOfOrderMessage in aliceOutOfOrderMessages)
            {
                byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
                Assert.AreEqual(aliceOutOfOrderMessage.first(), Encoding.UTF8.GetString(outOfOrderPlaintext));
            }
        }
    }
}
