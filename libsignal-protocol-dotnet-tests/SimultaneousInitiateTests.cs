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
using libsignal.state;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace libsignal_test
{
    [TestClass]
    public class SimultaneousInitiateTests
    {
        private static readonly SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("+14151231234", 1);
        private static readonly SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1);

        private static readonly ECKeyPair aliceSignedPreKey = Curve.generateKeyPair();
        private static readonly ECKeyPair bobSignedPreKey = Curve.generateKeyPair();

        private static readonly uint aliceSignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);
        private static readonly uint bobSignedPreKeyId = (uint)new Random().Next((int)Medium.MAX_VALUE);

        [TestMethod, TestCategory("libsignal")]
        public void testBasicSimultaneousInitiate()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            Assert.AreEqual(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            Assert.AreEqual("sample message", Encoding.UTF8.GetString(alicePlaintext));
            Assert.AreEqual("hey there", Encoding.UTF8.GetString(bobPlaintext));

            Assert.AreEqual((uint)3, aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion());
            Assert.AreEqual((uint)3, bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion());

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

            byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

            Assert.AreEqual("second message", Encoding.UTF8.GetString(responsePlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.AreEqual("third message", Encoding.UTF8.GetString(finalPlaintext));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void testLostSimultaneousInitiate()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
            Assert.AreEqual<uint>(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));
            Assert.IsTrue(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.getType(), CiphertextMessage.PREKEY_TYPE);

            byte[] responsePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(aliceResponse.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.IsTrue(finalMessage.getType() == CiphertextMessage.WHISPER_TYPE);

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void testSimultaneousInitiateLostMessage()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
            Assert.AreEqual<uint>(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

            Assert.IsTrue(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
            Assert.IsTrue(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void testSimultaneousInitiateRepeatedMessages()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

            Assert.AreEqual<uint>(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
            Assert.AreEqual<uint>(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
            Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

            Assert.IsTrue(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
            Assert.IsTrue(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
                Assert.AreEqual<uint>(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void testRepeatedSimultaneousInitiateRepeatedMessages()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

                aliceSessionBuilder.process(bobPreKeyBundle);
                bobSessionBuilder.process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
                Assert.AreEqual<uint>(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
                byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

                Assert.IsTrue(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
                Assert.IsTrue(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
                Assert.AreEqual<uint>(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }
        [TestMethod]
        public void testRepeatedSimultaneousInitiateLostMessageRepeatedMessages()
        {
            SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();


            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            //    PreKeyBundle aliceLostPreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobLostPreKeyBundle);
            //    bobSessionBuilder.process(aliceLostPreKeyBundle);

            CiphertextMessage lostMessageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
            //    CiphertextMessage lostMessageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            for (int i = 0; i < 15; i++)
            {
                PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
                PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

                aliceSessionBuilder.process(bobPreKeyBundle);
                bobSessionBuilder.process(alicePreKeyBundle);

                CiphertextMessage messageForBob = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAlice = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBob.getType(), CiphertextMessage.PREKEY_TYPE);
                Assert.AreEqual<uint>(messageForAlice.getType(), CiphertextMessage.PREKEY_TYPE);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
                byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintext).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintext).Equals("hey there"));

                Assert.IsTrue(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);
                Assert.IsTrue(bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            for (int i = 0; i < 50; i++)
            {
                CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("hey there"));
                CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("sample message"));

                Assert.AreEqual<uint>(messageForBobRepeat.getType(), CiphertextMessage.WHISPER_TYPE);
                Assert.AreEqual<uint>(messageForAliceRepeat.getType(), CiphertextMessage.WHISPER_TYPE);

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

                byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new SignalMessage(messageForAliceRepeat.serialize()));
                byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new SignalMessage(messageForBobRepeat.serialize()));

                Assert.IsTrue(Encoding.UTF8.GetString(alicePlaintextRepeat).Equals("sample message"));
                Assert.IsTrue(Encoding.UTF8.GetString(bobPlaintextRepeat).Equals("hey there"));

                Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));
            }

            CiphertextMessage aliceResponse = aliceSessionCipher.encrypt(Encoding.UTF8.GetBytes("second message"));

            Assert.AreEqual<uint>(aliceResponse.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] responsePlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceResponse.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(responsePlaintext).Equals("second message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage finalMessage = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("third message"));

            Assert.AreEqual<uint>(finalMessage.getType(), CiphertextMessage.WHISPER_TYPE);

            byte[] finalPlaintext = aliceSessionCipher.decrypt(new SignalMessage(finalMessage.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(finalPlaintext).Equals("third message"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));

            byte[] lostMessagePlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(lostMessageForBob.serialize()));
            Assert.IsTrue(Encoding.UTF8.GetString(lostMessagePlaintext).Equals("hey there"));

            Assert.IsFalse(isSessionIdEqual(aliceStore, bobStore));

            CiphertextMessage blastFromThePast = bobSessionCipher.encrypt(Encoding.UTF8.GetBytes("unexpected!"));
            byte[] blastFromThePastPlaintext = aliceSessionCipher.decrypt(new SignalMessage(blastFromThePast.serialize()));

            Assert.IsTrue(Encoding.UTF8.GetString(blastFromThePastPlaintext).Equals("unexpected!"));
            Assert.IsTrue(isSessionIdEqual(aliceStore, bobStore));
        }

        private bool isSessionIdEqual(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
        {
            return ByteUtil.isEqual(aliceStore.LoadSession(BOB_ADDRESS).getSessionState().getAliceBaseKey(),
                                 bobStore.LoadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey());
        }

        private PreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore)
        {
            ECKeyPair aliceUnsignedPreKey = Curve.generateKeyPair();
            int aliceUnsignedPreKeyId = new Random().Next((int)Medium.MAX_VALUE);
            byte[] aliceSignature = Curve.calculateSignature(aliceStore.GetIdentityKeyPair().getPrivateKey(),
                                                                       aliceSignedPreKey.getPublicKey().serialize());

            PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                                                              (uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                                                              aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
                                                              aliceSignature, aliceStore.GetIdentityKeyPair().getPublicKey());

            aliceStore.StoreSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, (ulong)DateTime.UtcNow.Ticks, aliceSignedPreKey, aliceSignature));
            aliceStore.StorePreKey((uint)aliceUnsignedPreKeyId, new PreKeyRecord((uint)aliceUnsignedPreKeyId, aliceUnsignedPreKey));

            return alicePreKeyBundle;
        }

        private PreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore)
        {
            ECKeyPair bobUnsignedPreKey = Curve.generateKeyPair();
            int bobUnsignedPreKeyId = new Random().Next((int)Medium.MAX_VALUE);
            byte[] bobSignature = Curve.calculateSignature(bobStore.GetIdentityKeyPair().getPrivateKey(),
                                                                     bobSignedPreKey.getPublicKey().serialize());

            PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                                                            (uint)bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                                                            bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                                                            bobSignature, bobStore.GetIdentityKeyPair().getPublicKey());

            bobStore.StoreSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, (ulong)DateTime.UtcNow.Ticks, bobSignedPreKey, bobSignature));
            bobStore.StorePreKey((uint)bobUnsignedPreKeyId, new PreKeyRecord((uint)bobUnsignedPreKeyId, bobUnsignedPreKey));

            return bobPreKeyBundle;
        }
    }
}
