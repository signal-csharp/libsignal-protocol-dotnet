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
using System.IO;
using System.Linq;
using Google.Protobuf;
using libsignal.ecc;
using libsignal.util;

namespace libsignal.protocol
{
    public partial class SignalMessage : CiphertextMessage
    {
        private static readonly int MAC_LENGTH = 8;

        private readonly uint messageVersion;
        private readonly ECPublicKey senderRatchetKey;
        private readonly uint counter;
        private readonly uint previousCounter;
        private readonly byte[] ciphertext;
        private readonly byte[] serialized;

        public SignalMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1 - MAC_LENGTH, MAC_LENGTH);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] mac = messageParts[2];

                if (ByteUtil.highBitsToInt(version) < CURRENT_VERSION)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SignalMessage signalMessage = SignalMessage.Parser.ParseFrom(message);

                if (signalMessage.CiphertextOneofCase == CiphertextOneofOneofCase.None ||
                    signalMessage.CounterOneofCase == CounterOneofOneofCase.None ||
                    signalMessage.RatchedKeyOneofCase == RatchedKeyOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.senderRatchetKey = Curve.decodePoint(signalMessage.RatchetKey.ToByteArray(), 0);
                this.messageVersion = (uint)ByteUtil.highBitsToInt(version);
                this.counter = signalMessage.Counter;
                this.previousCounter = signalMessage.PreviousCounter;
                this.ciphertext = signalMessage.Ciphertext.ToByteArray();
            }
            catch (/*InvalidProtocolBufferException | InvalidKeyException | Parse*/Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public SignalMessage(uint messageVersion, byte[] macKey, ECPublicKey senderRatchetKey,
                              uint counter, uint previousCounter, byte[] ciphertext,
                              IdentityKey senderIdentityKey,
                              IdentityKey receiverIdentityKey)
        {
            byte[] version = { ByteUtil.intsToByteHighAndLow((int)messageVersion, (int)CURRENT_VERSION) };
            byte[] message = new SignalMessage
            {
                ratchedKeyOneofCase_ = RatchedKeyOneofOneofCase.RatchetKey,
                RatchetKey = ByteString.CopyFrom(senderRatchetKey.serialize()), //TODO serialize ok?
                counterOneofCase_ = CounterOneofOneofCase.Counter,
                Counter = counter,
                previousCounterOneofCase_ = PreviousCounterOneofOneofCase.PreviousCounter,
                PreviousCounter = previousCounter,
                ciphertextOneofCase_ = CiphertextOneofOneofCase.Ciphertext,
                Ciphertext = ByteString.CopyFrom(ciphertext),
            }.ToByteArray();

            byte[] mac = getMac(senderIdentityKey, receiverIdentityKey, macKey, ByteUtil.combine(version, message));

            this.serialized = ByteUtil.combine(version, message, mac);
            this.senderRatchetKey = senderRatchetKey;
            this.counter = counter;
            this.previousCounter = previousCounter;
            this.ciphertext = ciphertext;
            this.messageVersion = messageVersion;
        }

        public ECPublicKey getSenderRatchetKey()
        {
            return senderRatchetKey;
        }

        public uint getMessageVersion()
        {
            return messageVersion;
        }

        public uint getCounter()
        {
            return counter;
        }

        public byte[] getBody()
        {
            return ciphertext;
        }

        public void verifyMac(IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey, byte[] macKey)
        {
            byte[][] parts = ByteUtil.split(serialized, serialized.Length - MAC_LENGTH, MAC_LENGTH);
            byte[] ourMac = getMac(senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
            byte[] theirMac = parts[1];

            if (!Enumerable.SequenceEqual(ourMac, theirMac))
            {
                throw new InvalidMessageException("Bad Mac!");
            }
        }

        private byte[] getMac(IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey,
                        byte[] macKey, byte[] serialized)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                byte[] sik = senderIdentityKey.getPublicKey().serialize();
                stream.Write(sik, 0, sik.Length);
                byte[] rik = receiverIdentityKey.getPublicKey().serialize();
                stream.Write(rik, 0, rik.Length);

                stream.Write(serialized, 0, serialized.Length);
                byte[] fullMac = Sign.sha256sum(macKey, stream.ToArray());
                return ByteUtil.trim(fullMac, MAC_LENGTH);
            }
            catch (/*NoSuchAlgorithmException | java.security.InvalidKey*/Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        public override byte[] serialize()
        {
            return serialized;
        }

        public override uint getType()
        {
            return CiphertextMessage.WHISPER_TYPE;
        }

        public static bool isLegacy(byte[] message)
        {
            return message != null && message.Length >= 1 &&
                ByteUtil.highBitsToInt(message[0]) != CURRENT_VERSION;
        }
    }
}
