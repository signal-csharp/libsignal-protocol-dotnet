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
using Google.Protobuf;
using libsignal.ecc;
using libsignal.util;

namespace libsignal.protocol
{
    public partial class SenderKeyMessage : CiphertextMessage
    {
        private static readonly int SIGNATURE_LENGTH = 64;

        private readonly uint messageVersion;
        private readonly uint keyId;
        private readonly uint iteration;
        private readonly byte[] ciphertext;
        private readonly byte[] serialized;

        public SenderKeyMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1 - SIGNATURE_LENGTH, SIGNATURE_LENGTH);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] signature = messageParts[2];

                if (ByteUtil.highBitsToInt(version) < 3)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SenderKeyMessage senderKeyMessage = SenderKeyMessage.Parser.ParseFrom(message);

                if (senderKeyMessage.IdOneofCase == IdOneofOneofCase.None ||
                    senderKeyMessage.IterationOneofCase == IterationOneofOneofCase.None ||
                    senderKeyMessage.CiphertextOneofCase == CiphertextOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.messageVersion = (uint)ByteUtil.highBitsToInt(version);
                this.keyId = senderKeyMessage.Id;
                this.iteration = senderKeyMessage.Iteration;
                this.ciphertext = senderKeyMessage.Ciphertext.ToByteArray();
            }
            catch (/*InvalidProtocolBufferException | Parse*/Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public SenderKeyMessage(uint keyId, uint iteration, byte[] ciphertext, ECPrivateKey signatureKey)
        {
            byte[] version = { ByteUtil.intsToByteHighAndLow((int)CURRENT_VERSION, (int)CURRENT_VERSION) };
            byte[] message = new SenderKeyMessage
            {
                Id = keyId,
                Iteration = iteration,
                Ciphertext = ByteString.CopyFrom(ciphertext),
            }.ToByteArray();

            byte[] signature = getSignature(signatureKey, ByteUtil.combine(version, message));

            this.serialized = ByteUtil.combine(version, message, signature);
            this.messageVersion = CURRENT_VERSION;
            this.keyId = keyId;
            this.iteration = iteration;
            this.ciphertext = ciphertext;
        }

        public uint getKeyId()
        {
            return keyId;
        }

        public uint getIteration()
        {
            return iteration;
        }

        public byte[] getCipherText()
        {
            return ciphertext;
        }

        public void verifySignature(ECPublicKey signatureKey)
        {
            try
            {
                byte[][] parts = ByteUtil.split(serialized, serialized.Length - SIGNATURE_LENGTH, SIGNATURE_LENGTH);

                if (!Curve.verifySignature(signatureKey, parts[0], parts[1]))
                {
                    throw new InvalidMessageException("Invalid signature!");
                }

            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        private byte[] getSignature(ECPrivateKey signatureKey, byte[] serialized)
        {
            try
            {
                return Curve.calculateSignature(signatureKey, serialized);
            }
            catch (InvalidKeyException e)
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
            return CiphertextMessage.SENDERKEY_TYPE;
        }
    }
}
