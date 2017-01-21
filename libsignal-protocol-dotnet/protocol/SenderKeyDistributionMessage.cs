

using Google.Protobuf;
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
using libsignal.ecc;
using libsignal.util;
using System;

namespace libsignal.protocol
{
    public partial class SenderKeyDistributionMessage : CiphertextMessage
    {

        private readonly uint id;
        private readonly uint iteration;
        private readonly byte[] chainKey;
        private readonly ECPublicKey signatureKey;
        private readonly byte[] serialized;

        public SenderKeyDistributionMessage(uint id, uint iteration, byte[] chainKey, ECPublicKey signatureKey)
        {
            byte[] version = { ByteUtil.intsToByteHighAndLow((int)CURRENT_VERSION, (int)CURRENT_VERSION) };
            byte[] protobuf = new SenderKeyDistributionMessage
            {
                Id = id,
                Iteration = iteration,
                ChainKey = ByteString.CopyFrom(chainKey),
                SigningKey = ByteString.CopyFrom(signatureKey.serialize())

            }.ToByteArray();

            this.id = id;
            this.iteration = iteration;
            this.chainKey = chainKey;
            this.signatureKey = signatureKey;
            this.serialized = ByteUtil.combine(version, protobuf);
        }

        public SenderKeyDistributionMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.Length - 1);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];

                if (ByteUtil.highBitsToInt(version) < CiphertextMessage.CURRENT_VERSION)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
                }

                if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
                }

                SenderKeyDistributionMessage distributionMessage = SenderKeyDistributionMessage.Parser.ParseFrom(message);

                if (distributionMessage.IdOneofCase == IdOneofOneofCase.None ||
                    distributionMessage.IterationOneofCase == IterationOneofOneofCase.None ||
                    distributionMessage.ChainKeyOneofCase == ChainKeyOneofOneofCase.None ||
                    distributionMessage.SigningKeyOneofCase == SigningKeyOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.id = distributionMessage.Id;
                this.iteration = distributionMessage.Iteration;
                this.chainKey = distributionMessage.ChainKey.ToByteArray();
                this.signatureKey = Curve.decodePoint(distributionMessage.SigningKey.ToByteArray(), 0);
            }
            catch (Exception e)
            {
                //InvalidProtocolBufferException | InvalidKey
                throw new InvalidMessageException(e);
            }
        }

        public override byte[] serialize()
        {
            return serialized;
        }


        public override uint getType()
        {
            return SENDERKEY_DISTRIBUTION_TYPE;
        }

        public uint getIteration()
        {
            return iteration;
        }

        public byte[] getChainKey()
        {
            return chainKey;
        }

        public ECPublicKey getSignatureKey()
        {
            return signatureKey;
        }

        public uint getId()
        {
            return id;
        }
    }
}
