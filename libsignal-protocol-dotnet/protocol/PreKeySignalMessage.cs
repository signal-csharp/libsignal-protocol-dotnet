
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
using Strilanc.Value;
using System;

namespace libsignal.protocol
{
    public partial class PreKeySignalMessage : CiphertextMessage
    {

        private readonly uint version;
        private readonly uint registrationId;
        private readonly May<uint> preKeyId;
        private readonly uint signedPreKeyId;
        private readonly ECPublicKey baseKey;
        private readonly IdentityKey identityKey;
        private readonly SignalMessage message;
        private readonly byte[] serialized;

        public PreKeySignalMessage(byte[] serialized)
        {
            try
            {
                this.version = (uint)ByteUtil.highBitsToInt(serialized[0]);

                if (this.version > CiphertextMessage.CURRENT_VERSION)
                {
                    throw new InvalidVersionException("Unknown version: " + this.version);
                }

                if (this.version < CiphertextMessage.CURRENT_VERSION) {
                throw new LegacyMessageException("Legacy version: " + this.version);
                }
                PreKeySignalMessage preKeySignalMessage = PreKeySignalMessage.Parser.ParseFrom(ByteString.CopyFrom(serialized, 1, serialized.Length - 1));

                if (
                    preKeySignalMessage.SignedPreKeyIdOneofCase == SignedPreKeyIdOneofOneofCase.None ||
                    preKeySignalMessage.BaseKeyOneofCase == BaseKeyOneofOneofCase.None ||
                    preKeySignalMessage.BaseKeyOneofCase == BaseKeyOneofOneofCase.None ||
                    preKeySignalMessage.MessageOneofCase == MessageOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this.serialized = serialized;
                this.registrationId = preKeySignalMessage.RegistrationId;
                this.preKeyId = preKeySignalMessage.PreKeyIdOneofCase == PreKeyIdOneofOneofCase.PreKeyId ? new May<uint>(preKeySignalMessage.PreKeyId) : May<uint>.NoValue;
                this.signedPreKeyId = preKeySignalMessage.SignedPreKeyIdOneofCase == SignedPreKeyIdOneofOneofCase.SignedPreKeyId ? preKeySignalMessage.SignedPreKeyId : uint.MaxValue; // -1
                this.baseKey = Curve.decodePoint(preKeySignalMessage.BaseKey.ToByteArray(), 0);
                this.identityKey = new IdentityKey(Curve.decodePoint(preKeySignalMessage.IdentityKey.ToByteArray(), 0));
                this.message = new SignalMessage(preKeySignalMessage.Message.ToByteArray());
            }
            catch (Exception e)
            {
                //(InvalidProtocolBufferException | InvalidKeyException | LegacyMessage
                throw new InvalidMessageException(e.Message);
            }
        }

        public PreKeySignalMessage(uint messageVersion, uint registrationId, May<uint> preKeyId,
                                    uint signedPreKeyId, ECPublicKey baseKey, IdentityKey identityKey,
                                    SignalMessage message)
        {
            this.version = messageVersion;
            this.registrationId = registrationId;
            this.preKeyId = preKeyId;
            this.signedPreKeyId = signedPreKeyId;
            this.baseKey = baseKey;
            this.identityKey = identityKey;
            this.message = message;

            PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage
            {
                SignedPreKeyId = signedPreKeyId,
                BaseKey = ByteString.CopyFrom(baseKey.serialize()),
                IdentityKey = ByteString.CopyFrom(identityKey.serialize()),
                Message = ByteString.CopyFrom(message.serialize()),
                RegistrationId = registrationId
            };

            if (preKeyId.HasValue) // .isPresent()
            {
                preKeySignalMessage.PreKeyId = preKeyId.ForceGetValue(); // get()
            }

            byte[] versionBytes = { ByteUtil.intsToByteHighAndLow((int)this.version, (int)CURRENT_VERSION) };
            byte[] messageBytes = preKeySignalMessage.ToByteArray();

            this.serialized = ByteUtil.combine(versionBytes, messageBytes);
        }

        public uint getMessageVersion()
        {
            return version;
        }

        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        public uint getRegistrationId()
        {
            return registrationId;
        }

        public May<uint> getPreKeyId()
        {
            return preKeyId;
        }

        public uint getSignedPreKeyId()
        {
            return signedPreKeyId;
        }

        public ECPublicKey getBaseKey()
        {
            return baseKey;
        }

        public SignalMessage getSignalMessage()
        {
            return message;
        }


        public override byte[] serialize()
        {
            return serialized;
        }


        public override uint getType()
        {
            return CiphertextMessage.PREKEY_TYPE;
        }

    }
}
