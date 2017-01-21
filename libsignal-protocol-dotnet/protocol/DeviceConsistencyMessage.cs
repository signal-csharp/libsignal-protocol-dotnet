/** 
 * Copyright (C) 2017 golf1052
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
using libsignal.devices;
using libsignal.ecc;
using org.whispersystems.curve25519;
using Google.Protobuf;

namespace libsignal.protocol
{
    public class DeviceConsistencyMessage
    {
        private readonly DeviceConsistencySignature signature;
        private readonly int generation;
        private readonly byte[] serialized;

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair)
        {
            try
            {
                byte[] signatureBytes = Curve.calculateVrfSignature(identityKeyPair.getPrivateKey(), commitment.toByteArray());
                byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKeyPair.getPublicKey().getPublicKey(), commitment.toByteArray(), signatureBytes);

                this.generation = commitment.getGeneration();
                this.signature = new DeviceConsistencySignature(signatureBytes, vrfOutputBytes);
                this.serialized = new DeviceConsistencyCodeMessage
                {
                    Generation = (uint) commitment.getGeneration(),
                    Signature = ByteString.CopyFrom(signature.getSignature())
                }.ToByteArray();
            }
            catch (InvalidKeyException e)
            {
                Debug.Assert(false);
                throw e;
            }
            catch (VrfSignatureVerificationFailedException e)
            {
                Debug.Assert(false);
                throw e;
            }
        }

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey)
        {
            try
            {
                DeviceConsistencyCodeMessage message = DeviceConsistencyCodeMessage.Parser.ParseFrom(serialized);
                byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKey.getPublicKey(), commitment.toByteArray(), message.Signature.ToByteArray());

                this.generation = (int)message.Generation;
                this.signature = new DeviceConsistencySignature(message.Signature.ToByteArray(), vrfOutputBytes);
                this.serialized = serialized;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMessageException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
            catch (VrfSignatureVerificationFailedException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public byte[] getSerialized()
        {
            return serialized;
        }

        public DeviceConsistencySignature getSignature()
        {
            return signature;
        }

        public int getGeneration()
        {
            return generation;
        }
    }
}
