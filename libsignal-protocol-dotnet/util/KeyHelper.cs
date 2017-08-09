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
using libsignal.state;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace libsignal.util
{
    /**
     * Helper class for generating keys of different types.
     *
     * @author Moxie Marlinspike
     */
    public class KeyHelper
    {

        private KeyHelper() { }

        /**
         * Generate an identity key pair.  Clients should only do this once,
         * at install time.
         *
         * @return the generated IdentityKeyPair.
         */
        public static IdentityKeyPair generateIdentityKeyPair()
        {
            ECKeyPair keyPair = Curve.generateKeyPair();
            IdentityKey publicKey = new IdentityKey(keyPair.getPublicKey());
            return new IdentityKeyPair(publicKey, keyPair.getPrivateKey());
        }

        /**
         * Generate a registration ID.  Clients should only do this once,
         * at install time.
         *
         * @param extendedRange By default (false), the generated registration
         *                      ID is sized to require the minimal possible protobuf
         *                      encoding overhead. Specify true if the caller needs
         *                      the full range of MAX_INT at the cost of slightly
         *                      higher encoding overhead.
         * @return the generated registration ID.
         */
        public static uint generateRegistrationId(bool extendedRange)
        {
            if (extendedRange) return getRandomSequence(uint.MaxValue - 1) + 1;
            else return getRandomSequence(16380) + 1;
        }

        public static uint getRandomSequence(uint max)
        {
            byte[] randomBytes = new byte[sizeof(uint)];
            using (var gen = RandomNumberGenerator.Create())
            {
                gen.GetBytes(randomBytes);
            }
            return BitConverter.ToUInt32(randomBytes, 0) % max;
        }

        /**
         * Generate a list of PreKeys.  Clients should do this at install time, and
         * subsequently any time the list of PreKeys stored on the server runs low.
         * <p>
         * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
         * store PreKeys in a circular buffer, so that they are repeated as infrequently
         * as possible.
         *
         * @param start The starting PreKey ID, inclusive.
         * @param count The number of PreKeys to generate.
         * @return the list of generated PreKeyRecords.
         */
        public static IList<PreKeyRecord> generatePreKeys(uint start, uint count)
        {
            IList<PreKeyRecord> results = new List<PreKeyRecord>();

            start--;

            for (uint i = 0; i < count; i++)
            {
                results.Add(new PreKeyRecord(((start + i) % (Medium.MAX_VALUE - 1)) + 1, Curve.generateKeyPair()));
            }

            return results;
        }

        /**
         * Generate a signed PreKey
         *
         * @param identityKeyPair The local client's identity key pair.
         * @param signedPreKeyId The PreKey id to assign the generated signed PreKey
         *
         * @return the generated signed PreKey
         * @throws InvalidKeyException when the provided identity key is invalid
         */
        public static SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, uint signedPreKeyId)
        {
            ECKeyPair keyPair = Curve.generateKeyPair();
            byte[] signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

            return new SignedPreKeyRecord(signedPreKeyId, getTime(), keyPair, signature);
        }


        public static ECKeyPair generateSenderSigningKey()
        {
            return Curve.generateKeyPair();
        }

        public static byte[] generateSenderKey()
        {
            byte[] key = new byte[32];
            using (var gen = RandomNumberGenerator.Create())
            {
                gen.GetBytes(key);
            }
            return key;
        }

        public static uint generateSenderKeyId()
        {
            return getRandomSequence(uint.MaxValue);
        }

        public static ulong getTime()
        {
            return (ulong)DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
        }
    }
}
