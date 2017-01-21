/** 
 * Copyright (C) 2017 smndtrl, langboost, golf1052
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
using libsignal.util;
using System;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace org.whispersystems.libsignal.fingerprint
{

    public class NumericFingerprintGenerator : FingerprintGenerator
    {
        private static readonly int FINGERPRINT_VERSION = 0;

        private readonly int iterations;

        /**
         * Construct a fingerprint generator for 60 digit numerics.
         *
         * @param iterations The number of internal iterations to perform in the process of
         *                   generating a fingerprint. This needs to be constant, and synchronized
         *                   across all clients.
         *
         *                   The higher the iteration count, the higher the security level:
         *
         *                   - 1024 ~ 109.7 bits
         *                   - 1400 > 110 bits
         *                   - 5200 > 112 bits
         */
        public NumericFingerprintGenerator(int iterations)
        {
            this.iterations = iterations;
        }

        public object MessageDigest { get; private set; }

        /**
         * Generate a scannable and displayble fingerprint.
         *
         * @param localStableIdentifier The client's "stable" identifier.
         * @param localIdentityKey The client's identity key.
         * @param remoteStableIdentifier The remote party's "stable" identifier.
         * @param remoteIdentityKey The remote party's identity key.
         * @return A unique fingerprint for this conversation.
         */

        public Fingerprint createFor(string localStableIdentifier, IdentityKey localIdentityKey,
                               string remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            return createFor(localStableIdentifier,
                new List<IdentityKey>(new[] { localIdentityKey }),
                remoteStableIdentifier,
                new List<IdentityKey>(new[] { remoteIdentityKey }));
        }

        /**
        * Generate a scannable and displayble fingerprint for logical identities that have multiple
        * physical keys.
        *
        * Do not trust the output of this unless you've been through the device consistency process
        * for the provided localIdentityKeys.
        *
        * @param localStableIdentifier The client's "stable" identifier.
        * @param localIdentityKeys The client's collection of physical identity keys.
        * @param remoteStableIdentifier The remote party's "stable" identifier.
        * @param remoteIdentityKeys The remote party's collection of physical identity key.
        * @return A unique fingerprint for this conversation.
        */
        public Fingerprint createFor(string localStableIdentifier, List<IdentityKey> localIdentityKeys,
            string remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
        {
            byte[] localFingerprint = getFingerprint(iterations, localStableIdentifier, localIdentityKeys);
            byte[] remoteFingerprint = getFingerprint(iterations, remoteStableIdentifier, remoteIdentityKeys);

            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint, remoteFingerprint);

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(localFingerprint, remoteFingerprint);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        private byte[] getFingerprint(int iterations, string stableIdentifier, List<IdentityKey> unsortedIdentityKeys)
        {
            try
            {
                SHA512 digest = SHA512.Create();
                byte[] publicKey = getLogicalKeyBytes(unsortedIdentityKeys);
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(FINGERPRINT_VERSION),
                    publicKey, Encoding.UTF8.GetBytes(stableIdentifier));

                for (int i = 0; i < iterations; i++)
                {
                    hash = digest.ComputeHash(ByteUtil.combine(new byte[][]
                    {
                        hash, publicKey
                    }));
                }

                return hash;
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        private byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys)
        {
            List<IdentityKey> sortedIdentityKeys = new List<IdentityKey>(identityKeys);
            sortedIdentityKeys.Sort(new IdentityKeyComparator());

            MemoryStream baos = new MemoryStream();

            foreach (IdentityKey identityKey in sortedIdentityKeys)
            {
                byte[] publicKeyBytes = identityKey.getPublicKey().serialize();
                baos.Write(publicKeyBytes, 0, publicKeyBytes.Length);
            }

            return baos.ToArray();
        }
    }

}