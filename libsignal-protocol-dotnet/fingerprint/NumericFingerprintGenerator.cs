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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using libsignal;
using libsignal.util;

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

        /// <summary>
        /// Generate a scannable and displayable fingerprint.
        /// </summary>
        /// <param name="version">The version of fingerprint you are generating.</param>
        /// <param name="localStableIdentifier">The client's "stable" identifier.</param>
        /// <param name="localIdentityKey">The client's identity key.</param>
        /// <param name="remoteStableIdentifier">The remote party's "stable" identifier.</param>
        /// <param name="remoteIdentityKey">The remote party's identity key.</param>
        /// <returns>A unique fingerprint for this conversation.</returns>
        public Fingerprint createFor(int version,
            byte[] localStableIdentifier,
            IdentityKey localIdentityKey,
            byte[] remoteStableIdentifier,
            IdentityKey remoteIdentityKey)
        {
            return createFor(version,
                localStableIdentifier,
                new List<IdentityKey>(new[] { localIdentityKey }),
                remoteStableIdentifier,
                new List<IdentityKey>(new[] { remoteIdentityKey }));
        }

        /// <summary>
        /// Generate a scannable and displayable fingerprint for logical identities that have multiple physical keys.
        /// 
        /// Do not trust the output of this unless you've been through the device consistency process for the provided
        /// localIdentityKeys.
        /// </summary>
        /// <param name="version">The version of fingerprint you are generating.</param>
        /// <param name="localStableIdentifier">The client's "stable" identifier.</param>
        /// <param name="localIdentityKeys">The client's collection of physical identity keys.</param>
        /// <param name="remoteStableIdentifier">The remote party's "stable" identifier.</param>
        /// <param name="remoteIdentityKeys">The remote party's collection of physical identity key.</param>
        /// <returns>A unique fingerprint for this conversation.</returns>
        public Fingerprint createFor(int version,
            byte[] localStableIdentifier,
            List<IdentityKey> localIdentityKeys,
            byte[] remoteStableIdentifier,
            List<IdentityKey> remoteIdentityKeys)
        {
            byte[] localFingerprint = getFingerprint(iterations, localStableIdentifier, localIdentityKeys);
            byte[] remoteFingerprint = getFingerprint(iterations, remoteStableIdentifier, remoteIdentityKeys);

            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint,
                remoteFingerprint);

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(version,
                localFingerprint, remoteFingerprint);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        private byte[] getFingerprint(int iterations, byte[] stableIdentifier, List<IdentityKey> unsortedIdentityKeys)
        {
            try
            {
                SHA512 digest = SHA512.Create();
                byte[] publicKey = getLogicalKeyBytes(unsortedIdentityKeys);
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(FINGERPRINT_VERSION),
                    publicKey, stableIdentifier);

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
