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
using libsignal.kdf;
using libsignal.util;
using System.Text;

namespace libsignal.ratchet
{
    public class RootKey
    {

        private readonly HKDF kdf;
        private readonly byte[] key;

        public RootKey(HKDF kdf, byte[] key)
        {
            this.kdf = kdf;
            this.key = key;
        }

        public byte[] getKeyBytes()
        {
            return key;
        }

        public Pair<RootKey, ChainKey> createChain(ECPublicKey theirRatchetKey, ECKeyPair ourRatchetKey)
        {
            byte[] sharedSecret = Curve.calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
            byte[] derivedSecretBytes = kdf.deriveSecrets(sharedSecret, key, Encoding.UTF8.GetBytes("WhisperRatchet"), DerivedRootSecrets.SIZE);
            DerivedRootSecrets derivedSecrets = new DerivedRootSecrets(derivedSecretBytes);

            RootKey newRootKey = new RootKey(kdf, derivedSecrets.getRootKey());
            ChainKey newChainKey = new ChainKey(kdf, derivedSecrets.getChainKey(), 0);

            return new Pair<RootKey, ChainKey>(newRootKey, newChainKey);
        }
    }
}
