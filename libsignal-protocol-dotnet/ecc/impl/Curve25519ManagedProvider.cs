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

namespace libsignal.ecc.impl
{
    class Curve25519ManagedProvider : ICurve25519Provider
    {
        private org.whispersystems.curve25519.Curve25519 curve;
        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="type">Such as Curve25519.CSHARP or Curve25519.BEST</param>
        public Curve25519ManagedProvider(string type)
        {
            curve = org.whispersystems.curve25519.Curve25519.getInstance(type);
        }

        public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            return curve.calculateAgreement(theirPublic, ourPrivate);
        }

        public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            return curve.calculateSignature(random, privateKey, message);
        }

        public byte[] calculateVrfSignature(byte[] privateKey, byte[] message)
        {
            return curve.calculateVrfSignature(privateKey, message);
        }

        public byte[] generatePrivateKey(byte[] random)
        {
            return curve.generatePrivateKey(random);
        }

        public byte[] generatePublicKey(byte[] privateKey)
        {
            return curve.generatePublicKey(privateKey);
        }

        public bool isNative()
        {
            return curve.isNative();
        }

        public bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return curve.verifySignature(publicKey, message, signature);
        }

        public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return curve.verifyVrfSignature(publicKey, message, signature);
        }
    }
}
