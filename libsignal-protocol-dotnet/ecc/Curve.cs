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

namespace libsignal.ecc
{
    public class Curve
    {
        public const int DJB_TYPE = 0x05;

        public static bool isNative()
        {
            return Curve25519.getInstance(Curve25519ProviderType.BEST).isNative();
        }

        public static ECKeyPair generateKeyPair()
        {
            Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519ProviderType.BEST).generateKeyPair();

            return new ECKeyPair(new DjbECPublicKey(keyPair.getPublicKey()),
                                 new DjbECPrivateKey(keyPair.getPrivateKey()));
        }

        public static ECPublicKey decodePoint(byte[] bytes, int offset)
        {
            if (bytes == null || bytes.Length - offset < 1)
            {
                throw new InvalidKeyException("No key type identifier");
            }
            int type = bytes[offset] & 0xFF;

            switch (type)
            {
                case Curve.DJB_TYPE:
                    if (bytes.Length - offset < 33)
                    {
                        throw new InvalidKeyException("Bad key length: " + bytes.Length);
                    }

                    byte[] keyBytes = new byte[32];
                    System.Buffer.BlockCopy(bytes, offset + 1, keyBytes, 0, keyBytes.Length);
                    return new DjbECPublicKey(keyBytes);
                default:
                    throw new InvalidKeyException("Bad key type: " + type);
            }
        }

        public static ECPrivateKey decodePrivatePoint(byte[] bytes)
        {
            return new DjbECPrivateKey(bytes);
        }

        public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
        {
            if (publicKey == null)
            {
                throw new InvalidKeyException("public value is null");
            }

            if (privateKey == null)
            {
                throw new InvalidKeyException("private value is null");
            }

            if (publicKey.getType() != privateKey.getType())
            {
                throw new InvalidKeyException("Public and private keys must be of the same type!");
            }

            if (publicKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(Curve25519ProviderType.BEST)
                                 .calculateAgreement(((DjbECPublicKey)publicKey).getPublicKey(),
                                                     ((DjbECPrivateKey)privateKey).getPrivateKey());
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + publicKey.getType());
            }
        }

        public static bool verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey == null || message == null || signature == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(Curve25519ProviderType.BEST)
                                 .verifySignature(((DjbECPublicKey)signingKey).getPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
        {
            if (signingKey == null || message == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(Curve25519ProviderType.BEST)
                                 .calculateSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
        {
            if (signingKey == null || message == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(Curve25519ProviderType.BEST)
                    .calculateVrfSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }

        public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
        {
            if (signingKey == null || message == null || signature == null)
            {
                throw new InvalidKeyException("Values must not be null");
            }

            if (signingKey.getType() == DJB_TYPE)
            {
                return Curve25519.getInstance(Curve25519ProviderType.BEST)
                    .verifyVrfSignature(((DjbECPublicKey)signingKey).getPublicKey(), message, signature);
            }
            else
            {
                throw new InvalidKeyException("Unknown type: " + signingKey.getType());
            }
        }
    }
}
