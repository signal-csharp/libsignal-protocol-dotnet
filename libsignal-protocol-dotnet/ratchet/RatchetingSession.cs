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
using libsignal.protocol;
using libsignal.state;
using libsignal.util;
using Strilanc.Value;
using System;
using System.IO;
using System.Text;

namespace libsignal.ratchet
{
    public class RatchetingSession
    {

        public static void initializeSession(SessionState sessionState,
                                             SymmetricSignalProtocolParameters parameters)
        {
            if (isAlice(parameters.getOurBaseKey().getPublicKey(), parameters.getTheirBaseKey()))
            {
                AliceSignalProtocolParameters.Builder aliceParameters = AliceSignalProtocolParameters.newBuilder();

                aliceParameters.setOurBaseKey(parameters.getOurBaseKey())
                               .setOurIdentityKey(parameters.getOurIdentityKey())
                               .setTheirRatchetKey(parameters.getTheirRatchetKey())
                               .setTheirIdentityKey(parameters.getTheirIdentityKey())
                               .setTheirSignedPreKey(parameters.getTheirBaseKey())
                               .setTheirOneTimePreKey(May<ECPublicKey>.NoValue);

                RatchetingSession.initializeSession(sessionState, aliceParameters.create());
            }
            else
            {
                BobSignalProtocolParameters.Builder bobParameters = BobSignalProtocolParameters.newBuilder();

                bobParameters.setOurIdentityKey(parameters.getOurIdentityKey())
                             .setOurRatchetKey(parameters.getOurRatchetKey())
                             .setOurSignedPreKey(parameters.getOurBaseKey())
                             .setOurOneTimePreKey(May<ECKeyPair>.NoValue)
                             .setTheirBaseKey(parameters.getTheirBaseKey())
                             .setTheirIdentityKey(parameters.getTheirIdentityKey());

                RatchetingSession.initializeSession(sessionState, bobParameters.create());
            }
        }

        public static void initializeSession(SessionState sessionState, AliceSignalProtocolParameters parameters)

        {
            try
            {
                sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
                sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
                sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

                ECKeyPair sendingRatchetKey = Curve.generateKeyPair();
                MemoryStream secrets = new MemoryStream();

                byte[] discontinuityBytes = getDiscontinuityBytes();
                secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);

                byte[] agree1 = Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                                       parameters.getOurIdentityKey().getPrivateKey());
                byte[] agree2 = Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                                        parameters.getOurBaseKey().getPrivateKey());
                byte[] agree3 = Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                                       parameters.getOurBaseKey().getPrivateKey());

                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);


                if (parameters.getTheirOneTimePreKey().HasValue)
                {
                    byte[] otAgree = Curve.calculateAgreement(parameters.getTheirOneTimePreKey().ForceGetValue(),
                                                           parameters.getOurBaseKey().getPrivateKey());
                    secrets.Write(otAgree, 0, otAgree.Length);
                }

                DerivedKeys derivedKeys = calculateDerivedKeys(secrets.ToArray());
                Pair<RootKey, ChainKey> sendingChain = derivedKeys.getRootKey().createChain(parameters.getTheirRatchetKey(), sendingRatchetKey);

                sessionState.addReceiverChain(parameters.getTheirRatchetKey(), derivedKeys.getChainKey());
                sessionState.setSenderChain(sendingRatchetKey, sendingChain.second());
                sessionState.setRootKey(sendingChain.first());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        public static void initializeSession(SessionState sessionState,
                                             BobSignalProtocolParameters parameters)
        {

            try
            {
                sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
                sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
                sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

                MemoryStream secrets = new MemoryStream();

                byte[] discontinuityBytes = getDiscontinuityBytes();
                secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);

                byte[] agree1 = Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                                       parameters.getOurSignedPreKey().getPrivateKey());
                byte[] agree2 = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                       parameters.getOurIdentityKey().getPrivateKey());
                byte[] agree3 = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                       parameters.getOurSignedPreKey().getPrivateKey());
                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);

                if (parameters.getOurOneTimePreKey().HasValue)
                {
                    byte[] otAgree = Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                                           parameters.getOurOneTimePreKey().ForceGetValue().getPrivateKey());
                    secrets.Write(otAgree, 0, otAgree.Length);
                }

                DerivedKeys derivedKeys = calculateDerivedKeys(secrets.ToArray());

                sessionState.setSenderChain(parameters.getOurRatchetKey(), derivedKeys.getChainKey());
                sessionState.setRootKey(derivedKeys.getRootKey());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        private static byte[] getDiscontinuityBytes()
        {
            byte[] discontinuity = new byte[32];
            //Arrays.fill(discontinuity, (byte)0xFF);
            for (int i = 0; i < discontinuity.Length; i++)
            {
                discontinuity[i] = 0xFF;
            }
            return discontinuity;
        }

        private static DerivedKeys calculateDerivedKeys(byte[] masterSecret)
        {
            HKDF kdf = new HKDFv3();
            byte[] derivedSecretBytes = kdf.deriveSecrets(masterSecret, Encoding.UTF8.GetBytes("WhisperText"), 64);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);

            return new DerivedKeys(new RootKey(kdf, derivedSecrets[0]),
                                   new ChainKey(kdf, derivedSecrets[1], 0));
        }

        private static bool isAlice(ECPublicKey ourKey, ECPublicKey theirKey)
        {
            return ourKey.CompareTo(theirKey) < 0;
        }

        public class DerivedKeys
        {
            private readonly RootKey rootKey;
            private readonly ChainKey chainKey;

            internal DerivedKeys(RootKey rootKey, ChainKey chainKey)
            {
                this.rootKey = rootKey;
                this.chainKey = chainKey;
            }

            public RootKey getRootKey()
            {
                return rootKey;
            }

            public ChainKey getChainKey()
            {
                return chainKey;
            }
        }
    }
}
