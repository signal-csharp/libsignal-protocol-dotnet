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

using libsignal.ecc.impl;
using System.Security.Cryptography;

namespace libsignal.ecc
{
	/// <summary>
	/// Choose between various implementations of Curve25519 (native, managed, etc).
	/// </summary>
	public enum Curve25519ProviderType
	{
		/// <summary>
		/// Attempt to provide a native implementation. If one is not available, error out (TODO, break apart managed and native implementations in NuGet packages where we can dynamically use what is best based on the current environment).
		/// </summary>
		BEST = 0x05,
		/// <summary>
		/// Explicitly use the native implementation
		/// </summary>
		NATIVE
	}

	class Curve25519
	{
		private static Curve25519 instance;
		private ICurve25519Provider provider;

		private Curve25519() { }

		/// <summary>
		/// Accesses the currently in use Curve25519 provider, according to the type requested.
		/// </summary>
		/// <param name="type">Type of provider requested.</param>
		/// <returns>Provider</returns>
		public static Curve25519 getInstance(Curve25519ProviderType type)
		{
			if (instance == null)
            {
                instance = new Curve25519();
                switch (type)
                {
                    case Curve25519ProviderType.NATIVE:
                        {
                            instance.provider = (ICurve25519Provider)new Curve25519NativeProvider();
                            break;
                        }
                    case Curve25519ProviderType.BEST:
                        {
                            instance.provider = (ICurve25519Provider)new Curve25519ManagedProvider(
                                org.whispersystems.curve25519.Curve25519.BEST);
                            break;
                        }
                }
			}
			return instance;
		}

		/// <summary>
		/// <see cref="Curve25519" /> is backed by a WinRT implementation of curve25519. Returns true for native.
		/// </summary>
		/// <returns>True. Backed by a native provider.</returns>
		public bool isNative()
		{
			return provider.isNative();
		}

		/// <summary>
		/// Generates a Curve25519 keypair.
		/// </summary>
		/// <returns>A randomly generated Curve25519 keypair.</returns>
		public Curve25519KeyPair generateKeyPair()
		{
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] random = new byte[32];
                rng.GetBytes(random);
                byte[] privateKey = provider.generatePrivateKey(random);
                byte[] publicKey = provider.generatePublicKey(privateKey);
                return new Curve25519KeyPair(publicKey, privateKey);
            }
		}

		/// <summary>
		/// Calculates an ECDH agreement.
		/// </summary>
		/// <param name="publicKey">The Curve25519 (typically remote party's) public key.</param>
		/// <param name="privateKey">The Curve25519 (typically yours) private key.</param>
		/// <returns>A 32-byte shared secret.</returns>
		public byte[] calculateAgreement(byte[] publicKey, byte[] privateKey)
		{
			return provider.calculateAgreement(privateKey, publicKey);
		}

		/// <summary>
		/// Calculates a Curve25519 signature.
		/// </summary>
		/// <param name="privateKey">The private Curve25519 key to create the signature with.</param>
		/// <param name="message">The message to sign.</param>
		/// <returns>64 byte signature</returns>
		public byte[] calculateSignature(byte[] privateKey, byte[] message)
		{
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] random = new byte[64];
                rng.GetBytes(random);
                return provider.calculateSignature(random, privateKey, message);
            }
		}

		/// <summary>
		/// Verify a Curve25519 signature.
		/// </summary>
		/// <param name="publicKey">The Curve25519 public key the signature belongs to.</param>
		/// <param name="message">The message that was signed.</param>
		/// <param name="signature">The signature to verify.</param>
		/// <returns>Boolean for if valid</returns>
		public bool verifySignature(byte[] publicKey, byte[] message, byte[] signature)
		{
			return provider.verifySignature(publicKey, message, signature);
		}

        public byte[] calculateVrfSignature(byte[] privateKey, byte[] message)
        {
            return provider.calculateVrfSignature(privateKey, message);
        }

        public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return provider.verifyVrfSignature(publicKey, message, signature);
        }
	}

	/// <summary>
	/// Curve25519 public and private key stored together.
	/// </summary>
	public class Curve25519KeyPair
	{

		private readonly byte[] publicKey;
		private readonly byte[] privateKey;

		/// <summary>
		/// Create a curve 25519 keypair from a public and private keys.
		/// </summary>
		/// <param name="publicKey">32 byte public key</param>
		/// <param name="privateKey">32 byte private key</param>
		public Curve25519KeyPair(byte[] publicKey, byte[] privateKey)
		{
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}

		/// <summary>
		/// Curve25519 public key
		/// </summary>
		/// <returns></returns>
		public byte[] getPublicKey()
		{
			return publicKey;
		}

		/// <summary>
		/// Curve25519 private key
		/// </summary>
		/// <returns></returns>
		public byte[] getPrivateKey()
		{
			return privateKey;
		}
	}
}
