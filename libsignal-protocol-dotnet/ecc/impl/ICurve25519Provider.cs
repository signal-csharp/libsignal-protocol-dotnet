/** 
 * Copyright (C) 2017 langboost, golf1052
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
	/// <summary>
	/// If you want to expose an implementation of Curve25519 to this class library,
	/// implement this interface.
	/// </summary>
	public interface ICurve25519Provider
	{
		byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic);
		byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message);
		byte[] generatePrivateKey(byte[] random);
		byte[] generatePublicKey(byte[] privateKey);
		bool isNative();
		bool verifySignature(byte[] publicKey, byte[] message, byte[] signature);
        byte[] calculateVrfSignature(byte[] privateKey, byte[] message);
        byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature);
	}
}