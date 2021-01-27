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

namespace libsignal.state
{
    /// <summary>
    /// A class that contains a remote PreKey and collection of associated items.
    /// </summary>
    public class PreKeyBundle
    {
        private uint registrationId;

        private uint deviceId;

        private uint preKeyId;
        private ECPublicKey preKeyPublic;

        private uint signedPreKeyId;
        private ECPublicKey signedPreKeyPublic;
        private byte[] signedPreKeySignature;

        private IdentityKey identityKey;

        public PreKeyBundle(uint registrationId, uint deviceId, uint preKeyId, ECPublicKey preKeyPublic,
                            uint signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                            IdentityKey identityKey)
        {
            this.registrationId = registrationId;
            this.deviceId = deviceId;
            this.preKeyId = preKeyId;
            this.preKeyPublic = preKeyPublic;
            this.signedPreKeyId = signedPreKeyId;
            this.signedPreKeyPublic = signedPreKeyPublic;
            this.signedPreKeySignature = signedPreKeySignature;
            this.identityKey = identityKey;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the device ID this PreKey belongs to.</returns>
        public uint getDeviceId()
        {
            return deviceId;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the unique key ID for this PreKey.</returns>
        public uint getPreKeyId()
        {
            return preKeyId;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the public key for this PreKey.</returns>
        public ECPublicKey getPreKey()
        {
            return preKeyPublic;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the unique key ID for this signed prekey.</returns>
        public uint getSignedPreKeyId()
        {
            return signedPreKeyId;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the signed prekey for this PreKeyBundle.</returns>
        public ECPublicKey getSignedPreKey()
        {
            return signedPreKeyPublic;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the signature over the signed prekey.</returns>
        public byte[] getSignedPreKeySignature()
        {
            return signedPreKeySignature;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the <see cref="IdentityKey"/> of this PreKeys owner.</returns>
        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>the registration ID associated with this PreKey.</returns>
        public uint getRegistrationId()
        {
            return registrationId;
        }
    }
}
