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
    /**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
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

        /**
         * @return the device ID this PreKey belongs to.
         */
        public uint getDeviceId()
        {
            return deviceId;
        }

        /**
         * @return the unique key ID for this PreKey.
         */
        public uint getPreKeyId()
        {
            return preKeyId;
        }

        /**
         * @return the public key for this PreKey.
         */
        public ECPublicKey getPreKey()
        {
            return preKeyPublic;
        }

        /**
         * @return the unique key ID for this signed prekey.
         */
        public uint getSignedPreKeyId()
        {
            return signedPreKeyId;
        }

        /**
         * @return the signed prekey for this PreKeyBundle.
         */
        public ECPublicKey getSignedPreKey()
        {
            return signedPreKeyPublic;
        }

        /**
         * @return the signature over the signed  prekey.
         */
        public byte[] getSignedPreKeySignature()
        {
            return signedPreKeySignature;
        }

        /**
         * @return the {@link org.whispersystems.libsignal.IdentityKey} of this PreKeys owner.
         */
        public IdentityKey getIdentityKey()
        {
            return identityKey;
        }

        /**
         * @return the registration ID associated with this PreKey.
         */
        public uint getRegistrationId()
        {
            return registrationId;
        }
    }
}
