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

using System.Collections.Generic;

namespace libsignal.state
{
    public interface SignedPreKeyStore
    {


        /**
         * Load a local SignedPreKeyRecord.
         *
         * @param signedPreKeyId the ID of the local SignedPreKeyRecord.
         * @return the corresponding SignedPreKeyRecord.
         * @throws InvalidKeyIdException when there is no corresponding SignedPreKeyRecord.
         */
        SignedPreKeyRecord LoadSignedPreKey(uint signedPreKeyId);

        /**
         * Load all local SignedPreKeyRecords.
         *
         * @return All stored SignedPreKeyRecords.
         */
        List<SignedPreKeyRecord> LoadSignedPreKeys();

        /**
         * Store a local SignedPreKeyRecord.
         *
         * @param signedPreKeyId the ID of the SignedPreKeyRecord to store.
         * @param record the SignedPreKeyRecord.
         */
        void StoreSignedPreKey(uint signedPreKeyId, SignedPreKeyRecord record);

        /**
         * @param signedPreKeyId A SignedPreKeyRecord ID.
         * @return true if the store has a record for the signedPreKeyId, otherwise false.
         */
        bool ContainsSignedPreKey(uint signedPreKeyId);

        /**
         * Delete a SignedPreKeyRecord from local storage.
         *
         * @param signedPreKeyId The ID of the SignedPreKeyRecord to remove.
         */
        void RemoveSignedPreKey(uint signedPreKeyId);
    }
}
