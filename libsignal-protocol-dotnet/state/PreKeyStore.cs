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

namespace libsignal.state
{
    /**
     * An interface describing the local storage of {@link PreKeyRecord}s.
     *
     * @author
     */
    public interface PreKeyStore
    {

        /**
         * Load a local PreKeyRecord.
         *
         * @param preKeyId the ID of the local PreKeyRecord.
         * @return the corresponding PreKeyRecord.
         * @throws InvalidKeyIdException when there is no corresponding PreKeyRecord.
         */
        PreKeyRecord LoadPreKey(uint preKeyId);

        /**
         * Store a local PreKeyRecord.
         *
         * @param preKeyId the ID of the PreKeyRecord to store.
         * @param record the PreKeyRecord.
         */
        void StorePreKey(uint preKeyId, PreKeyRecord record);

        /**
         * @param preKeyId A PreKeyRecord ID.
         * @return true if the store has a record for the preKeyId, otherwise false.
         */
         bool ContainsPreKey(uint preKeyId);

        /**
         * Delete a PreKeyRecord from local storage.
         *
         * @param preKeyId The ID of the PreKeyRecord to remove.
         */
        void RemovePreKey(uint preKeyId);

    }
}
