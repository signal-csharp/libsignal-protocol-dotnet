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
    /// <summary>
    /// An interface describing the local storage of <see cref="PreKeyRecord"/>s
    /// </summary>
    public interface PreKeyStore
    {
        /// <summary>
        /// Load a local PreKeyRecord.
        /// </summary>
        /// <param name="preKeyId">the ID of the local PreKeyRecord.</param>
        /// <returns>the corresponding PreKeyRecord.</returns>
        /// <exception cref="InvalidKeyIdException">when there is no corresponding PreKeyRecord.</exception>
        PreKeyRecord LoadPreKey(uint preKeyId);

        /// <summary>
        /// Store a local PreKeyRecord.
        /// </summary>
        /// <param name="preKeyId">the ID of the PreKeyRecord to store.</param>
        /// <param name="record">the PreKeyRecord.</param>
        void StorePreKey(uint preKeyId, PreKeyRecord record);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="preKeyId">A PreKeyRecord ID.</param>
        /// <returns>true if the store has a record for the preKeyId, otherwise false.</returns>
        bool ContainsPreKey(uint preKeyId);

        /// <summary>
        /// Delete a PreKeyRecord from local storage.
        /// </summary>
        /// <param name="preKeyId">The ID of the PreKeyRecord to remove.</param>
        void RemovePreKey(uint preKeyId);

    }
}
