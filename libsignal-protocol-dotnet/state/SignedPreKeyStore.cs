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
        /// <summary>
        /// Load a local SignedPreKeyRecord.
        /// </summary>
        /// <param name="signedPreKeyId">the ID of the local SignedPreKeyRecord.</param>
        /// <returns>the corresponding SignedPreKeyRecord.</returns>
        /// <exception cref="InvalidKeyIdException">when there is no corresponding SignedPreKeyRecord.</exception>
        SignedPreKeyRecord LoadSignedPreKey(uint signedPreKeyId);

        /// <summary>
        /// Load all local SignedPreKeyRecords.
        /// </summary>
        /// <returns>All stored SignedPreKeyRecords.</returns>
        List<SignedPreKeyRecord> LoadSignedPreKeys();

        /// <summary>
        /// Store a local SignedPreKeyRecord.
        /// </summary>
        /// <param name="signedPreKeyId">the ID of the SignedPreKeyRecord to store.</param>
        /// <param name="record">the SignedPreKeyRecord.</param>
        void StoreSignedPreKey(uint signedPreKeyId, SignedPreKeyRecord record);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedPreKeyId">A SignedPreKeyRecord ID.</param>
        /// <returns>true if the store has a record for the signedPreKeyId, otherwise false.</returns>
        bool ContainsSignedPreKey(uint signedPreKeyId);

        /// <summary>
        /// Delete a SignedPreKeyRecord from local storage.
        /// </summary>
        /// <param name="signedPreKeyId">The ID of the SignedPreKeyRecord to remove.</param>
        void RemoveSignedPreKey(uint signedPreKeyId);
    }
}
