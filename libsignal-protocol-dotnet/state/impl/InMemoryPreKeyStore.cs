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

using System;
using System.Collections.Generic;

namespace libsignal.state.impl
{
    public class InMemoryPreKeyStore : PreKeyStore
	{

		private readonly IDictionary<uint, byte[]> store = new Dictionary<uint, byte[]>();


		public PreKeyRecord LoadPreKey(uint preKeyId)
		{
			try
			{
				if (!store.ContainsKey(preKeyId))
				{
					throw new InvalidKeyIdException("No such prekeyrecord!");
				}
				byte[] record;
				store.TryGetValue(preKeyId, out record);  // get()

				return new PreKeyRecord(record);
			}
			catch (Exception e)
			{
				throw new Exception(e.Message);
			}
		}


		public void StorePreKey(uint preKeyId, PreKeyRecord record)
		{
			store[preKeyId] = record.serialize();
		}


		public bool ContainsPreKey(uint preKeyId)
		{
			return store.ContainsKey(preKeyId);
		}


		public void RemovePreKey(uint preKeyId)
		{
			store.Remove(preKeyId);
		}
	}
}
