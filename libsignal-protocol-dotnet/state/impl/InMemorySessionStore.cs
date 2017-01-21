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
    public class InMemorySessionStore : SessionStore
	{

		static object Lock = new object();

		private IDictionary<SignalProtocolAddress, byte[]> sessions = new Dictionary<SignalProtocolAddress, byte[]>();

		public InMemorySessionStore() { }

		//[MethodImpl(MethodImplOptions.Synchronized)]
		public SessionRecord LoadSession(SignalProtocolAddress remoteAddress)
		{
			try
			{
				if (ContainsSession(remoteAddress))
				{
					byte[] session;
					sessions.TryGetValue(remoteAddress, out session); // get()

					return new SessionRecord(session);
				}
				else
				{
					return new SessionRecord();
				}
			}
			catch (Exception e)
			{
				throw new Exception(e.Message);
			}
		}


		public List<uint> GetSubDeviceSessions(String name)
		{
			List<uint> deviceIds = new List<uint>();

			foreach (SignalProtocolAddress key in sessions.Keys) //keySet()
			{
				if (key.getName().Equals(name) &&
					key.getDeviceId() != 1)
				{
					deviceIds.Add(key.getDeviceId());
				}
			}

			return deviceIds;
		}


		public void StoreSession(SignalProtocolAddress address, SessionRecord record)
		{
			sessions[address] = record.serialize();
		}


		public bool ContainsSession(SignalProtocolAddress address)
		{
			return sessions.ContainsKey(address);
		}


		public void DeleteSession(SignalProtocolAddress address)
		{
			sessions.Remove(address);
		}


		public void DeleteAllSessions(String name)
		{
			foreach (SignalProtocolAddress key in sessions.Keys) // keySet()
			{
				if (key.getName().Equals(name))
				{
					sessions.Remove(key);
				}
			}
		}
	}
}
