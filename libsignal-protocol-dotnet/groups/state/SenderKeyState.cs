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
using Google.Protobuf;
using libsignal.ecc;
using libsignal.groups.ratchet;
using libsignal.state;
using Strilanc.Value;

namespace libsignal.groups.state
{
    /// <summary>
    /// Represents the state of an individual SenderKey ratchet.
    /// </summary>
    public class SenderKeyState
	{
		private static readonly int MAX_MESSAGE_KEYS = 2000;

		private SenderKeyStateStructure senderKeyStateStructure;

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, ECPublicKey signatureKey)
			: this(id, iteration, chainKey, signatureKey, May<ECPrivateKey>.NoValue)
		{
		}

		public SenderKeyState(uint id, uint iteration, byte[] chainKey, ECKeyPair signatureKey)
		: this(id, iteration, chainKey, signatureKey.getPublicKey(), new May<ECPrivateKey>(signatureKey.getPrivateKey()))
		{
		}

		private SenderKeyState(uint id, uint iteration, byte[] chainKey,
							  ECPublicKey signatureKeyPublic,
							  May<ECPrivateKey> signatureKeyPrivate)
		{
            SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure = new SenderKeyStateStructure.Types.SenderChainKey
            {
                Iteration = iteration,
                Seed = ByteString.CopyFrom(chainKey)
            };

            SenderKeyStateStructure.Types.SenderSigningKey signingKeyStructure = new SenderKeyStateStructure.Types.SenderSigningKey
            {
                Public = ByteString.CopyFrom(signatureKeyPublic.serialize())
            };

			if (signatureKeyPrivate.HasValue)
			{
				signingKeyStructure.Private = ByteString.CopyFrom(signatureKeyPrivate.ForceGetValue().serialize());
			}

            this.senderKeyStateStructure = new SenderKeyStateStructure
            {
                SenderKeyId = id,
                SenderChainKey = senderChainKeyStructure,
                SenderSigningKey = signingKeyStructure
            };
		}

		public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure)
		{
			this.senderKeyStateStructure = senderKeyStateStructure;
		}

		public uint getKeyId()
		{
			return senderKeyStateStructure.SenderKeyId;
		}

		public SenderChainKey getSenderChainKey()
		{
			return new SenderChainKey(senderKeyStateStructure.SenderChainKey.Iteration,
									  senderKeyStateStructure.SenderChainKey.Seed.ToByteArray());
		}

		public void setSenderChainKey(SenderChainKey chainKey)
		{
            SenderKeyStateStructure.Types.SenderChainKey senderChainKeyStructure = new SenderKeyStateStructure.Types.SenderChainKey
            {
                Iteration = chainKey.getIteration(),
                Seed = ByteString.CopyFrom(chainKey.getSeed())
            };

            this.senderKeyStateStructure.SenderChainKey = senderChainKeyStructure;
		}

		public ECPublicKey getSigningKeyPublic()
		{
			return Curve.decodePoint(senderKeyStateStructure.SenderSigningKey.Public.ToByteArray(), 0);
		}

		public ECPrivateKey getSigningKeyPrivate()
		{
			return Curve.decodePrivatePoint(senderKeyStateStructure.SenderSigningKey.Private.ToByteArray());
		}

		public bool hasSenderMessageKey(uint iteration)
		{
			foreach (SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey in senderKeyStateStructure.SenderMessageKeys)
			{
				if (senderMessageKey.Iteration == iteration) return true;
			}

			return false;
		}

		public void addSenderMessageKey(SenderMessageKey senderMessageKey)
		{
            SenderKeyStateStructure.Types.SenderMessageKey senderMessageKeyStructure = new SenderKeyStateStructure.Types.SenderMessageKey
            {
                Iteration = senderMessageKey.getIteration(),
                Seed = ByteString.CopyFrom(senderMessageKey.getSeed())
            };
            this.senderKeyStateStructure.SenderMessageKeys.Add(senderMessageKeyStructure);

			if (senderKeyStateStructure.SenderMessageKeys.Count > MAX_MESSAGE_KEYS)
			{
                senderKeyStateStructure.SenderMessageKeys.RemoveAt(0);
			}
		}

		public SenderMessageKey removeSenderMessageKey(uint iteration)
		{
			LinkedList<SenderKeyStateStructure.Types.SenderMessageKey> keys = new LinkedList<SenderKeyStateStructure.Types.SenderMessageKey>(senderKeyStateStructure.SenderMessageKeys);
			IEnumerator<SenderKeyStateStructure.Types.SenderMessageKey> iterator = keys.GetEnumerator(); // iterator();

			SenderKeyStateStructure.Types.SenderMessageKey result = null;

			while (iterator.MoveNext()) // hastNext
			{
				SenderKeyStateStructure.Types.SenderMessageKey senderMessageKey = iterator.Current; // next();

				if (senderMessageKey.Iteration == iteration) //senderMessageKey.getIteration()
				{
					result = senderMessageKey;
					keys.Remove(senderMessageKey); //iterator.remove();
					break;
				}
			}

            this.senderKeyStateStructure.SenderMessageKeys.Clear();
            this.senderKeyStateStructure.SenderMessageKeys.AddRange(keys);

			if (result != null)
			{
				return new SenderMessageKey(result.Iteration, result.Seed.ToByteArray());
			}
			else
			{
				return null;
			}
		}

		public SenderKeyStateStructure getStructure()
		{
			return senderKeyStateStructure;
		}
	}
}
