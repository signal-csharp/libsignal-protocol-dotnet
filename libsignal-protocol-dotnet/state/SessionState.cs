using System;
using System.Collections.Generic;
using System.Diagnostics;
using Google.Protobuf;
using libsignal.ecc;
using libsignal.kdf;
using libsignal.ratchet;
using libsignal.util;
using Strilanc.Value;
using static libsignal.state.SessionStructure;
using static libsignal.state.SessionStructure.Types;

namespace libsignal.state
{
    public class SessionState
	{
		private static readonly int MAX_MESSAGE_KEYS = 2000;

		private SessionStructure sessionStructure;

		public SessionState()
		{
            this.sessionStructure = new SessionStructure { };
		}

		public SessionState(SessionStructure sessionStructure)
		{
			this.sessionStructure = sessionStructure;
		}

		public SessionState(SessionState copy)
		{
            this.sessionStructure = new SessionStructure(copy.sessionStructure);
		}

		public SessionStructure getStructure()
		{
			return sessionStructure;
		}

		public byte[] getAliceBaseKey()
		{
			return this.sessionStructure.AliceBaseKey.ToByteArray();
		}

		public void setAliceBaseKey(byte[] aliceBaseKey)
		{
            this.sessionStructure.AliceBaseKey = ByteString.CopyFrom(aliceBaseKey);									 
		}

		public void setSessionVersion(uint version)
		{
            this.sessionStructure.SessionVersion = version;
		}

		public uint getSessionVersion()
		{
			uint sessionVersion = this.sessionStructure.SessionVersion;

			if (sessionVersion == 0) return 2;
			else return sessionVersion;
		}

		public void setRemoteIdentityKey(IdentityKey identityKey)
		{
            this.sessionStructure.RemoteIdentityPublic = ByteString.CopyFrom(identityKey.serialize());
		}

		public void setLocalIdentityKey(IdentityKey identityKey)
		{
			this.sessionStructure.LocalIdentityPublic = ByteString.CopyFrom(identityKey.serialize());
		}

		public IdentityKey getRemoteIdentityKey()
		{
			try
			{
				if (this.sessionStructure.RemoteIdentityPublicOneofCase == RemoteIdentityPublicOneofOneofCase.None)
				{
					return null;
				}

				return new IdentityKey(this.sessionStructure.RemoteIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				Debug.WriteLine(e.ToString(), "SessionRecordV2");
				return null;
			}
		}

		public IdentityKey getLocalIdentityKey()
		{
			try
			{
				return new IdentityKey(this.sessionStructure.LocalIdentityPublic.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public uint getPreviousCounter()
		{
			return sessionStructure.PreviousCounter;
		}

		public void setPreviousCounter(uint previousCounter)
		{
			this.sessionStructure.PreviousCounter = previousCounter;
		}

		public RootKey getRootKey()
		{
			return new RootKey(HKDF.createFor(getSessionVersion()),
							   this.sessionStructure.RootKey.ToByteArray());
		}

		public void setRootKey(RootKey rootKey)
		{
            this.sessionStructure.RootKey = ByteString.CopyFrom(rootKey.getKeyBytes());
		}

		public ECPublicKey getSenderRatchetKey()
		{
			try
			{
				return Curve.decodePoint(sessionStructure.SenderChain.SenderRatchetKey.ToByteArray(), 0);
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public ECKeyPair getSenderRatchetKeyPair()
		{
			ECPublicKey publicKey = getSenderRatchetKey();
			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.SenderChain
																			   .SenderRatchetKeyPrivate
																			   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public bool hasReceiverChain(ECPublicKey senderEphemeral)
		{
			return getReceiverChain(senderEphemeral) != null;
		}

		public bool hasSenderChain()
		{
			return sessionStructure.SenderChainOneofCase == SenderChainOneofOneofCase.SenderChain;
		}

		private Pair<Chain, uint> getReceiverChain(ECPublicKey senderEphemeral)
		{
			IList<Chain> receiverChains = sessionStructure.ReceiverChains;
			uint index = 0;

			foreach (Chain receiverChain in receiverChains)
			{
				try
				{
					ECPublicKey chainSenderRatchetKey = Curve.decodePoint(receiverChain.SenderRatchetKey.ToByteArray(), 0);

					if (chainSenderRatchetKey.Equals(senderEphemeral))
					{
						return new Pair<Chain, uint>(receiverChain, index);
					}
				}
				catch (InvalidKeyException e)
				{
					Debug.WriteLine(e.ToString(), "SessionRecordV2");
				}

				index++;
			}

			return null;
		}

		public ChainKey getReceiverChainKey(ECPublicKey senderEphemeral)
		{
			Pair<Chain, uint> receiverChainAndIndex = getReceiverChain(senderEphemeral);
			Chain receiverChain = receiverChainAndIndex.first();

			if (receiverChain == null)
			{
				return null;
			}
			else
			{
				return new ChainKey(HKDF.createFor(getSessionVersion()),
									receiverChain.ChainKey.Key.ToByteArray(),
									receiverChain.ChainKey.Index);
			}
		}

		public void addReceiverChain(ECPublicKey senderRatchetKey, ChainKey chainKey)
		{
            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.getKey()),
                Index = chainKey.getIndex()
            };

            Chain chain = new Chain
            {
                ChainKey = chainKeyStructure,
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKey.serialize())
            };
            this.sessionStructure.ReceiverChains.Add(chain);

			while (this.sessionStructure.ReceiverChains.Count > 5)
			{
                this.sessionStructure.ReceiverChains.RemoveAt(0); //TODO why was here a TODO?
			}
		}

		public void setSenderChain(ECKeyPair senderRatchetKeyPair, ChainKey chainKey)
		{
            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.getKey()),
                Index = chainKey.getIndex()
            };

            Chain senderChain = new Chain
            {
                SenderRatchetKey = ByteString.CopyFrom(senderRatchetKeyPair.getPublicKey().serialize()),
                SenderRatchetKeyPrivate = ByteString.CopyFrom(senderRatchetKeyPair.getPrivateKey().serialize()),
                ChainKey = chainKeyStructure
            };

            this.sessionStructure.SenderChain = senderChain;
		}

		public ChainKey getSenderChainKey()
		{
			Chain.Types.ChainKey chainKeyStructure = sessionStructure.SenderChain.ChainKey;
			return new ChainKey(HKDF.createFor(getSessionVersion()),
								chainKeyStructure.Key.ToByteArray(), chainKeyStructure.Index);
		}


		public void setSenderChainKey(ChainKey nextChainKey)
		{
            Chain.Types.ChainKey chainKey = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(nextChainKey.getKey()),
                Index = nextChainKey.getIndex()
            };

            sessionStructure.SenderChain.ChainKey = chainKey;
		}

		public bool hasMessageKeys(ECPublicKey senderEphemeral, uint counter)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

			if (chain == null)
			{
				return false;
			}

			IList<Chain.Types.MessageKey> messageKeyList = chain.MessageKeys;

			foreach (Chain.Types.MessageKey messageKey in messageKeyList)
			{
				if (messageKey.Index == counter)
				{
					return true;
				}
			}

			return false;
		}

		public MessageKeys removeMessageKeys(ECPublicKey senderEphemeral, uint counter)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

			if (chain == null)
			{
				return null;
			}

			List<Chain.Types.MessageKey> messageKeyList = new List<Chain.Types.MessageKey>(chain.MessageKeys);
			IEnumerator<Chain.Types.MessageKey> messageKeyIterator = messageKeyList.GetEnumerator();
			MessageKeys result = null;

			while (messageKeyIterator.MoveNext()) //hasNext()
			{
				Chain.Types.MessageKey messageKey = messageKeyIterator.Current; // next()

				if (messageKey.Index == counter)
				{
					result = new MessageKeys(messageKey.CipherKey.ToByteArray(),
											messageKey.MacKey.ToByteArray(),
											 messageKey.Iv.ToByteArray(),
											 messageKey.Index);

					messageKeyList.Remove(messageKey); //messageKeyIterator.remove();
					break;
				}
			}

            chain.MessageKeys.Clear();
            chain.MessageKeys.AddRange(messageKeyList);

            sessionStructure.ReceiverChains[(int)chainAndIndex.second()] = chain;
            return result;
		}

		public void setMessageKeys(ECPublicKey senderEphemeral, MessageKeys messageKeys)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();
            Chain.Types.MessageKey messageKeyStructure = new Chain.Types.MessageKey
            {
                CipherKey = ByteString.CopyFrom(messageKeys.getCipherKey()),
                MacKey = ByteString.CopyFrom(messageKeys.getMacKey()),
                Index = messageKeys.getCounter(),
                Iv = ByteString.CopyFrom(messageKeys.getIv())
            };

            chain.MessageKeys.Add(messageKeyStructure);
			if (chain.MessageKeys.Count > MAX_MESSAGE_KEYS)
			{
                chain.MessageKeys.RemoveAt(0);
			}

            sessionStructure.ReceiverChains[(int)chainAndIndex.second()] = chain;
        }

		public void setReceiverChainKey(ECPublicKey senderEphemeral, ChainKey chainKey)
		{
			Pair<Chain, uint> chainAndIndex = getReceiverChain(senderEphemeral);
			Chain chain = chainAndIndex.first();

            Chain.Types.ChainKey chainKeyStructure = new Chain.Types.ChainKey
            {
                Key = ByteString.CopyFrom(chainKey.getKey()),
                Index = chainKey.getIndex()
            };

            chain.ChainKey = chainKeyStructure;

            sessionStructure.ReceiverChains[(int) chainAndIndex.second()] = chain;
        }

		public void setPendingKeyExchange(uint sequence,
										  ECKeyPair ourBaseKey,
										  ECKeyPair ourRatchetKey,
										  IdentityKeyPair ourIdentityKey)
		{
            PendingKeyExchange structure = new PendingKeyExchange
            {
                LocalBaseKey = ByteString.CopyFrom(ourBaseKey.getPublicKey().serialize()),
                LocalBaseKeyPrivate = ByteString.CopyFrom(ourBaseKey.getPrivateKey().serialize()),
                LocalRatchetKey = ByteString.CopyFrom(ourRatchetKey.getPublicKey().serialize()),
                LocalRatchetKeyPrivate = ByteString.CopyFrom(ourRatchetKey.getPrivateKey().serialize()),
                LocalIdentityKey = ByteString.CopyFrom(ourIdentityKey.getPublicKey().serialize()),
                LocalIdentityKeyPrivate = ByteString.CopyFrom(ourIdentityKey.getPrivateKey().serialize())
            };

            this.sessionStructure.PendingKeyExchange = structure;
		}

		public uint getPendingKeyExchangeSequence()
		{
			return sessionStructure.PendingKeyExchange.Sequence;
		}

		public ECKeyPair getPendingKeyExchangeBaseKey()
		{
			ECPublicKey publicKey = Curve.decodePoint(sessionStructure.PendingKeyExchange
																.LocalBaseKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalBaseKeyPrivate
																	   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public ECKeyPair getPendingKeyExchangeRatchetKey()
		{
			ECPublicKey publicKey = Curve.decodePoint(sessionStructure.PendingKeyExchange
																.LocalRatchetKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalRatchetKeyPrivate
																	   .ToByteArray());

			return new ECKeyPair(publicKey, privateKey);
		}

		public IdentityKeyPair getPendingKeyExchangeIdentityKey()
		{
			IdentityKey publicKey = new IdentityKey(sessionStructure.PendingKeyExchange
															.LocalIdentityKey.ToByteArray(), 0);

			ECPrivateKey privateKey = Curve.decodePrivatePoint(sessionStructure.PendingKeyExchange
																	   .LocalIdentityKeyPrivate
																	   .ToByteArray());

			return new IdentityKeyPair(publicKey, privateKey);
		}

		public bool hasPendingKeyExchange()
		{
			return sessionStructure.PendingKeyExchangeOneofCase == PendingKeyExchangeOneofOneofCase.PendingKeyExchange;
		}

		public void setUnacknowledgedPreKeyMessage(May<uint> preKeyId, uint signedPreKeyId, ECPublicKey baseKey)
		{
            PendingPreKey pending = new PendingPreKey
            {
                SignedPreKeyId = (int) signedPreKeyId,
                BaseKey = ByteString.CopyFrom(baseKey.serialize())
            };

			if (preKeyId.HasValue)
			{
                pending.PreKeyId = preKeyId.ForceGetValue();
			}

            this.sessionStructure.PendingPreKey = pending;
		}

		public bool hasUnacknowledgedPreKeyMessage()
		{
			return this.sessionStructure.PendingPreKeyOneofCase == PendingPreKeyOneofOneofCase.PendingPreKey;
		}

		public UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems()
		{
			try
			{
				May<uint> preKeyId;

				if (sessionStructure.PendingPreKey.PreKeyIdOneofCase != PendingPreKey.PreKeyIdOneofOneofCase.None)
				{
					preKeyId = new May<uint>(sessionStructure.PendingPreKey.PreKeyId);
				}
				else
				{
					preKeyId = May<uint>.NoValue;
				}

				return
					new UnacknowledgedPreKeyMessageItems(preKeyId,
														 (uint)sessionStructure.PendingPreKey.SignedPreKeyId,
														 Curve.decodePoint(sessionStructure.PendingPreKey
																						   .BaseKey
																						   .ToByteArray(), 0));
			}
			catch (InvalidKeyException e)
			{
				throw new Exception(e.Message);
			}
		}

		public void clearUnacknowledgedPreKeyMessage()
		{
            this.sessionStructure.PendingPreKey = null;
		}

		public void setRemoteRegistrationId(uint registrationId)
		{
            this.sessionStructure.RemoteRegistrationId = registrationId;
		}

		public uint getRemoteRegistrationId()
		{
			return this.sessionStructure.RemoteRegistrationId;
		}

		public void setLocalRegistrationId(uint registrationId)
		{
            this.sessionStructure.LocalRegistrationId = registrationId;
		}

		public uint GetLocalRegistrationId()
		{
			return this.sessionStructure.LocalRegistrationId;
		}

		public byte[] serialize()
		{
			return sessionStructure.ToByteArray();
		}

		public class UnacknowledgedPreKeyMessageItems
		{
			private readonly May<uint> preKeyId;
			private readonly uint signedPreKeyId;
			private readonly ECPublicKey baseKey;

			public UnacknowledgedPreKeyMessageItems(May<uint> preKeyId,
													uint signedPreKeyId,
													ECPublicKey baseKey)
			{
				this.preKeyId = preKeyId;
				this.signedPreKeyId = signedPreKeyId;
				this.baseKey = baseKey;
			}


			public May<uint> getPreKeyId()
			{
				return preKeyId;
			}

			public uint getSignedPreKeyId()
			{
				return signedPreKeyId;
			}

			public ECPublicKey getBaseKey()
			{
				return baseKey;
			}
		}
	}
}
