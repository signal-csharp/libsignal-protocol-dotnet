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

using libsignal.groups.state;
using libsignal.protocol;
using libsignal.util;
using System;

namespace libsignal.groups
{
    /**
     * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
     *
     * Once a session has been established, {@link org.whispersystems.libsignal.groups.GroupCipher}
     * can be used to encrypt/decrypt messages in that session.
     * <p>
     * The built sessions are unidirectional: they can be used either for sending or for receiving,
     * but not both.
     *
     * Sessions are constructed per (groupId + senderId + deviceId) tuple.  Remote logical users
     * are identified by their senderId, and each logical recipientId can have multiple physical
     * devices.
     *
     * @author
     */

    public class GroupSessionBuilder
    {

        private readonly SenderKeyStore senderKeyStore;

        public GroupSessionBuilder(SenderKeyStore senderKeyStore)
        {
            this.senderKeyStore = senderKeyStore;
        }

        /**
         * Construct a group session for receiving messages from senderKeyName.
         *
         * @param senderKeyName The (groupId, senderId, deviceId) tuple associated with the SenderKeyDistributionMessage.
         * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
         */
        public void process(SenderKeyName senderKeyName, SenderKeyDistributionMessage senderKeyDistributionMessage)
        {
            lock (GroupCipher.LOCK)
            {
                SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
                senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getId(),
                                                  senderKeyDistributionMessage.getIteration(),
                                                  senderKeyDistributionMessage.getChainKey(),
                                                  senderKeyDistributionMessage.getSignatureKey());
                senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
            }
        }

        /**
         * Construct a group session for sending messages.
         *
         * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
         * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
         */
        public SenderKeyDistributionMessage create(SenderKeyName senderKeyName)
        {
            lock (GroupCipher.LOCK)
            {
                try
                {
                    SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);

                    if (senderKeyRecord.isEmpty())
                    {
                        senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
                                                          0,
                                                          KeyHelper.generateSenderKey(),
                                                          KeyHelper.generateSenderSigningKey());
                        senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
                    }

                    SenderKeyState state = senderKeyRecord.getSenderKeyState();

                    return new SenderKeyDistributionMessage(state.getKeyId(),
                                                            state.getSenderChainKey().getIteration(),
                                                            state.getSenderChainKey().getSeed(),
                                                            state.getSigningKeyPublic());

                }
                catch (Exception e) when (e is InvalidKeyIdException || e is InvalidKeyException)
                {
                    throw new Exception(e.Message);
                }
            }
        }
    }
}
