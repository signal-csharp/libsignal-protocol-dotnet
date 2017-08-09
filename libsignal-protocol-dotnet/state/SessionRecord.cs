using Google.Protobuf;
using System.Collections.Generic;
using System.Linq;

namespace libsignal.state
{
    /// <summary>
    /// A SessionRecord encapsulates the state of an ongoing session.</summary>
    public class SessionRecord
    {
        private static int ARCHIVED_STATES_MAX_LENGTH = 40;

        private SessionState sessionState = new SessionState();
        private LinkedList<SessionState> previousStates = new LinkedList<SessionState>();
        private bool fresh = false;

        public SessionRecord()
        {
            this.fresh = true;
        }

        public SessionRecord(SessionState sessionState)
        {
            this.sessionState = sessionState;
            this.fresh = false;
        }

        public SessionRecord(byte[] serialized)
        {
            RecordStructure record = RecordStructure.Parser.ParseFrom(serialized);
            this.sessionState = new SessionState(record.CurrentSession);
            this.fresh = false;

            foreach (SessionStructure previousStructure in record.PreviousSessions)
            {
                previousStates.AddLast(new SessionState(previousStructure)); // add -> AddLast (java)
            }
        }

        public bool hasSessionState(uint version, byte[] aliceBaseKey)
        {
            if (sessionState.getSessionVersion() == version && Enumerable.SequenceEqual(aliceBaseKey, sessionState.getAliceBaseKey()))
            {
                return true;
            }
            foreach (SessionState state in previousStates)
            {
                if (state.getSessionVersion() == version && Enumerable.SequenceEqual(aliceBaseKey, state.getAliceBaseKey()))
                {
                    return true;
                }
            }
            return false;
        }

        public SessionState getSessionState()
        {
            return sessionState;
        }

        /// <returns>
        /// return the list of all currently maintained "previous" session states.</returns>
        public LinkedList<SessionState> getPreviousSessionStates()
        {
            return previousStates;
        }

        public void RemovePreviousSessionStates()
        {
            previousStates.Clear();
        }

        public bool isFresh()
        {
            return fresh;
        }

         /// <summary>
         /// Move the current SessionState into the list of "previous" session states,
         /// and replace the current SessionState with a fresh reset instance.</summary>
        public void archiveCurrentState()
        {
            promoteState(new SessionState());
        }

        public void promoteState(SessionState promotedState)
        {
            this.previousStates.AddFirst(sessionState);
            this.sessionState = promotedState;
            if (previousStates.Count > ARCHIVED_STATES_MAX_LENGTH)
            {
                previousStates.RemoveLast();
            }
        }

        public void setState(SessionState sessionState)
        {
            this.sessionState = sessionState;
        }

        /// <returns>
        /// Returns a serialized version of the current SessionRecord.</returns>
        public byte[] serialize()
        {
            List<SessionStructure> previousStructures = new List<SessionStructure>();
            foreach (SessionState previousState in previousStates)
            {
                previousStructures.Add(previousState.getStructure());
            }
            RecordStructure record = new RecordStructure
            {
                CurrentSession = sessionState.getStructure(),
            };
            record.PreviousSessions.AddRange(previousStructures);
            return record.ToByteArray();
        }
    }
}
