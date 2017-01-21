/** 
* Copyright (C) 2017 smndtrl, langboost, golf1052
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
using System.Diagnostics;
using System.Text;
using libsignal;
using libsignal.util;

namespace org.whispersystems.libsignal.fingerprint
{
    public class DisplayableFingerprint
    {
        private readonly string localFingerprintNumbers;
        private readonly string remoteFingerprintNumbers;

        internal DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint)
        {
            this.localFingerprintNumbers = getDisplayStringFor(localFingerprint);
            this.remoteFingerprintNumbers = getDisplayStringFor(remoteFingerprint);
        }

        public string getDisplayText()
        {
            if (localFingerprintNumbers.CompareTo(remoteFingerprintNumbers) <= 0)
            {
                return localFingerprintNumbers + remoteFingerprintNumbers;
            }
            else
            {
                return remoteFingerprintNumbers + localFingerprintNumbers;
            }
        }

        private string getDisplayStringFor(byte[] fingerprint)
        {
            return getEncodedChunk(fingerprint, 0) +
                getEncodedChunk(fingerprint, 5) +
                getEncodedChunk(fingerprint, 10) +
                getEncodedChunk(fingerprint, 15) +
                getEncodedChunk(fingerprint, 20) +
                getEncodedChunk(fingerprint, 25);
        }

        private string getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return string.Format("{0:d5}", chunk);
        }
    }
}