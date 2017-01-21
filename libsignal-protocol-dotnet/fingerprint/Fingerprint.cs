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
 
 namespace org.whispersystems.libsignal.fingerprint
{
    public class Fingerprint
    {

        private readonly DisplayableFingerprint displayableFingerprint;
        private readonly ScannableFingerprint scannableFingerprint;

        public Fingerprint(DisplayableFingerprint displayableFingerprint,
                           ScannableFingerprint scannableFingerprint)
        {
            this.displayableFingerprint = displayableFingerprint;
            this.scannableFingerprint = scannableFingerprint;
        }

        /**
         * @return A text fingerprint that can be displayed and compared remotely.
         */
        public DisplayableFingerprint getDisplayableFingerprint()
        {
            return displayableFingerprint;
        }

        /**
         * @return A scannable fingerprint that can be scanned anc compared locally.
         */
        public ScannableFingerprint getScannableFingerprint()
        {
            return scannableFingerprint;
        }
    }
}