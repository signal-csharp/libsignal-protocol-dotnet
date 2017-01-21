/** 
 * Copyright (C) 2017 golf1052
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

namespace libsignal.util
{
    public abstract class ByteArrayComparator
    {
        protected int compare(byte[] left, byte[] right)
        {
            for (int i = 0, j = 0; i < left.Length && j < right.Length; i++, j++)
            {
                int a = (left[i] & 0xff);
                int b = (right[j] & 0xff);

                if (a != b)
                {
                    return a - b;
                }
            }

            return left.Length - right.Length;
        }
    }
}
