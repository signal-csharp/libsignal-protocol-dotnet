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

namespace libsignal.util
{
    public class Pair<T1, T2>
    {
        private readonly T1 v1;
        private readonly T2 v2;

        public Pair(T1 v1, T2 v2)
        {
            this.v1 = v1;
            this.v2 = v2;
        }

        public T1 first()
        {
            return v1;
        }

        public T2 second()
        {
            return v2;
        }

        public bool equals(Object o)
        {
            return o is Pair<T1, T2> &&
                equal(((Pair<T1, T2>)o).first(), first()) &&
                equal(((Pair<T1, T2>)o).second(), second());
        }

        public int hashCode()
        {
            return first().GetHashCode() ^ second().GetHashCode();
        }

        private bool equal(Object first, Object second)
        {
            if (first == null && second == null) return true;
            if (first == null || second == null) return false;
            return first.Equals(second);
        }
    }
}
