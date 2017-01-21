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

namespace libsignal
{
    public class InvalidKeyException : Exception
    {

        public InvalidKeyException() { }

        public InvalidKeyException(String detailMessage)
            : base(detailMessage)
        {

        }

        public InvalidKeyException(Exception exception)
            : base(exception.Message)
        {

        }

        public InvalidKeyException(String detailMessage, Exception exception)
            : base(detailMessage, exception)
        {

        }
    }
}
