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
using System.Linq;

namespace libsignal
{
    public class InvalidMessageException : Exception
    {

        public InvalidMessageException() { }

        public InvalidMessageException(String detailMessage)
                        : base(detailMessage)
        {

        }

        public InvalidMessageException(Exception exception)
                        : base(exception.Message)
        {

        }

        public InvalidMessageException(String detailMessage, Exception exception)
                        : base(detailMessage, exception)
        {

        }

        public InvalidMessageException(String detailMessage, List<Exception> exceptions)
                        : base(string.Join(",", exceptions.Select(x => x.Message).ToArray()))
        {

        }
        public InvalidMessageException(String detailMessage, LinkedList<Exception> exceptions)
                        : base(string.Join(",", exceptions.Select(x => x.Message).ToArray()))
        {

        }
    }
}
