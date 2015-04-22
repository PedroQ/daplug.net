using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{
    public class DaplugAPIException : Exception
    {
        public DaplugAPIException() { }
        public DaplugAPIException(string message) : base(message) { }
        public DaplugAPIException(string message, Exception inner) : base(message, inner) { }
        protected DaplugAPIException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
