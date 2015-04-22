using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace daplug.net.Dongle
{
    public class DaplugCommunicationException : Exception
    {
        public DaplugCommunicationException() { }
        public DaplugCommunicationException(string message) : base(message) { }
        public DaplugCommunicationException(string message, Exception inner) : base(message, inner) { }
        protected DaplugCommunicationException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }
}
