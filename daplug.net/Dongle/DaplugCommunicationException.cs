﻿using System;

namespace daplug.net.Dongle
{
    [Serializable]
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
