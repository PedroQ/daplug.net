using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{

    [Serializable]
    public class DaplugAPIException : Exception
    {
        public byte ResponseSW1 { get; set; }
        public byte ResponseSW2 { get; set; }

        public DaplugAPIException() { }
        public DaplugAPIException(string message) : base(message) { }
        public DaplugAPIException(string message, Exception inner) : base(message, inner) { }
        public DaplugAPIException(string message, byte sw1, byte sw2) : base(message)
        {
            this.ResponseSW1 = sw1;
            this.ResponseSW2 = sw2;
        }
        protected DaplugAPIException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }

        public override String Message
        {
            get
            {
                string msg = base.Message;
                if (ResponseSW1 != 0 && ResponseSW2 != 0)
                {
                    string errorString = string.Format("Response SW: 0x{0:X2}{1:X2} ({0} {1})", ResponseSW1, ResponseSW2);
                    return msg + Environment.NewLine + errorString;
                }
                else
                    return msg;
            }
        }
    }
}
