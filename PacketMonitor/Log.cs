using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NLog;

namespace PacketMonitor.Log
{
    class Log
    {
        public static Logger MainLogger = LogManager.GetLogger("Main");
        public static Logger SSLLogger = LogManager.GetLogger("SSL");
    }

}
