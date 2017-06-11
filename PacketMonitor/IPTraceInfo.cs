using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketMonitor.SSL;
using SharpPcap.LibPcap;
using SharpPcap;
using System.IO;

namespace PacketMonitor.IPTraceInfomation
{
    public class IPTraceInfo
    {
        public int No { get; set; }
        public string SrcIP { get; set; }
        public string DstIP { get; set; }
        public List<Port> Ports { get; set; }
        public string SrcLocation { get; set; }
        public string DstLocation { get; set; }
        public string SrcMac { get; set; }
        public string DstMac { get; set; }
        public int SrcToDstStream { get; set; }
        public int DstToSrcStream { get; set; }
        public DateTime FirstPacketTime { get; set; }
        public DateTime LastPacketTime { get; set; }
        public Certificate certificate { get; set; }
        public string Information { get; set; }
    }

    public class Port
    {
        public Port(string _SrcPort, string _DstPort)
        {
            SrcPort = _SrcPort;
            DstPort = _DstPort;
            hasSSL = false;
            SSLPcapFileWriter = null;

            if(int.Parse(_SrcPort) < 1000)
            {
                PortApplication = PortsApplication[int.Parse(_SrcPort)];
            }
            else if (int.Parse(_DstPort) < 1000)
            {
                PortApplication = PortsApplication[int.Parse(_DstPort)];
            }
        }

        public string SrcPort { get; set; }
        public string DstPort { get; set; }
        public bool hasSSL { get; set; }
        public PcapFileWriter SSLPcapFileWriter { get; set; }
        public string PortApplication { get; set; }

        public static void Initial_PortsApplication()
        {
            PortsApplication.Add(25, "SMTP(25)");  
            PortsApplication.Add(80, "HTTP(80)");
            PortsApplication.Add(110, "POP3(110)"); 
            PortsApplication.Add(143, "IMAP(143)");
            PortsApplication.Add(220, "IMAP(220)"); 
            PortsApplication.Add(443, "HTTPS(443)");
            PortsApplication.Add(465, "SMTP_SSL(465)");
            PortsApplication.Add(993, "IMAP_SSL(993)");
            PortsApplication.Add(995, "POP3_SSL(995)");
        }


        public static Dictionary<int, string> PortsApplication = new Dictionary<int, string>();
    }

    public class PcapFileWriter
    {
        public static List<CaptureFileWriterDevice> list = new List<CaptureFileWriterDevice>();

        private const int MaxOpenedFile = 490;
        private CaptureFileWriterDevice Writer;


        public PcapFileWriter(string FileName)
        {
            if ( IsMaxOpenedFile() )
            {
                list[0].Close(); 
                for (int i = 0; i < MaxOpenedFile - 1; i++)
                {
                    list[i] = list[i + 1];
                }
                Writer = new CaptureFileWriterDevice(FileName);
                list[MaxOpenedFile - 1] = Writer;
            }
            else
            {
                Writer = new CaptureFileWriterDevice(FileName);
                list.Add(Writer);
            }         
        }

        public void Write(Byte[] packet)
        {
            Writer.Write(packet);

            int Count = list.Count;
            int index = list.IndexOf(Writer);
            for(int i = index; i< Count-1; i++)
            {
                list[i] = list[i + 1];
            }
            list[Count - 1] = Writer;
        }

        public static void CloseAll()
        {
            foreach(var each in list)
            {
                each.Close();
            }
        }

        private bool IsMaxOpenedFile()
        {
            return list.Count >= MaxOpenedFile ? true : false;
        }

    }
    
}
