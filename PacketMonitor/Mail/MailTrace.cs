using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;
using System.Net;
using System.IO;
using SharpPcap.LibPcap;



namespace PacketMonitor.Mail
{
    // 此部分是追蹤使用 IMAP POP3 SMTP 協定的郵件
    enum MailPort : int
    {
        POP3_1 = 110,
        POP3_2 = 995,

        IMAP_1 = 143,
        IMAP_2 = 993,

        SMTP_1 = 25,
        SMTP_2 = 2525,
        SMTP_3 = 465
    }

    class MailTrace
    {
        #region Static Method
        public static void Trace(Packet packet)
        {
            IpPacket ipPacket = null;
            TcpPacket tcpPacket = null;

            try
            {
                ipPacket = PacketDotNet.IPv4Packet.GetEncapsulated(packet);
                if (ipPacket == null)
                    return;
                tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                if (tcpPacket == null)
                    return;
            }
            catch
            {
                Console.WriteLine();
                return;
            }

            bool _isSend;
            if ( isMailPort(tcpPacket,out _isSend) )
            {
                // analyze whether the mail session is exist.
                if (!MailList.ContainsKey(tcpPacket.SourcePort + tcpPacket.DestinationPort))
                {
                    MailTrace _MailTrace = new MailTrace(ipPacket.SourceAddress, ipPacket.DestinationAddress, tcpPacket.SourcePort, tcpPacket.DestinationPort, _isSend);
                    _MailTrace.PcapFileWriter.Write(packet.Bytes);
                    MailList.Add(tcpPacket.SourcePort + tcpPacket.DestinationPort, _MailTrace);
                    return;
                }

                // the mail session has exist and write it into pcap file.
                MailList[tcpPacket.SourcePort + tcpPacket.DestinationPort].PcapFileWriter.Write(packet.Bytes);

                if ( MailList[tcpPacket.SourcePort + tcpPacket.DestinationPort].MailEnd == true )
                {
                    MailList.Remove(tcpPacket.SourcePort + tcpPacket.DestinationPort);
                }
                if ( tcpPacket.Fin == true ) // the fin flag means the session will be disconnected. First is from Server and Second is from client.
                {
                    MailList[tcpPacket.SourcePort + tcpPacket.DestinationPort].PacketFlagFinCount++;
                    if ( MailList[tcpPacket.SourcePort + tcpPacket.DestinationPort].PacketFlagFinCount == 2 )
                    {
                        MailList[tcpPacket.SourcePort + tcpPacket.DestinationPort].MailEnd = true;                      
                    }
                }
            }
        }

        // analyze whether the port is mail port 
        private static bool isMailPort(TcpPacket e, out bool isSend)
        {
            if ( (MailPort)e.DestinationPort == MailPort.SMTP_1 || (MailPort)e.SourcePort == MailPort.SMTP_1 ||
                 (MailPort)e.DestinationPort == MailPort.SMTP_2 || (MailPort)e.SourcePort == MailPort.SMTP_2 ||
                 (MailPort)e.DestinationPort == MailPort.SMTP_3 || (MailPort)e.SourcePort == MailPort.SMTP_3  )
            {
                isSend = true;
                return true;
            }
            else if ( (MailPort)e.DestinationPort == MailPort.POP3_1 || (MailPort)e.SourcePort == MailPort.POP3_1 ||
                      (MailPort)e.DestinationPort == MailPort.POP3_2 || (MailPort)e.SourcePort == MailPort.POP3_2 ||
                      (MailPort)e.DestinationPort == MailPort.IMAP_1 || (MailPort)e.SourcePort == MailPort.IMAP_1 ||
                      (MailPort)e.DestinationPort == MailPort.IMAP_2 || (MailPort)e.SourcePort == MailPort.IMAP_2  )
            {
                isSend = false;
                return true;
            }
            isSend = false; // this is not mean, just give it a value.
            return false;
        }
        #endregion

        #region Private Method
        private MailTrace(IPAddress _SrcIP, IPAddress _DstIP, ushort _SrcPort, ushort _DstPort, bool isSend)
        {
            SrcIP = _SrcIP;
            DstIP = _DstIP;
            SrcPort = _SrcPort;
            DstPort = _DstPort;
            PacketFlagFinCount = 0;
            MailEnd = false;

            SubFilePath = FileStoragePath.GetPath_AppMail();

            string time = DateTime.Now.TimeOfDay.Hours + "時" + DateTime.Now.TimeOfDay.Minutes + "分" + DateTime.Now.TimeOfDay.Seconds + "." + DateTime.Now.TimeOfDay.Milliseconds + "秒  ";
            MailType = isSend ? "Send     " : "Receive ";
            PcapFileName = MailType + time + SrcIP + " - " + DstIP + ".pcap";
            PcapFileWriter = new CaptureFileWriterDevice(SubFilePath + "\\" + PcapFileName);
        }
        #endregion


        private IPAddress SrcIP;
        private IPAddress DstIP;
        private ushort SrcPort;
        private ushort DstPort;
        private string SubFilePath;
        private string PcapFileName;
        private string MailType;
        private int PacketFlagFinCount;
        private bool MailEnd;
        private CaptureFileWriterDevice PcapFileWriter;

        public static Dictionary<int,MailTrace> MailList = new Dictionary<int, MailTrace>();
    }
}
