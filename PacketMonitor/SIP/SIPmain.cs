using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace PacketMonitor.SIP
{
    public class Call
    {
        public enum PacketType
        {
            SIPDialog,
            RTP
        }
        public enum CallDirection
        {
            Caller,
            Callee
        }

        #region Public Properties
        public DateTime CallStarted { get; set; }
        public string CallID { get; set; }
        public bool SeenBYE { get; set; }
        public bool Confirmed { get; set; }
        public bool isEnd { get; set; }
        public int SourcePort { get; set; }      // not used
        public int DestinationPort { get; set; } // not used
        public int CallerRTPPort { get; set; }
        public int CalleeRTPPort { get; set; }
        public int CallerRTCPPort
        {
            get { return CallerRTPPort + 1; }
        }
        public int CalleeRTCPPort
        {
            get { return CalleeRTPPort + 1; }
        }
        public IPAddress CallerIP { get; set; }
        public IPAddress CalleeIP { get; set; }
        public List<UdpPacket> SIPMessages { get; set; }  // not used
        public CallDirection WhoHungUp { get; set; }

        #endregion


        #region Public Static Properties
        public static Dictionary<string, Call> SIPSessions = new Dictionary<string, Call>();
        #endregion

        private CaptureFileWriterDevice captureFileWriter;

        public string SIPPacketFilePath { get; }
        public string SIPPacketFilePathAndName { get; }

        //WaveFormat g726Format = new WaveFormat(8000, 32, 1);
        //WaveFileWriter wavWriter;

        public Call(string callID)
        {
            Console.WriteLine("Setup new call: " + callID);

            // Init collection of sip messages
            SIPMessages = new List<UdpPacket>();

            // Setup capture file
            SIPPacketFilePath = FileStoragePath.GetPath_SIP();
            SIPPacketFilePathAndName = SIPPacketFilePath + "\\" + callID + ".pcap";
            captureFileWriter = new CaptureFileWriterDevice( SIPPacketFilePathAndName );

            // Setup properties
            this.CallID = callID;
            // Set call started date/time
            CallStarted = DateTime.Now;

            isEnd = false;
        }

        #region Public Methods
        public void WritePacket(Packet raw, PacketType type)
        {
            captureFileWriter.Write(raw.Bytes);          
        }

        public void CloseCall()
        {
            // Close capture file
            captureFileWriter.Close();

            // Create details file
            using (StreamWriter sr = new StreamWriter(File.OpenWrite(SIPPacketFilePath + "\\" + CallID + ".txt")))
            {
                sr.WriteLine(string.Format("{0,-20}: {1}", "Call Started", CallStarted.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Callee", this.CalleeIP.ToString()));
                // sr.WriteLine(string.Format("{0,-20}: {1}", "Callee ID", this.CalleeID.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Caller", this.CallerIP.ToString()));
                // sr.WriteLine(string.Format("{0,-20}: {1}", "Caller ID", this.CallerID.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Hungup", this.WhoHungUp.ToString()));
            }
        }
        #endregion

        #region Static methods
        public static Call GetCallByRTPPort(int port)
        {
            foreach (var c in SIPSessions)
            {
                if (c.Value.CalleeRTPPort == port || c.Value.CallerRTPPort == port
                    || c.Value.CalleeRTCPPort == port || c.Value.CallerRTCPPort == port)
                    return c.Value;
            }
            return null;
        }
        #endregion
    }
}
