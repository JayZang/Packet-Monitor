using System;
using SharpPcap;
using LumiSoft.Net.SDP;
using LumiSoft.Net.SIP.Message;
using LumiSoft.Net.SIP.Stack;
using PacketDotNet;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;

namespace PacketMonitor.SIP
{
    public class SIPTRACE
    {
#if DEBUG
        [DllImport("RTP_Debug.dll")]
        static extern int pacp_to_wav(StringBuilder PcapFile, StringBuilder StoragePath);
#endif


        public void Handler(Packet packet)
        {
            var udpPacket = UdpPacket.GetEncapsulated(packet);

            // if it's not udp , udpPacket will be null and we don't handle it.
            if (udpPacket != null)
            {
                try
                {
                    // signalling packet
                    SIP_Message msg = ParseSIPMessage(udpPacket.PayloadData);
                    if (msg != null && msg.CallID != null)
                    {
                        SDP_Message sdp = null;
                        Console.WriteLine("SIP capture");
                        try
                        {
                            sdp = SDP_Message.Parse(System.Text.Encoding.Default.GetString(msg.Data));
                        }
                        catch { }

                        if (msg is SIP_Request && msg.CallID != null)
                        {
                            SIP_Request r = (SIP_Request)msg;
                            //already containsKey 
                            if (!Call.SIPSessions.ContainsKey(r.CallID))
                            {
                                if (r.RequestLine.Method == "INVITE")
                                {
                                    Call.SIPSessions.Add(r.CallID, new Call(r.CallID));
                                    Call.SIPSessions[r.CallID].CallerIP = ((IpPacket)udpPacket.ParentPacket).SourceAddress;
                                    Call.SIPSessions[r.CallID].CalleeIP = ((IpPacket)udpPacket.ParentPacket).DestinationAddress;
                                }
                                else
                                    return;     // Ignore this conversation
                            }

                            // if this is an invite, do we have an audio rtp port defined?
                            if (r.RequestLine.Method == "INVITE")
                            {
                                if (sdp != null)
                                {
                                    foreach (var a in sdp.MediaDescriptions)
                                    {
                                        Console.Out.WriteLine(r.CallID + " - Got RTP Media Port: " + ((IpPacket)udpPacket.ParentPacket).SourceAddress + ":" + a.Port.ToString());
                                        if (Call.SIPSessions[r.CallID].CallerIP.ToString() == ((IpPacket)udpPacket.ParentPacket).SourceAddress.ToString())
                                            Call.SIPSessions[r.CallID].CallerRTPPort = a.Port;
                                        else
                                            Call.SIPSessions[r.CallID].CalleeRTPPort = a.Port;
                                        a.MediaFormats.GetType();

                                        break; // First description is about audio . Second is about viedo and we don't need it, so break.
                                    }
                                }
                            }

                            if (r.RequestLine.Method == "BYE")
                            {
                                if (Call.SIPSessions.ContainsKey(r.CallID))
                                {
                                    // Log bye was recevied
                                    Call.SIPSessions[r.CallID].SeenBYE = true;

                                    // Now indicate who hung up
                                    Call.SIPSessions[r.CallID].WhoHungUp = ((IpPacket)udpPacket.ParentPacket).SourceAddress == Call.SIPSessions[r.CallID].CallerIP ?
                                        Call.CallDirection.Caller : Call.CallDirection.Callee;
                                }
                                else
                                {
                                    Console.WriteLine("Unknown CallID: " + r.CallID);
                                }
                            }
                        }//    if (msg is SIP_Request && msg.CallID != null)
                        else if (msg is SIP_Response && msg.CallID != null)
                        {
                            SIP_Response r = (SIP_Response)msg;

                            if (r.StatusCode != 183 && r.StatusCode != 100 && r.StatusCode != 200)
                                Call.SIPSessions[r.CallID].isEnd = true;

                            if (sdp != null)
                            {
                                foreach (var a in sdp.MediaDescriptions)
                                {
                                    Console.Out.WriteLine(r.CallID + " - Got RTP Media Port: " + ((IpPacket)udpPacket.ParentPacket).SourceAddress + ":" + a.Port.ToString());
                                    if (Call.SIPSessions[r.CallID].CallerIP.ToString() == ((IpPacket)udpPacket.ParentPacket).SourceAddress.ToString())
                                        Call.SIPSessions[r.CallID].CallerRTPPort = a.Port;
                                    else
                                        Call.SIPSessions[r.CallID].CalleeRTPPort = a.Port;

                                    break; // First description is about audio . Second is about viedo and we don't need it, so break.
                                }
                            }

                            if (Call.SIPSessions.ContainsKey(r.CallID))
                                if (r.StatusCodeType == SIP_StatusCodeType.Success && Call.SIPSessions[r.CallID].SeenBYE)
                                {
                                    Call.SIPSessions[r.CallID].Confirmed = true;
                                    Call.SIPSessions[r.CallID].isEnd = true;
                                }
                        }

                        // Add packet to history
                        if (Call.SIPSessions.ContainsKey(msg.CallID))
                        {
                            Call.SIPSessions[msg.CallID].WritePacket(packet, Call.PacketType.SIPDialog);
                            // Check to see is this call has been terminated
                            if (Call.SIPSessions[msg.CallID].Confirmed)
                            {
                                // Close off the call now last data has been written
                                Console.WriteLine("Call Ended: " + msg.CallID);

                                // Close off the call
                                Call.SIPSessions[msg.CallID].CloseCall();

                                StringBuilder file = new StringBuilder(Directory.GetCurrentDirectory() + "//" + Call.SIPSessions[msg.CallID].SIPPacketFilePathAndName);
                                StringBuilder StoragePath = new StringBuilder(Directory.GetCurrentDirectory() + "//" + Call.SIPSessions[msg.CallID].SIPPacketFilePath);
                                pacp_to_wav(file, StoragePath);

                            }

                            if(Call.SIPSessions[msg.CallID].isEnd == true)
                                Call.SIPSessions.Remove(msg.CallID);
                        }
                    }
                    else
                    {
                        Call c = Call.GetCallByRTPPort(udpPacket.SourcePort);
                        if (c != null)
                            c.WritePacket(packet, Call.PacketType.RTP);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }

        public void PacketFileRTP(StringBuilder PcapFile,StringBuilder StoragePath)
        {
            pacp_to_wav(PcapFile, StoragePath);
        }

        // input udp packet's payload 
        private SIP_Message ParseSIPMessage(byte[] data)
        {
            try
            {
                return SIP_Request.Parse(data);
            }
            catch
            {
                try
                {
                    return SIP_Response.Parse(data);
                }
                catch
                {
                    return null;
                }
            }
        }

    }
}