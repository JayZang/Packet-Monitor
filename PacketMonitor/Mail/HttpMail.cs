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
    // 此部分是用來追蹤使用 Http 協定的郵件，目前是先擷取所有的Post Request
    class HttpMail
    {
        #region Static Method
        public static void Trace(Packet packet, PacketMonitorForm PacketMonitor)
        {
            IpPacket ipPacket = null;
            TcpPacket tcpPacket = null;

            try
            {
                ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if (ipPacket == null || ipPacket.Version == IpVersion.IPv6)
                    return;
                tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                if (tcpPacket == null)
                    return;


                long Key = ipPacket.SourceAddress.Address + tcpPacket.SourcePort + ipPacket.DestinationAddress.Address + tcpPacket.AcknowledgmentNumber;

                if (isReassembledPacketOfPostRequest(ipPacket, tcpPacket))
                {

                    PacketReassemble(Key, tcpPacket);
                    MailList[Key].TimeToLive = 0;

                    // Var_PushFlag == true 表示資料都已經擷取完全
                    if (MailList[Key].Var_PushFlag == true)
                    {
                        var Mail = MailList[Key];
                        foreach (var Data in Mail.PostRequestDataList)
                            Mail.PostRequestData += new string(Data);
                        foreach (var Data in Mail.VarDataList)
                            Mail.VarData += new string(Data);

                        DoSomething(Mail, PacketMonitor);
                        MailList.Remove(Key);
                    }
                }
                else if (isPostRequest(tcpPacket))
                {
                    MailList.Add(Key, new HttpMail(ipPacket, tcpPacket));
                }
                else
                    return;

                AddMailLiveTime();
            }
            catch
            {
                Console.WriteLine();
                return;
            }
        }

        // Analyze the packet whether is POST request.
        private static bool isPostRequest(TcpPacket packet)
        {
            if (packet.PayloadData.Length <= 4)
                return false;

            byte[] RequestByte = packet.PayloadData;
            char[] Request = new char[4];
            Request[0] = (char)RequestByte[0];
            Request[1] = (char)RequestByte[1];
            Request[2] = (char)RequestByte[2];
            Request[3] = (char)RequestByte[3];

            if (Request[0] == 0x50 && Request[1] == 0x4f && Request[2] == 0x53 && Request[3] == 0x54) // Request = "POST"
                return true;
            return false;
        }

        // Analyze the Packet whether need reassemble.
        private static bool isReassembledPacketOfPostRequest(IpPacket ipPacket, TcpPacket tcpPacket)
        {
            return MailList.ContainsKey(ipPacket.SourceAddress.Address + tcpPacket.SourcePort + tcpPacket.AcknowledgmentNumber);
        }

        // Reassemble the packet
        private static void PacketReassemble(long Key, TcpPacket tcpPacket)
        {
            // 代表POST要求的內容尚未重組完成
            if (MailList[Key].PostRequest_PushFlag == false && MailList[Key].Var_PushFlag == false)
            {
                MailList[Key].PostRequest_PushFlag = tcpPacket.Psh;
                var PostRequestData = new char[tcpPacket.PayloadData.Length];
                for (int i = 0; i < tcpPacket.PayloadData.Length; i++)
                {
                    PostRequestData[i] = (char)tcpPacket.PayloadData[i];
                }
                MailList[Key].PostRequestDataList.Add(PostRequestData);
            }

            // 代表POST要求已經重組完成，此封包是POST要求所夾帶的內容
            else if (MailList[Key].PostRequest_PushFlag == true && MailList[Key].Var_PushFlag == false)
            {
                MailList[Key].Var_PushFlag = tcpPacket.Psh;
                var VarData = new char[tcpPacket.PayloadData.Length];
                for (int i = 0; i < tcpPacket.PayloadData.Length; i++)
                {
                    VarData[i] = (char)tcpPacket.PayloadData[i];
                }
                MailList[Key].VarDataList.Add(VarData);
            }
        }
        #endregion

        // 增加每個Mail資料的生存次數，當大於 MailLiveTime 時則從 MailList刪去
        private static void AddMailLiveTime()
        {
            List<long> Keys = new List<long>();

            foreach(var Mail in MailList)
            {
                Mail.Value.TimeToLive += 1;
                if (Mail.Value.TimeToLive >= MailLiveTime)
                    Keys.Add(Mail.Key);
            }
            foreach (var Key in Keys)
                MailList.Remove(Key);
        }

        // 當Post Request擷取完成時要做的事
        private static void DoSomething(HttpMail Mail, PacketMonitorForm PacketMonitor)
        {
            // PacketMonitor.mTxtBox.Text += Mail.PostRequestData + Mail.VarData + "\r\n\r\n";
            // 需要URI解碼
            //PacketMonitor.mTxtBox.Text += Uri.UnescapeDataString(Mail.PostRequestData) + Uri.UnescapeDataString(Mail.VarData) + "\r\n";
            //PacketMonitor.mTxtBox.Text += "------------------------------------------------------------------------------------------------\r\n\r\n";
        }

        // 建構子
        private HttpMail(IpPacket ipPacket, TcpPacket tcpPacket)
        {
            TimeToLive = 0;
            UserIP = ipPacket.SourceAddress.ToString();
            ServerIP = ipPacket.DestinationAddress.ToString();
            UserPort = tcpPacket.SourcePort.ToString();
            AckNumber = tcpPacket.AcknowledgmentNumber;
            PostRequest_PushFlag = tcpPacket.Psh;
            Var_PushFlag = false;
            PostRequestDataList = new List<char[]>();
            VarDataList = new List<char[]>();

            var PostRequestData = new char[tcpPacket.PayloadData.Length];
            for (int i =0; i< tcpPacket.PayloadData.Length;i++)
            {
                PostRequestData[i] = (char)tcpPacket.PayloadData[i];
            }
            PostRequestDataList.Add(PostRequestData);
        }

        private int TimeToLive;
        private string UserIP, ServerIP;
        private string UserPort;
        private uint AckNumber;
        private bool PostRequest_PushFlag, Var_PushFlag;
        private List<char[]> PostRequestDataList, VarDataList;
        private string PostRequestData, VarData;

        public static Dictionary<long, HttpMail> MailList = new Dictionary<long, HttpMail>();
        private static int MailLiveTime = 500;
    }

    
}
