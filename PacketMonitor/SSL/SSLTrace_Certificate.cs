using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpPcap;
using PacketDotNet;
using PacketMonitor.IPTraceInfomation;
using PacketMonitor.Log;

namespace PacketMonitor.SSL
{
    //  SSL 的 Certificate 擷取

    public class CertificateManage
    {
        public CertificateManage()
        {
            CertificateList = new List<Certificate>();
        }

        public Certificate Trace(Packet packet)
        {
            IpPacket ipPacket = null;
            TcpPacket tcpPacket = null;

            try
            {
                ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if (ipPacket == null || ipPacket.Version == IpVersion.IPv6)
                    return null;
                tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet); 
                if (tcpPacket == null)
                    return null;
            }
            catch
            {
                Console.WriteLine();
                return null;
            }

            var index = isReassembledPacket(ipPacket, tcpPacket);

            if ( index != -1 )
            {
                CertificateList[index].Push_Flag = tcpPacket.Psh;                
                CertificateList[index].PacketPayLoads.Add(tcpPacket.PayloadData);
                CertificateList[index].TotalPayLoadLength += tcpPacket.PayloadData.Length;
            }
            else if (isServerHelloPacket(tcpPacket))
            {
                var _Cer = new Certificate(ipPacket, tcpPacket);
                CertificateList.Add(_Cer);
                index = CertificateList.IndexOf(_Cer);
            }
            else
            {
                return null;
            }

            // Push_Flag = true 代表需要重組的封包都已接收到 !!!!!  新發現，此方法有時候行不通
            if (CertificateList[index].Push_Flag == true)
            {
                var certificate = CertificateList[index];
                certificate.TotalPayLoad = new byte[certificate.TotalPayLoadLength];
                byte[] TotalPayLoad = certificate.TotalPayLoad;

                int offset = 0;
                foreach (var PayLoad in certificate.PacketPayLoads)
                {
                    for (int i = 0; i < PayLoad.Length; i++)
                    {
                        TotalPayLoad[offset + i] = PayLoad[i];
                    }
                    offset += PayLoad.Length;
                }

                var RecordLayerLength = TotalPayLoad[3] * 256 + TotalPayLoad[4];
                var ServerHelloLength = TotalPayLoad[6] * 65536 + TotalPayLoad[7] * 256 + TotalPayLoad[8];

                int PayLoad_CertificateIndex;
                if (RecordLayerLength == (ServerHelloLength + 4))
                    PayLoad_CertificateIndex = RecordLayerLength + 10;
                else if (RecordLayerLength < (ServerHelloLength + 4))    // 為true時表示可能出錯
                {
                    CertificateList.RemoveAt(index);
                    return null;
                }
                else
                    PayLoad_CertificateIndex = ServerHelloLength + 9;

                try
                {
                    if (TotalPayLoad[PayLoad_CertificateIndex] != 0x0b)    // Handshake Type   = Certificate(0x0b)    
                    {
                        // 若不是交握的認證層則跳出
                        CertificateList.RemoveAt(index);
                        return null;
                    }
                }
                catch   // Sometimes it is out of range of array TotalPayLoad.
                {
                    CertificateList.RemoveAt(index);
                    return null;
                }

                try
                {
                    for (int i = 0; i < TotalPayLoad.Length; i++)
                    {
                        if ((PayLoad_CertificateIndex + i + 2) >= TotalPayLoad.Length)
                            break;

                        // Certificate 的國家欄位
                        if (TotalPayLoad[PayLoad_CertificateIndex + i] == 0x55 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 1] == 0x04 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 2] == 0x06)
                        {
                            int StringLength = TotalPayLoad[PayLoad_CertificateIndex + i + 4];              // 字串的長度
                            char[] StringByte = new char[StringLength];
                            for (int j = 0; j < StringLength; j++)
                            {
                                StringByte[j] = (char)TotalPayLoad[PayLoad_CertificateIndex + i + 5 + j];
                            }

                            if (!certificate.Country.Contains(new string(StringByte)))
                                certificate.Country.Add(new string(StringByte));

                        }

                        // Certificate 的地點欄位
                        if (TotalPayLoad[PayLoad_CertificateIndex + i] == 0x55 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 1] == 0x04 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 2] == 0x07)
                        {
                            int StringLength = TotalPayLoad[PayLoad_CertificateIndex + i + 4];
                            char[] StringByte = new char[StringLength];
                            for (int j = 0; j < StringLength; j++)
                            {
                                StringByte[j] = (char)TotalPayLoad[PayLoad_CertificateIndex + i + 5 + j];
                            }

                            if (!certificate.Locality.Contains(new string(StringByte)))
                                certificate.Locality.Add(new string(StringByte));
                        }

                        // Certificate 的省欄位
                        if (TotalPayLoad[PayLoad_CertificateIndex + i] == 0x55 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 1] == 0x04 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 2] == 0x08)
                        {
                            int StringLength = TotalPayLoad[PayLoad_CertificateIndex + i + 4];
                            char[] StringByte = new char[StringLength];
                            for (int j = 0; j < StringLength; j++)
                            {
                                StringByte[j] = (char)TotalPayLoad[PayLoad_CertificateIndex + i + 5 + j];
                            }

                            if (!certificate.StateOrProvince.Contains(new string(StringByte)))
                                certificate.StateOrProvince.Add(new string(StringByte));
                        }

                        // Certificate 的機構欄位
                        if (TotalPayLoad[PayLoad_CertificateIndex + i] == 0x55 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 1] == 0x04 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 2] == 0x0a)
                        {
                            int StringLength = TotalPayLoad[PayLoad_CertificateIndex + i + 4];
                            char[] StringByte = new char[StringLength];
                            for (int j = 0; j < StringLength; j++)
                            {
                                StringByte[j] = (char)TotalPayLoad[PayLoad_CertificateIndex + i + 5 + j];
                            }

                            if (!certificate.Organization.Contains(new string(StringByte)))
                                certificate.Organization.Add(new string(StringByte));
                        }

                        // Certificate 的 CommonName 欄位
                        if (TotalPayLoad[PayLoad_CertificateIndex + i] == 0x55 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 1] == 0x04 &&
                             TotalPayLoad[PayLoad_CertificateIndex + i + 2] == 0x03)
                        {
                            int StringLength = TotalPayLoad[PayLoad_CertificateIndex + i + 4];
                            char[] StringByte = new char[StringLength];
                            for (int j = 0; j < StringLength; j++)
                            {
                                StringByte[j] = (char)TotalPayLoad[PayLoad_CertificateIndex + i + 5 + j];
                            }

                            if (!certificate.CommonName.Contains(new string(StringByte)))
                                certificate.CommonName.Add(new string(StringByte));
                        }
                    }
                }
                catch
                {
                    // 不用 return ，因為已知有 Certificate 資料，只是取值時超出陣列
                }

                CertificateList.RemoveAt(index);  // 移除此筆Certificate資料
                return certificate;
            }
            else
                return null;
        }

        private bool isServerHelloPacket(TcpPacket tcpPacket)
        {
            if (tcpPacket.PayloadData.Length < 10)
                return false;
            if (tcpPacket.PayloadData[0] == 0x16 && tcpPacket.PayloadData[5] == 0x02)       // Record Layer Type = Handshake(0x16)  &  Handshake Type = Server Hello(0x02)            
                return true;
            return false;
        }

        private int isReassembledPacket(IpPacket ipPacket, TcpPacket tcpPacket)
        {
            foreach(var _Certificate in CertificateList)
            {
                if ( ipPacket.SourceAddress.ToString() == _Certificate.ServerIP &&
                     ipPacket.DestinationAddress.ToString() == _Certificate.UserIP &&
                     tcpPacket.SourcePort.ToString() == _Certificate.ServerPort &&
                     tcpPacket.DestinationPort.ToString() == _Certificate.UserPort)
                    return CertificateList.IndexOf(_Certificate);
            }

            return -1;
        }

        private List<Certificate> CertificateList;
    }

    public class Certificate
    {
        public Certificate(IpPacket ipPacket, TcpPacket tcpPacket)
        {
            TimeToLive = 0;

            ServerIP = ipPacket.SourceAddress.ToString();
            UserIP = ipPacket.DestinationAddress.ToString();
            ServerPort = tcpPacket.SourcePort.ToString();
            UserPort = tcpPacket.DestinationPort.ToString();
            Push_Flag = tcpPacket.Psh;
            TotalPayLoadLength = tcpPacket.PayloadData.Length;
            TotalPayLoad = null;

            Country = new List<string>();
            StateOrProvince = new List<string>();
            Locality = new List<string>();
            Organization = new List<string>();
            CommonName = new List<string>();

            PacketPayLoads = new List<byte[]>();
            PacketPayLoads.Add(tcpPacket.PayloadData);
        }


        public string UserIP { get; }
        public string ServerIP { get; }
        public string UserPort { get; }
        public string ServerPort { get; }
        public int TimeToLive;
        public bool Push_Flag;
        public byte[] TotalPayLoad;
        public int TotalPayLoadLength;

        public List<string> Country { get; }
        public List<string> StateOrProvince { get; }
        public List<string> Locality { get; }
        public List<string> Organization { get; }
        public List<string> CommonName { get; }

        public List<byte[]> PacketPayLoads;
    }
}
