using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SSL;
using System.IO;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Data.SQLite;
using PacketMonitor.IPTraceInfomation;
using PacketMonitor.Log;

namespace PacketMonitor.SSL
{
    class SSLTracer
    {
        public SSLTracer(string StorePath)
        {
            StoragePath = FileStoragePath.GetPath_SSL();
            SSLAnalyze = new SSLAnalyzer();
            _CertificateManage = new CertificateManage();
            SSLInformationList = new List<SSLInformation>();
            DBManage.GetDBHandler(DBDataType.SSL, out DB_connection, out DB_cmd);
        }

        public unsafe void Trace(Packet packet, PacketMonitorForm Form)
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
                if (tcpPacket.PayloadData.Length < 6)
                    return;
            }
            catch
            {
                return;
            }

            TraceClientHello(ipPacket, tcpPacket, Form);

            fixed ( Byte* _Byte = packet.Bytes)
            {
                SSLAnalyze.InsertPacketData(_Byte);
            }
        
            if ( SSLAnalyze.GetHandShakeMainContent() )
            {             
                var _SSLInformation = AddToSSLInfo(Form,null);
                WriteToDB(_SSLInformation);
                
            }

            var _Certificate = _CertificateManage.Trace(packet);
            if ( _Certificate != null )
            {
                AddToSSLInfo(Form, _Certificate);
                DoSomething(Form, _Certificate);
            }        
        }
        
        //追蹤有傳送 ClientHello 之封包，並更新該 IPTraceInfo 為 hasSSL 以標明要儲存往後之對應封包 
        private void TraceClientHello(IpPacket ipPacket, TcpPacket tcpPacket, PacketMonitorForm form)
        {
            if ( tcpPacket.PayloadData[0] == 0x16 && tcpPacket.PayloadData[5] == 0x01) // Record Layer Type = Handshake(0x16)  &  Handshake Type = Client Hello(0x01)            
            {
                bool isSSLVersion = false;
                if ((tcpPacket.PayloadData[1] == 0x02 && tcpPacket.PayloadData[2] == 0x00) ||
                    (tcpPacket.PayloadData[1] == 0x03 && tcpPacket.PayloadData[2] == 0x00) ||
                    (tcpPacket.PayloadData[1] == 0x03 && tcpPacket.PayloadData[2] == 0x01) ||
                    (tcpPacket.PayloadData[1] == 0x03 && tcpPacket.PayloadData[2] == 0x02) ||
                    (tcpPacket.PayloadData[1] == 0x03 && tcpPacket.PayloadData[2] == 0x03))
                {
                    isSSLVersion = true;
                }
                if (!isSSLVersion)
                    return;

                int Count = form.listIPTrace.Count;
                List<IPTraceInfo> _IPTrace = form.listIPTrace;

                for (int j = 0; j < Count; j++)
                {
                    if ((_IPTrace[j].SrcIP == ipPacket.SourceAddress.ToString()) && (_IPTrace[j].DstIP == ipPacket.DestinationAddress.ToString()) ||
                         (_IPTrace[j].SrcIP == ipPacket.DestinationAddress.ToString()) && (_IPTrace[j].DstIP == ipPacket.SourceAddress.ToString()))
                    {
                        foreach(var port in _IPTrace[j].Ports)
                        {
                            if((port.SrcPort == tcpPacket.SourcePort.ToString() && port.DstPort == tcpPacket.DestinationPort.ToString()) ||
                               (port.SrcPort == tcpPacket.DestinationPort.ToString() && port.DstPort == tcpPacket.SourcePort.ToString()))
                            {
                                port.hasSSL = true;
                                string FileName = ipPacket.SourceAddress.ToString() + "(" + tcpPacket.SourcePort.ToString() + ") - " + ipPacket.DestinationAddress.ToString() + "(" + tcpPacket.DestinationPort.ToString() + ").pcap";
                                port.SSLPcapFileWriter = new PcapFileWriter(StoragePath + "\\"+ FileName);

                                return;
                            }
                        }

                        return;
                    }
                }
            }          
        }
        
        //結合 Key 和 Certificate 之資訊緩存 
        private unsafe SSLInformation AddToSSLInfo(PacketMonitorForm form, Certificate _Certificate)
        {
            List<IPTraceInfo> list = form.listIPTrace;
            Port port = null;

            // 當有 Certificate 時代表有建立了 SSL 連線對談，但尚未取得完整鑰匙資訊，因此先放入列表中等待資訊完整放入
            if (_Certificate != null)
            {
                SSLInformationList.Add(new SSLInformation { UserIP = _Certificate.UserIP,
                                                            ServerIP = _Certificate.ServerIP,
                                                            UserPort = _Certificate.UserPort,
                                                            ServerPort = _Certificate.ServerPort,
                                                            certificate = _Certificate,         
                });
                return null;
            }
            else if (_Certificate == null )
            {
                string _UserIP = string.Format("{0}.{1}.{2}.{3}", SSLAnalyze.GetUserIP()[3], SSLAnalyze.GetUserIP()[2], SSLAnalyze.GetUserIP()[1], SSLAnalyze.GetUserIP()[0]);
                string _ServerIP = string.Format("{0}.{1}.{2}.{3}", SSLAnalyze.GetServerIP()[3], SSLAnalyze.GetServerIP()[2], SSLAnalyze.GetServerIP()[1], SSLAnalyze.GetServerIP()[0]);
                string _UserPort = SSLAnalyze.GetUserPort().ToString();
                string _ServerPort = SSLAnalyze.GetServerPort().ToString();

                for (int j = 0; j < list.Count; j++)
                {
                    if ((list[j].SrcIP == _ServerIP) && (list[j].DstIP == _UserIP) )
                    {
                        foreach(var p in list[j].Ports)
                        {
                            if ((p.SrcPort == _ServerPort) && (p.DstPort == _UserPort))
                                port = p;

                            break;
                        }
                    }
                    else if((list[j].DstIP == _ServerIP) && (list[j].SrcIP == _UserIP))
                    {
                        foreach (var p in list[j].Ports)
                        {
                            if ((p.SrcPort == _UserPort) && (p.DstPort == _ServerPort))
                                port = p;

                            break;
                        }
                    }
                }

                foreach (var _SSLInformation in SSLInformationList)
                {
                    if (_UserIP == _SSLInformation.UserIP &&
                        _ServerIP == _SSLInformation.ServerIP &&
                        _UserPort == _SSLInformation.UserPort &&
                        _ServerPort == _SSLInformation.ServerPort)
                    {
                        _SSLInformation.Version = SSLAnalyze.GetVersion().ToString();
                        _SSLInformation.CipherSuite = SSLAnalyze.GetCipherSuite().ToString();

                        string pubkey = null;
                        if (SSLAnalyze.GetPubKeyLen() > 0)
                        {
                            for (int i = 0; i < SSLAnalyze.GetPubKeyLen(); i++)
                                pubkey += string.Format("{0:x2} ", SSLAnalyze.GetPubkey()[i]);
                        }
                        _SSLInformation.PubKey = pubkey;

                        string sessionkey = null;
                        if (SSLAnalyze.GetSessionKeyLen() > 0)
                        {
                            for (int i = 0; i < SSLAnalyze.GetSessionKeyLen(); i++)
                                sessionkey += string.Format("{0:x2} ", SSLAnalyze.GetSessionKey()[i]);
                        }
                        _SSLInformation.SessionKey = sessionkey;

                        string NewSessionkey = null;
                        if (SSLAnalyze.GetNewSessionTicketLen() > 0)
                        {
                            for (int i = 0; i < SSLAnalyze.GetNewSessionTicketLen(); i++)
                                NewSessionkey += string.Format("{0:x2} ", SSLAnalyze.GetNewSessionTicket()[i]);
                        }
                        _SSLInformation.NewSessionKey = NewSessionkey;

                        if(port !=null && (pubkey != null || sessionkey != null || NewSessionkey != null))
                        {
                            port.keys.ServerPort = _ServerPort;
                            port.keys.UserPort = _UserPort;
                            if (port.keys.pubKey == null)
                                port.keys.pubKey = pubkey;
                            if (port.keys.sessionKey == null)
                                port.keys.sessionKey = sessionkey;
                            if (port.keys.newSessionkey == null)
                                port.keys.newSessionkey = NewSessionkey;
                            port.keys.hasKey = true;
                        }

                        SSLInformationList.Remove(_SSLInformation);
                        return _SSLInformation;
                    }
                }

                // 此之後之程式碼是設定沒有 Certificate 之 SSL資訊
                var sslInformation = new SSLInformation();
                sslInformation.UserIP = _UserIP;
                sslInformation.ServerIP = _ServerIP;
                sslInformation.UserPort = _UserPort;
                sslInformation.ServerPort = _ServerPort;
                sslInformation.Version = SSLAnalyze.GetVersion().ToString();
                sslInformation.CipherSuite = SSLAnalyze.GetCipherSuite().ToString();

                string _pubkey = null;
                if (SSLAnalyze.GetPubKeyLen() > 0)
                {
                    for (int i = 0; i < SSLAnalyze.GetPubKeyLen(); i++)
                        _pubkey += string.Format("{0:x2} ", SSLAnalyze.GetPubkey()[i]);
                }
                sslInformation.PubKey = _pubkey;

                string _sessionkey = null;
                if (SSLAnalyze.GetSessionKeyLen() > 0)
                {
                    for (int i = 0; i < SSLAnalyze.GetSessionKeyLen(); i++)
                        _sessionkey += string.Format("{0:x2} ", SSLAnalyze.GetSessionKey()[i]);
                }
                sslInformation.SessionKey = _sessionkey;

                string _NewSessionkey = null;
                if (SSLAnalyze.GetNewSessionTicketLen() > 0)
                {
                    for (int i = 0; i < SSLAnalyze.GetNewSessionTicketLen(); i++)
                        _NewSessionkey += string.Format("{0:x2} ", SSLAnalyze.GetNewSessionTicket()[i] );
                }
                sslInformation.NewSessionKey = _NewSessionkey;

                sslInformation.certificate = null;

                if (port != null && (_pubkey != null || _sessionkey != null || _NewSessionkey != null))
                {
                    port.keys.ServerPort = _ServerPort;
                    port.keys.UserPort = _UserPort;
                    if (port.keys.pubKey == null)
                        port.keys.pubKey = _pubkey;
                    if (port.keys.sessionKey == null)
                        port.keys.sessionKey = _sessionkey;
                    if (port.keys.newSessionkey == null)
                        port.keys.newSessionkey = _NewSessionkey;
                    port.keys.hasKey = true;
                }
                return sslInformation;
            }

            return null;
        }

        // 取得了 SSL 完整資訊後要做的事情 ( 將Certificate資訊放進listIPTrace )
        private void DoSomething(PacketMonitorForm form, Certificate _Certificate)
        {
            int Count = form.listIPTrace.Count;
            List<IPTraceInfo> _IPTrace = form.listIPTrace;

            for (int j = 0; j < Count; j++)
            {
                if ((_IPTrace[j].SrcIP == _Certificate.ServerIP) && (_IPTrace[j].DstIP == _Certificate.UserIP) ||
                     (_IPTrace[j].DstIP == _Certificate.ServerIP) && (_IPTrace[j].SrcIP == _Certificate.UserIP))
                {
                    if( _IPTrace[j].certificate == null && _Certificate != null)
                        _IPTrace[j].certificate = _Certificate;                 

                    return;
                }
            }
        }

        private unsafe void WriteToDB(SSLInformation _SSLInformation)
        {
            if (_SSLInformation.PubKey == null && 
                _SSLInformation.SessionKey == null && 
                _SSLInformation.NewSessionKey == null && 
                _SSLInformation.certificate == null)
                return;

            string Certificate_Country = null;
            string Certificate_StateOrProvince = null;
            string Certificate_Locality = null;
            string Certificate_Organization = null;
            string Certificate_CommonName = null;

            if (_SSLInformation.certificate!= null)
            {
                if (_SSLInformation.certificate.Country.Count != 0)
                {
                    Certificate_Country += _SSLInformation.certificate.Country[0];
                    for (int i = 1; i < _SSLInformation.certificate.Country.Count; i++)
                    {
                        Certificate_Country += "   、  " + _SSLInformation.certificate.Country[i];
                        Certificate_Country.Replace("'", "\"");
                    }
                }
                if (_SSLInformation.certificate.StateOrProvince.Count != 0)
                {
                    Certificate_StateOrProvince += _SSLInformation.certificate.StateOrProvince[0];
                    for (int i = 1; i < _SSLInformation.certificate.StateOrProvince.Count; i++)
                    {
                        Certificate_StateOrProvince += "   、  " + _SSLInformation.certificate.StateOrProvince[i];
                        Certificate_StateOrProvince.Replace("'", "\"");
                    }
                }
                if (_SSLInformation.certificate.Locality.Count != 0)
                {
                    Certificate_Locality += _SSLInformation.certificate.Locality[0];
                    for (int i = 1; i < _SSLInformation.certificate.Locality.Count; i++)
                    {
                        Certificate_Locality += "   、  " + _SSLInformation.certificate.Locality[i];
                        Certificate_Locality.Replace("'", "\"");
                    }
                }
                if (_SSLInformation.certificate.Organization.Count != 0)
                {
                    Certificate_Organization += _SSLInformation.certificate.Organization[0];
                    for (int i = 1; i < _SSLInformation.certificate.Organization.Count; i++)
                    {
                        Certificate_Organization += "   、  " + _SSLInformation.certificate.Organization[i];
                        Certificate_Organization.Replace("'", "\"");
                    }
                }
                if (_SSLInformation.certificate.CommonName.Count != 0)
                {
                    Certificate_CommonName += _SSLInformation.certificate.CommonName[0];
                    for (int i = 1; i < _SSLInformation.certificate.CommonName.Count; i++)
                    {
                        Certificate_CommonName += "   、  " + _SSLInformation.certificate.CommonName[i];
                        Certificate_CommonName.Replace("'", "\"");
                    }
                }
            }

            if (_SSLInformation.NewSessionKey != null)
                DB_cmd.CommandText = "UPDATE SSL SET NewSeesionTicket = '" + _SSLInformation.NewSessionKey +
                    "' WHERE ServerIP = '" + _SSLInformation.ServerIP +
                    "' AND UserIP = '" + _SSLInformation.UserIP + 
                    "' AND ServerPort = '" + _SSLInformation.ServerPort + 
                    "' AND UserPort = '" + _SSLInformation.UserPort + "'";
            else
            {
                DB_cmd.CommandText = "INSERT INTO SSL VALUES ('" + @_SSLInformation.UserIP + "', '"
                + @_SSLInformation.ServerIP + "', '"
                + @_SSLInformation.UserPort + "', '"
                + @_SSLInformation.ServerPort + "', '"
                + @_SSLInformation.CipherSuite + "', '"
                + @_SSLInformation.PubKey + "', '"
                + @_SSLInformation.SessionKey + "', '"
                + @_SSLInformation.NewSessionKey + "', '"
                + @Certificate_Country + "', '"
                + @Certificate_StateOrProvince + "', '"
                + @Certificate_Locality + "', '"
                + @Certificate_Organization + "', '"
                + @Certificate_CommonName + "')";
            }
            
            try
            {
                DB_cmd.ExecuteNonQuery();
            }
            catch(Exception ex)
            {
                string Info = "\r\n     Data insert to DB Error ! " +
                              "\r\n     User IP :" + _SSLInformation.UserIP +
                              "\r\n     Server IP :" + _SSLInformation.ServerIP +
                              "\r\n     User Port :" + _SSLInformation.UserPort +
                              "\r\n     Server Port :" + _SSLInformation.ServerPort;
                Log.Log.SSLLogger.Error(ex, Info);

                DB_cmd.CommandText = "INSERT INTO SSL VALUES ('" + @_SSLInformation.UserIP + "', '"
                + @_SSLInformation.ServerIP + "', '"
                + @_SSLInformation.UserPort + "', '"
                + @_SSLInformation.ServerPort + "', '"
                + @_SSLInformation.CipherSuite + "', '"
                + @_SSLInformation.PubKey + "', '"
                + @_SSLInformation.SessionKey + "', '"
                + @_SSLInformation.NewSessionKey + "', '','','','','')";

                DB_cmd.ExecuteNonQuery();
            }

        }

        private string StoragePath; 
        private SSLAnalyzer SSLAnalyze;
        private CertificateManage _CertificateManage;
        private SQLiteConnection DB_connection;
        private SQLiteCommand DB_cmd;
        private List<SSLInformation> SSLInformationList;
    }

    public class SSLInformation
    {
        public string UserIP { get; set; }
        public string ServerIP { get; set; }
        public string UserPort { get; set; }
        public string ServerPort { get; set; }
        public string Version { get; set; }
        public string CipherSuite { get; set; }
        public string PubKey { get; set; }
        public string SessionKey { get; set; }
        public string NewSessionKey { get; set; }
        public Certificate certificate { get; set; }
    }

}
