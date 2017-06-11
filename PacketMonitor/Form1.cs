using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Forms;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;
using System.IO;
using MaxMind.GeoIP2.Responses;
using System.Runtime.InteropServices;
using PacketMonitor.IPTraceInfomation;
using PacketMonitor.Mail;
using PacketMonitor.SIP;
using PacketMonitor.SSL;
using ReadPcapFile;
using System.Data.SQLite;

namespace PacketMonitor
{
    public partial class PacketMonitorForm : Form
    {

#if DEBUG
        [DllImport("RTP_Debug.dll")]
        static extern int pacp_to_wav(StringBuilder str, StringBuilder path);
#endif

        public PacketMonitorForm(Mode mode)
        {
            // must to set.
            Control.CheckForIllegalCrossThreadCalls = false;

            InitializeComponent();
            InitialCommom();
            InitailPage1();

            if(mode == Mode.Monitor)
            {
                mBtnSelectInterface_Click(null,null);
            }
            else if(mode == Mode.File)
            {
                this.mBtnSelectInterface.Text = "Select File";
                this.mBtnSelectInterface.Click -= new System.EventHandler(this.mBtnSelectInterface_Click);
                this.mBtnSelectInterface.Click += new System.EventHandler(this.mBtnSelectPacketFile_Click);
                this.mBtnSelectInterface.Image = global::PacketMonitor.Properties.Resources.file;
                mBtnSelectPacketFile_Click(null,null);
            }               
        }

        /*****************************************  For Common  *****************************************/
        private void InitialCommom()
        {
            Port.Initial_PortsApplication();
        }

        /*****************************************  For Page 1  *****************************************/
        #region Page1
        private void InitailPage1()
        {
        }

        private void mBtnSelectInterface_Click(object sender, EventArgs e)
        {
            if (Status == EnumStatus.Monitor)
            {
                MessageBox.Show("Monitoring... ! ", "Alarm");
                return;
            }

            SelectInterfaceForm = new SelectInterface();
            SelectInterfaceForm.ShowDialog();
            Device = SelectInterfaceForm.GetDeviceList();
            if (Device != null)
                mBtnStartMonitor_Click(null, null);
        }

        // Click button to Capture packets
        private void mBtnStartMonitor_Click(object sender, EventArgs e)
        {
            // If it's monitoring . Don't click it again.
            if (Status == EnumStatus.Monitor)
            {
                MessageBox.Show("Is Monitoring... \rDon't Click It Again ! ", "Alarm");
                return;
            }

            if (Device == null)
            {
                MessageBox.Show("Please Select One Interface or File.", "Alarm");
                return;
            }

            // Set event to handle packets when packet arrived.
            Device.OnPacketArrival -= new PacketArrivalEventHandler(PushPacketToQueue); // 若暫停過後重新按開始則必須先把之前的事件函數去除，否則會重複執行函數
            Device.OnPacketArrival += new PacketArrivalEventHandler(PushPacketToQueue);

            int readTimeoutMilliseconds = 1000;
            if (Device is AirPcapDevice)
            {
                // NOTE: AirPcap devices cannot disable local capture
                var airPcap = Device as AirPcapDevice;
                airPcap.Open(SharpPcap.WinPcap.OpenFlags.Promiscuous, readTimeoutMilliseconds);
            }
            else if (Device is WinPcapDevice)
            {
                var winPcap = Device as WinPcapDevice;
                winPcap.Open(SharpPcap.WinPcap.OpenFlags.Promiscuous, readTimeoutMilliseconds);
            }
            else if (Device is LibPcapLiveDevice)
            {
                var livePcapDevice = Device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                MessageBox.Show("unknown device type of " + Device.GetType().ToString(), "Error");
            }

            mPacketTrace.Items.Clear();
            AllPcapFileWriter = new CaptureFileWriterDevice(FileStoragePath.GetPath_TotalPackets() + "\\" + DateTime.Now.ToString("tt hh.mm.ss.pcap"));
            SIPTrace = new SIPTRACE();
            SSLTrace = new SSLTracer(FileStoragePath.GetPath_TotalPackets());
            listIPTrace = new List<IPTraceInfo>();                             // new a IPTrace List 
            PacketQueue = new Queue<RawCapture>();                         // new a PacketQueue                       
            trdGetPacketFromQueue = new Thread(GetPacketFromQueue);        // Start thread to get packet from queue and then analyze.
            trdUpdateListUI = new Thread(UpdateListUI);                    // Stert thread to update list UI.
            trdGetPacketFromQueueAct = true;                               // Used to control GetPacketFromQueue thread to stop whem it's false
            trdUpdateListUIAct = true;
            Device.StartCapture();
            trdGetPacketFromQueue.Start();
            trdUpdateListUI.Start();
            Status = EnumStatus.Monitor;
            TotalPacketStream = 0;
            mStatusStreams.Text = "Total Streams(Byte) : 0     ";
            this.Text = "Packets Monitor ( Monitoring from " + Device.Description + " )";
            mStatusMonitor.Text = "Status : Montioring...     ";
            //MessageBox.Show("Monitoring ...", "Succeed");
        }

        private void mBtnStopMonitor_Click(object sender, EventArgs e)
        {
            if (Status == EnumStatus.Idle)
                return;

            if (Status == EnumStatus.Monitor)
            {
                Device.StopCapture();
                trdGetPacketFromQueueAct = false;                   // Thread for GetPacketFromQueue
                trdUpdateListUIAct = false;
                Status = EnumStatus.Idle;
                this.Text = "Packets Monitor ";
                mStatusMonitor.Text = "Status : Idle     ";
               
            }
            else if (Status == EnumStatus.OpenFile)
            {
                trdGetPacketFromQueueAct = false;                   // Thread for GetPacketFromQueue
                trdUpdateListUIAct = false;
                PcapFileEOF = false;
                Status = EnumStatus.Idle;
                this.Text = "Packets Monitor ";
                mStatusMonitor.Text = "Status : Idle     ";
            }
            PcapFileWriter.CloseAll();
            if( AllPcapFileWriter!=null )
                AllPcapFileWriter.Close();

        }

        private void mBtnSelectPacketFile_Click(object sender, EventArgs e)
        {
            mOpenFileDialog.Title = "Select file";
            mOpenFileDialog.InitialDirectory = Directory.GetCurrentDirectory() + "//" + FileStoragePath.GetPath_MainFolder() + "//";
            //mOpenFileDialog.Filter = "Pcap |*.pcap | Pcapng |*.pcapng";
            ReadPacpFile PacketFileReader = new ReadPacpFile();
            if (mOpenFileDialog.ShowDialog() == DialogResult.OK)
            {
                if (!PacketFileReader.OpenFile(mOpenFileDialog.FileName))
                {
                    MessageBox.Show("Open File Fail");
                    return;
                }
            }
            else
            {
                return;
            }

            PacketFileReader.PackerHandler = new PackerHandler(ReadPacketFileHandler);
            mPacketTrace.Items.Clear();
            SIPTrace = new SIPTRACE();
            SSLTrace = new SSLTracer(FileStoragePath.GetPath_TotalPackets());
            listIPTrace = new List<IPTraceInfo>();                             // new a IPTrace List 
            PacketQueue = new Queue<RawCapture>();                         // new a PacketQueue                       
            trdGetPacketFromQueue = new Thread(GetPacketFromQueue);        // Start thread to get packet from queue and then analyze.
            trdUpdateListUI = new Thread(UpdateListUI);                    // Stert thread to update list UI.
            Thread SipThread = new Thread(SipProcess);
            trdGetPacketFromQueueAct = true;                               // Used to control GetPacketFromQueue thread to stop whem it's false
            trdUpdateListUIAct = true;
            Status = EnumStatus.OpenFile;
            PacketFileReader.Start();
            trdGetPacketFromQueue.Start();
            trdUpdateListUI.Start();
            SipThread.Start();
            TotalPacketStream = 0;
            mStatusStreams.Text = "Total Streams(Byte) : 0     ";
            this.Text = "Packets Monitor ( Open File from " + mOpenFileDialog.FileName + " )";
            mStatusMonitor.Text = "Status : Open File...     ";
        }

        private void mBtnOpenFolder_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start(FileStoragePath.GetPath_MainFolder());
        }

        private void ReadPacketFileHandler(byte[] e, bool isEnd)
        {
            if (isEnd)
            {
                PcapFileEOF = true;
                return;
            }

            PosixTimeval time = new PosixTimeval();
            RawCapture rawCapture = new RawCapture(LinkLayers.Ethernet, time, e);
            lock (PacketQueueLock)
            {
                // push the packet to the queue .
                PacketQueue.Enqueue(rawCapture);
            }
        }

        private void FormClosing_EventHandler(object sender, FormClosingEventArgs e)
        {
            mBtnStopMonitor_Click(null, null);
            PcapFileWriter.list.Clear();
            Port.PortsApplication.Clear();
            Call.SIPSessions.Clear();
            HttpMail.MailList.Clear();
            MailTrace.MailList.Clear();
        }

        // 只在讀檔中用到
        private void SipProcess()
        {
            SIPTrace.PacketFileRTP(new StringBuilder(mOpenFileDialog.FileName), new StringBuilder(FileStoragePath.GetPath_SIP()));
        }

        // Received pakcets will be push into queue. ( This is a callback function.)
        private void PushPacketToQueue(object sender, CaptureEventArgs e)
        {
            Packet packet;
            try
            {
                packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                if (e.Packet.LinkLayerType != LinkLayers.Ethernet)
                {
                    return;
                }

                // Write the packet to pcap file .           
                FileInfo PcapFile_Total = new FileInfo(AllPcapFileWriter.Name);
                if (PcapFile_Total.Length < PcapFileMaxSizeOfByte) // 200 MB
                    AllPcapFileWriter.Write(packet.Bytes);
                else
                {
                    AllPcapFileWriter = new CaptureFileWriterDevice(FileStoragePath.GetPath_TotalPackets() + "\\" + DateTime.Now.ToString("tt hh.mm.ss.pcap"));
                    AllPcapFileWriter.Write(packet.Bytes);
                }


                // The Packet is too small , it does not be analyzed .
                if (packet.Bytes.Length <= 60)
                    return;

                lock (PacketQueueLock)
                {
                    // push the packet to the queue .
                    PacketQueue.Enqueue(e.Packet);
                }
            }
            catch
            {
                return;
            }
        }

        // This function works on a thread.
        private void GetPacketFromQueue()
        {
            while (trdGetPacketFromQueueAct)
            {
                RawCapture rawCapture;
                Packet packet = null;

                if (PacketQueue.Count == 0)  // the Queue doesn't have packets.
                {
                    if (PcapFileEOF == true)
                    {
                        trdGetPacketFromQueueAct = false;
                        break;
                    }
                    else
                        continue;
                }

                lock (PacketQueueLock)
                {
                    rawCapture = PacketQueue.Dequeue();
                }

                try
                {
                    packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                }
                catch
                {
                    continue;
                }

                LastPacketArrivalTime = rawCapture.Timeval.Date.ToLocalTime().ToString();


                //Hydar
             //   Packet tmpTcpPacket = null;


               
                //    tmpTcpPacket = (packet as TcpPacket);
                
                //else if (packet is EthernetPacket)
                //{
                //    //协议数据区（TCP/IP协议包数据区，包括IP协议数据及TCP协议数据）
                //    byte[] tmpBuf = new byte[packet.Bytes.Length - 8];
                //    //复制实际TCP/IP数据块
                //    Array.Copy(packet.Bytes, 8, tmpBuf, 0, tmpBuf.Length);
                //    MemoryStream tmpMs = new MemoryStream();
                //    //将原来的以太包头作为目标TCP/IP数据包的以太头
                //    tmpMs.Write(packet.Header, 0, packet.Header.Length);
                //    //将实际TCP/IP数据包写入目标TCP/IP数据包中，跟在以太包头后面，成为一个新的TCP/IP数据包
                //    tmpMs.Write(tmpBuf, 0, tmpBuf.Length);
                //    try
                //    {
                //        //尝试创建新的TCP/IP数据包对象，
                //        //第一个参数为以太头长度，第二个为数据包数据块
                //        tmpTcpPacket = Packet.ParsePacket(rawCapture.LinkLayerType, tmpMs.ToArray());
                //    }
                //    catch { tmpTcpPacket = null; }
                //    tmpMs.Dispose();
                //}

                // SIP、RTP Packet Analyze and handle them
                if (Status == EnumStatus.Monitor)
                    SIPTrace.Handler(packet);

                // POP3、SMTP、IMAP Packet Analyze
                MailTrace.Trace(packet);

                HttpMail.Trace(packet, this);

                // Log SSL Keys
                SSLTrace.Trace(packet, this);

                // Push pakcet to List<IPTrace>
                UpdateListIPTrace(rawCapture);
            }
        }

        // Push pakcet to List<IPTrace>        
        private void UpdateListIPTrace(RawCapture e)
        {
            Packet packet;
            try
            {
                packet = PacketDotNet.Packet.ParsePacket(e.LinkLayerType, e.Data);
                var ethPacket = PacketDotNet.EthernetPacket.GetEncapsulated(packet);
                var ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);
                if (ipPacket == null || ipPacket.Version == IpVersion.IPv6)
                    return;
                var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                UdpPacket udpPacket = null;
                string SrcPort;
                string DstPort;

                if (tcpPacket == null)
                {
                    udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet);
                    SrcPort = udpPacket.SourcePort.ToString();
                    DstPort = udpPacket.DestinationPort.ToString();
                }
                else
                {
                    SrcPort = tcpPacket.SourcePort.ToString();
                    DstPort = tcpPacket.DestinationPort.ToString();
                }

                bool isExistInList = false;

                foreach (var para in listIPTrace)
                {
                    if ((para.SrcIP == ipPacket.SourceAddress.ToString()) && (para.DstIP == ipPacket.DestinationAddress.ToString()))
                    {
                        para.LastPacketTime = e.Timeval.Date;
                        para.SrcToDstStream += ipPacket.PayloadLength;

                        bool hasPort = false;
                        foreach (var port in para.Ports)
                        {
                            if (port.SrcPort == SrcPort && port.DstPort == DstPort)
                            {
                                if (port.hasSSL)
                                {
                                    port.SSLPcapFileWriter.Write(packet.Bytes);
                                }
                                hasPort = true;

                                break;
                            }
                        }
                        if (!hasPort)
                        {
                            var port = new Port(SrcPort, DstPort);
                            bool isExistInfo = false;

                            foreach(var p in para.Ports)
                            {
                                if (p.PortApplication == port.PortApplication)
                                {
                                    isExistInfo = true;
                                    break;
                                }
                            }
                            if (!isExistInfo)
                                para.Information += port.PortApplication + "  ";

                            para.Ports.Add(port);
                        }
                            

                        TotalPacketStream += ipPacket.PayloadLength;
                        //UpdateListUI(para, false);
                        isExistInList = true;
                        break;
                    }
                    else if ((para.SrcIP == ipPacket.DestinationAddress.ToString()) && (para.DstIP == ipPacket.SourceAddress.ToString()))
                    {
                        para.LastPacketTime = e.Timeval.Date;
                        para.DstToSrcStream += ipPacket.PayloadLength;

                        bool hasPort = false;
                        foreach (var port in para.Ports)
                        {
                            if (port.SrcPort == DstPort && port.DstPort == SrcPort)
                            {
                                if (port.hasSSL)
                                {
                                    port.SSLPcapFileWriter.Write(packet.Bytes);
                                }
                                hasPort = true;

                                break;
                            }
                        }
                        if (!hasPort)
                        {
                            var port = new Port(DstPort, SrcPort);
                            bool isExistInfo = false;

                            foreach (var p in para.Ports)
                            {
                                if (p.PortApplication == port.PortApplication)
                                {
                                    isExistInfo = true;
                                    break;
                                }
                            }
                            if (!isExistInfo)
                                para.Information += port.PortApplication + "  ";

                            para.Ports.Add(port);
                        }

                        TotalPacketStream += ipPacket.PayloadLength;
                        //UpdateListUI(para, false);
                        isExistInList = true;
                        break;
                    }
                }
                if (!isExistInList)
                {
                    string SrcLocation, DstLocation;
                    FindLocationByIP(ipPacket, out SrcLocation, out DstLocation);

                    var _IPTrace = new IPTraceInfo()
                    {
                        No = listIPTrace.Count,
                        SrcIP = ipPacket.SourceAddress.ToString(),
                        DstIP = ipPacket.DestinationAddress.ToString(),
                        Ports = new List<Port>(),   
                        SrcLocation = SrcLocation,
                        DstLocation = DstLocation,
                        SrcMac = ethPacket.SourceHwAddress.ToString(),
                        DstMac = ethPacket.DestinationHwAddress.ToString(),
                        SrcToDstStream = ipPacket.PayloadLength,
                        DstToSrcStream = 0,
                        FirstPacketTime = e.Timeval.Date,
                        LastPacketTime = e.Timeval.Date,
                        certificate = null
                    };
                    var port = new Port(SrcPort, DstPort);
                    _IPTrace.Ports.Add(port);
                    _IPTrace.Information = port.PortApplication + "  ";

                    TotalPacketStream += _IPTrace.SrcToDstStream;
                    listIPTrace.Add(_IPTrace);
                    //UpdateListUI(_IPTrace,true);
                }

                //UpdateInfo(); // 放此處會嚴重使系統處理封包速度變慢，原因不明
            }
            catch
            {
            }
        }

        // Find Location and country by IP (Using the tool,GeoIP API)
        private void FindLocationByIP(IpPacket ipPacket, out string SrcLocation, out string DstLocation)
        {
            string SrcIP, DstIP;
            CityResponse Src, Dst;

            SrcIP = ipPacket.SourceAddress.ToString();
            DstIP = ipPacket.DestinationAddress.ToString();

            try
            {
                Src = GeoIP_DatabaseReader.City(SrcIP);
                SrcLocation = Src.Country.ToString() + ((Src.City.ToString() == "") ? "" : (" ( " + Src.City.ToString() + " ) "));
                //if( SrcLocation == "" || SrcLocation == " ")
                //    SrcLocation = "Not Found";
            }
            catch
            {
                SrcLocation = "";
                //SrcLocation = "Not Found";

                //byte[] IP = ipPacket.SourceAddress.GetAddressBytes();
                //if (IP[0] == 10)
                //{                                      
                //    SrcLocation = "Virtual IP";                    
                //}
                //else if ( IP[0] == 172 )
                //{
                //    if ( IP[1] >= 16 && IP[1] <= 31)
                //    {
                //        SrcLocation = "Virtual IP";
                //    }
                //}
                //else if (IP[0] == 192)
                //{
                //    if (IP[1] == 168 )
                //    {
                //        SrcLocation = "Virtual IP";
                //    }
                //}
            }

            try
            {
                Dst = GeoIP_DatabaseReader.City(DstIP);
                DstLocation = Dst.Country.ToString() + ((Dst.City.ToString() == "") ? "" : (" ( " + Dst.City.ToString() + " ) "));
                //if( DstLocation == "" || DstLocation == " ")
                //    DstLocation = "Not Found";
            }
            catch
            {
                DstLocation = "";
                //DstLocation = "Not Found";

                //byte[] IP = ipPacket.DestinationAddress.GetAddressBytes();
                //if (IP[0] == 10)
                //{
                //    DstLocation = "Virtual IP";
                //}
                //else if (IP[0] == 172)
                //{
                //    if (IP[1] >= 16 && IP[1] <= 31)
                //    {
                //        DstLocation = "Virtual IP";
                //    }
                //}
                //else if (IP[0] == 192)
                //{
                //    if (IP[1] == 168)
                //    {
                //        DstLocation = "Virtual IP";
                //    }
                //}
            }
        }

        // 工作於線程中迴圈更新
        private void UpdateListUI()
        {
            int index, Count;
            string SrcToDstStream, DstToSrcStream;

            while (trdUpdateListUIAct)
            {
                // 讀封包檔案結束時 goBreak = true，更新UI前先記錄目前更新是否需要再次更新
                bool goBreak = !trdGetPacketFromQueueAct;

                Count = listIPTrace.Count;

                if (Count == 0)
                    continue;

                for (int i = 0; i < Count; i++)
                {
                    index = mPacketTrace.Items.IndexOfKey(listIPTrace[i].No.ToString());

                    SrcToDstStream = listIPTrace[i].SrcToDstStream.ToString("N");
                    DstToSrcStream = listIPTrace[i].DstToSrcStream.ToString("N");

                    SrcToDstStream = SrcToDstStream.Remove(SrcToDstStream.IndexOf("."), 3);
                    DstToSrcStream = DstToSrcStream.Remove(DstToSrcStream.IndexOf("."), 3);

                    if (index == -1)
                    {
                        mPacketTrace.Items.Add(listIPTrace[i].No.ToString(), listIPTrace[i].No.ToString(), 0);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(listIPTrace[i].SrcIP);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(listIPTrace[i].DstIP);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(listIPTrace[i].SrcLocation);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(listIPTrace[i].DstLocation);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(SrcToDstStream);
                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(DstToSrcStream);

                        if (listIPTrace[i].certificate == null)
                            mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add("");
                        else if (listIPTrace[i].certificate != null)
                            mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add("      ✔");

                        mPacketTrace.Items[listIPTrace[i].No.ToString()].SubItems.Add(listIPTrace[i].Information);

                        if (listIPTrace[i].No % 2 == 0)
                            mPacketTrace.Items[listIPTrace[i].No].BackColor = Color.FromArgb(0xF0F0F0);
                        else
                            mPacketTrace.Items[listIPTrace[i].No].BackColor = Color.White;
                    }
                    else
                    {
                        if (index % 2 == 0)
                            mPacketTrace.Items[index].BackColor = Color.FromArgb(0xF0F0F0);
                        else
                            mPacketTrace.Items[index].BackColor = Color.White;

                        mPacketTrace.Items[index].SubItems[(int)IP_List_Column.Column_Stream_IP1ToIP2].Text = SrcToDstStream;
                        mPacketTrace.Items[index].SubItems[(int)IP_List_Column.Column_Stream_IP2ToIP1].Text = DstToSrcStream;

                        if (listIPTrace[i].certificate == null)
                            mPacketTrace.Items[index].SubItems[(int)IP_List_Column.Column_Certificate].Text = "";
                        else if (listIPTrace[i].certificate != null)
                            mPacketTrace.Items[index].SubItems[(int)IP_List_Column.Column_Certificate].Text = "      ✔";


                        mPacketTrace.Items[index].SubItems[(int)IP_List_Column.Column_Info].Text = listIPTrace[i].Information;
                    }
                }

                UpdateInfoBar();

                //在讀pcap檔案模式下，指示出不再有新的封包，這部分也作為整個讀檔的結尾。
                if (goBreak)
                {
                    trdUpdateListUIAct = false;
                    PcapFileEOF = false;
                    Status = EnumStatus.Idle;
                    //this.Text = "Packets Monitor ";
                    mStatusMonitor.Text = "Status : Idle     ";
                    MessageBox.Show("File EOF");
                    break;
                }
                Thread.Sleep(3000);
            }
        }

        private void UpdateInfoBar()
        {
            string TotalStream = TotalPacketStream.ToString("N");
            mStatusStreams.Text = "Total Streams(Byte) : " + TotalStream.Remove(TotalStream.IndexOf("."), 3) + "     ";

            string count = listIPTrace.Count.ToString("N");
            mStatusCommuncations.Text = "Connections : " + count.Remove(count.IndexOf("."), 3) + "     ";

            mStatusLastPacketTime.Text = "Last Packet Arrival Time : " + LastPacketArrivalTime + "     ";
        }

        // Open Dialog to show where is the location on the google map when double click the IP Trace UI.
        private void mPacketTrace_SelectedDoubleClick(object sender, EventArgs e)
        {
            CityResponse IP1, IP2;
            double IP1_Latitude, IP1_Longitude, IP2_Latitude, IP2_Longitude;
            string IP_1 = mPacketTrace.SelectedItems[0].SubItems[(int)IP_List_Column.Column_Address_IP1].Text;
            string IP_2 = mPacketTrace.SelectedItems[0].SubItems[(int)IP_List_Column.Column_Address_IP2].Text;

            try
            {
                IP1 = GeoIP_DatabaseReader.City(IP_1);
                IP1_Latitude = (double)IP1.Location.Latitude;  //緯度
                IP1_Longitude = (double)IP1.Location.Longitude;    //經度
            }
            catch
            {
                IP1_Latitude = 0;
                IP1_Longitude = 0;
            }

            try
            {
                IP2 = GeoIP_DatabaseReader.City(IP_2);
                IP2_Latitude = (double)IP2.Location.Latitude;  //緯度
                IP2_Longitude = (double)IP2.Location.Longitude;    //經度
            }
            catch
            {
                IP2_Latitude = 0;
                IP2_Longitude = 0;
            }
            // myBuilder.Append(DstLatitude + "," + DstLongitude);
            ShowMapForm ShowMap = new ShowMapForm(IP_1, IP_2, IP1_Latitude, IP1_Longitude, IP2_Latitude, IP2_Longitude);
            // ShowMap.Text = mPacketTrace.SelectedItems[0].SubItems[1].Text + " ( " + myBuilder.ToString() + " ) ";
            ShowMap.Show();
        }

        // Sorting ListView
        private void mPacketTrace_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            mPacketTrace.ListViewItemSorter = new ListViewItemComparer(e.Column);
        }

        // 被選中的IP若有SSL資訊則列出
        private void mPacketTrace_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            try
            {
                if (e.Item.SubItems[(int)IP_List_Column.Column_Certificate].Text == "")
                {
                    mTxtCettificateContent.Text = "";
                    return;
                }

                int index;
                if (!int.TryParse(e.Item.SubItems[(int)IP_List_Column.Column_No].Text, out index))
                    return;

                IPTraceInfo IP = listIPTrace[index];
                string Information;

                Information = "Server IP : " + IP.certificate.ServerIP + "\r\n\r\n";
                Information += "User   IP : " + IP.certificate.UserIP + "\r\n\r\n";
                Information += "Server   Port : " + IP.certificate.ServerPort + "\r\n\r\n";
                Information += "User   Port : " + IP.certificate.UserPort + "\r\n\r\n";

                if (IP.certificate.Country.Count != 0)
                {
                    Information += "Country   : " + IP.certificate.Country[0];
                    for (int i = 1; i < IP.certificate.Country.Count; i++)
                    {
                        Information += "   、  " + IP.certificate.Country[i];
                    }
                    Information += "\r\n\r\n";
                }
                if (IP.certificate.StateOrProvince.Count != 0)
                {
                    Information += "State Or Province   : " + IP.certificate.StateOrProvince[0];
                    for (int i = 1; i < IP.certificate.StateOrProvince.Count; i++)
                    {
                        Information += "   、  " + IP.certificate.StateOrProvince[i];
                    }
                    Information += "\r\n\r\n";
                }
                if (IP.certificate.Locality.Count != 0)
                {
                    Information += "Locality   : " + IP.certificate.Locality[0];
                    for (int i = 1; i < IP.certificate.Locality.Count; i++)
                    {
                        Information += "   、  " + IP.certificate.Locality[i];
                    }
                    Information += "\r\n\r\n";
                }
                if (IP.certificate.Organization.Count != 0)
                {
                    Information += "Organization   : " + IP.certificate.Organization[0];
                    for (int i = 1; i < IP.certificate.Organization.Count; i++)
                    {
                        Information += "   、  " + IP.certificate.Organization[i];
                    }
                    Information += "\r\n\r\n";
                }
                if (IP.certificate.CommonName.Count != 0)
                {
                    Information += "CommonName   : " + IP.certificate.CommonName[0];
                    for (int i = 1; i < IP.certificate.CommonName.Count; i++)
                    {
                        Information += "   、  " + IP.certificate.CommonName[i];
                    }
                    Information += "\r\n\r\n";
                }

                mTxtCettificateContent.Text = Information;

                #region Modified Code
                /*
                foreach (var IP in listIPTrace)
                {
                    if ((e.Item.SubItems[(int)IP_List_Column.Column_Address_IP1].Text == IP.SrcIP && e.Item.SubItems[(int)IP_List_Column.Column_Address_IP2].Text == IP.DstIP) ||
                        (e.Item.SubItems[(int)IP_List_Column.Column_Address_IP1].Text == IP.DstIP && e.Item.SubItems[(int)IP_List_Column.Column_Address_IP2].Text == IP.SrcIP))
                    {
                        string Information;

                        Information = "Server IP : " + IP.SSL_Certificate.ServerIP + "\r\n\r\n";
                        Information += "User   IP : " + IP.SSL_Certificate.UserIP + "\r\n\r\n";

                        if (IP.SSL_Certificate.Country.Count != 0)
                        {
                            Information += "Country   : " + IP.SSL_Certificate.Country[0];
                            for (int i = 1; i < IP.SSL_Certificate.Country.Count; i++)
                            {
                                Information += "   、  " + IP.SSL_Certificate.Country[i] ;
                            }
                            Information += "\r\n\r\n";
                        }
                        if (IP.SSL_Certificate.StateOrProvince.Count != 0)
                        {
                            Information += "State Or Province :   : " + IP.SSL_Certificate.StateOrProvince[0];
                            for (int i = 1; i < IP.SSL_Certificate.StateOrProvince.Count; i++)
                            {
                                Information += "   、  " + IP.SSL_Certificate.StateOrProvince[i] ;
                            }
                            Information += "\r\n\r\n";
                        }
                        if (IP.SSL_Certificate.Locality.Count != 0)
                        {
                            Information += "Locality   : " + IP.SSL_Certificate.Locality[0];
                            for (int i = 1; i < IP.SSL_Certificate.Locality.Count; i++)
                            {
                                Information += "   、  " + IP.SSL_Certificate.Locality[i] ;
                            }
                            Information += "\r\n\r\n";
                        }
                        if (IP.SSL_Certificate.Organization.Count != 0)
                        {
                            Information += "Organization   : " + IP.SSL_Certificate.Organization[0];
                            for (int i = 1; i < IP.SSL_Certificate.Organization.Count; i++)
                            {
                                Information += "   、  " + IP.SSL_Certificate.Organization[i] ;
                            }
                            Information += "\r\n\r\n";
                        }
                        if (IP.SSL_Certificate.CommonName.Count != 0)
                        {
                            Information += "CommonName   : " + IP.SSL_Certificate.CommonName[0];
                            for (int i = 1; i < IP.SSL_Certificate.CommonName.Count; i++)
                            {
                                Information += "   、  " + IP.SSL_Certificate.CommonName[i] ;
                            }
                            Information += "\r\n\r\n";
                        }

                        mTxtIPContent.Text = Information;
                        break;
                    }
                    
                }*/
                #endregion
            }
            catch
            {
                mTxtCettificateContent.Text = "";
                MessageBox.Show("Please try again .");
            }
        }
        #endregion

        /*****************************************  For Page 2  *****************************************/
       /*
            #region Page2
        private void mBtnSelectDB_Click(object sender, EventArgs e)
        {
            mOpenFileDialog.Title = "Select file";
            mOpenFileDialog.InitialDirectory = Directory.GetCurrentDirectory() + "//" + FileStoragePath.GetPath_MainFolder();
            mOpenFileDialog.Filter = "DB files (*.*)|*.db";
            if (mOpenFileDialog.ShowDialog() == DialogResult.OK)
            {
                ReadDB(mOpenFileDialog.FileName);
            }
        }

        private void ReadDB(string db)
        {
            int count = 0;
            SQLiteConnection DB_Connection;
            SQLiteCommand DB_cmd;
            mTreeViewDB.Nodes.Clear();

            DB_Connection = new SQLiteConnection(@"Data source=" + db);
            //建立資料庫連線
            DB_Connection.Open();// Open
            DB_cmd = DB_Connection.CreateCommand();//create command

            if (toolStripTextBox_ServerIP.Text == string.Empty && toolStripTextBox_ClientIP.Text == string.Empty)
                DB_cmd.CommandText = "SELECT * FROM SSL";
            else
            {
                string Condition_ServerIP = toolStripTextBox_ServerIP.Text == string.Empty ? " 1=1 AND " : " ServerIP = '" + toolStripTextBox_ServerIP.Text + "' AND";
                string Condition_ClientIP = toolStripTextBox_ClientIP.Text == string.Empty ? " 1=1 " : " UserIP = '" + toolStripTextBox_ClientIP.Text + "' ";
                DB_cmd.CommandText = "SELECT * FROM SSL WHERE" + Condition_ServerIP + Condition_ClientIP;
            }

            SQLiteDataReader DB_datareader = DB_cmd.ExecuteReader();
            while (DB_datareader.Read()) //read every data
            {
                TreeNode IPnode = new TreeNode();
                IPnode.Text = "ServerIP : " + DB_datareader["ServerIP"].ToString() + "     " +
                              "UserIP : " + DB_datareader["UserIP"].ToString() + "     " +
                              "ServerPort : " + DB_datareader["ServerPort"].ToString() + "     " +
                              "UserPort : " + DB_datareader["UserPort"].ToString();
                mTreeViewDB.Nodes.Add(IPnode);

                TreeNode CipherSuiteNode = new TreeNode();
                CipherSuiteNode.Text = "CipherSuite : " + DB_datareader["CipherSuite"].ToString();
                IPnode.Nodes.Add(CipherSuiteNode);

                TreeNode KeyNode = new TreeNode();
                KeyNode.Text = "SSL Keys : ";
                IPnode.Nodes.Add(KeyNode);

                TreeNode CertificateNode = new TreeNode();
                CertificateNode.Text = "Certificate : ";
                IPnode.Nodes.Add(CertificateNode);

                TreeNode PubKeyNode = new TreeNode();
                PubKeyNode.Text = "Pubkey : " + DB_datareader["Pubkey"].ToString();
                TreeNode SessionKeyNode = new TreeNode();
                SessionKeyNode.Text = "SessionKey : " + DB_datareader["SessionKey"].ToString();
                TreeNode NewSessionKeyNode = new TreeNode();
                NewSessionKeyNode.Text = "NewSeesionTicket : " + DB_datareader["NewSeesionTicket"].ToString();
                KeyNode.Nodes.Add(PubKeyNode);
                KeyNode.Nodes.Add(SessionKeyNode);
                KeyNode.Nodes.Add(NewSessionKeyNode);

                TreeNode Country = new TreeNode();
                Country.Text = "Country : " + DB_datareader["Country"].ToString();
                TreeNode StateOrProvinceNode = new TreeNode();
                StateOrProvinceNode.Text = "StateOrProvince : " + DB_datareader["StateOrProvince"].ToString();
                TreeNode LocalityNode = new TreeNode();
                LocalityNode.Text = "Locality : " + DB_datareader["Locality"].ToString();
                TreeNode OrganizationNode = new TreeNode();
                OrganizationNode.Text = "Organization : " + DB_datareader["Organization"].ToString();
                TreeNode CommonNameNode = new TreeNode();
                CommonNameNode.Text = "CommonName : " + DB_datareader["CommonName"].ToString();
                CertificateNode.Nodes.Add(Country);
                CertificateNode.Nodes.Add(StateOrProvinceNode);
                CertificateNode.Nodes.Add(LocalityNode);
                CertificateNode.Nodes.Add(OrganizationNode);
                CertificateNode.Nodes.Add(CommonNameNode);

                count++;
                mStatusCountDB.Text = "Total : " + count.ToString();
            }
        }
        #endregion
            */

    }
}
