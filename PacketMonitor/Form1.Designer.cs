using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;
using System.Threading;
using System.Collections.Generic;
using MaxMind.GeoIP2;
using PacketMonitor.SIP;
using PacketMonitor.SSL;
using PacketMonitor.IPTraceInfomation;
using System;
using System.IO;
using System.Data.SQLite;
using System.Drawing;


namespace PacketMonitor
{
    partial class PacketMonitorForm
    {
        /// <summary>
        /// 設計工具所需的變數。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清除任何使用中的資源。
        /// </summary>
        /// <param name="disposing">如果應該處置 Managed 資源則為 true，否則為 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form 設計工具產生的程式碼

        /// <summary>
        /// 此為設計工具支援所需的方法 - 請勿使用程式碼編輯器修改
        /// 這個方法的內容。
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(PacketMonitorForm));
            this.mOpenFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.mStatusStrip_Monitor = new System.Windows.Forms.StatusStrip();
            this.mStatusMonitor = new System.Windows.Forms.ToolStripStatusLabel();
            this.mStatusCommuncations = new System.Windows.Forms.ToolStripStatusLabel();
            this.mStatusStreams = new System.Windows.Forms.ToolStripStatusLabel();
            this.mStatusLastPacketTime = new System.Windows.Forms.ToolStripStatusLabel();
            this.mToolStrip_Monitor = new System.Windows.Forms.ToolStrip();
            this.toolStripSeparator5 = new System.Windows.Forms.ToolStripSeparator();
            this.mBtnSelectInterface = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator4 = new System.Windows.Forms.ToolStripSeparator();
            this.mBtnStartMonitor = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.mBtnStopMonitor = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.mBtnOpenFolder = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator8 = new System.Windows.Forms.ToolStripSeparator();
            this.mPanelIpInfo = new System.Windows.Forms.Panel();
            this.mTxtCettificateContent = new System.Windows.Forms.TextBox();
            this.mSplitterPage1 = new System.Windows.Forms.Splitter();
            this.mPanelIpTrace = new System.Windows.Forms.Panel();
            this.mReadFileProgressBar = new System.Windows.Forms.ProgressBar();
            this.mPacketTrace = new PacketMonitor.NewListView();
            this.columnHeader9 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader4 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader5 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader3 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader6 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader7 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader8 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.mStatusStrip_Monitor.SuspendLayout();
            this.mToolStrip_Monitor.SuspendLayout();
            this.mPanelIpInfo.SuspendLayout();
            this.mPanelIpTrace.SuspendLayout();
            this.SuspendLayout();
            // 
            // mStatusStrip_Monitor
            // 
            this.mStatusStrip_Monitor.AutoSize = false;
            this.mStatusStrip_Monitor.BackColor = System.Drawing.Color.WhiteSmoke;
            this.mStatusStrip_Monitor.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.mStatusStrip_Monitor.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mStatusMonitor,
            this.mStatusCommuncations,
            this.mStatusStreams,
            this.mStatusLastPacketTime});
            this.mStatusStrip_Monitor.Location = new System.Drawing.Point(0, 584);
            this.mStatusStrip_Monitor.Name = "mStatusStrip_Monitor";
            this.mStatusStrip_Monitor.Padding = new System.Windows.Forms.Padding(1, 0, 10, 0);
            this.mStatusStrip_Monitor.Size = new System.Drawing.Size(1101, 20);
            this.mStatusStrip_Monitor.TabIndex = 10;
            // 
            // mStatusMonitor
            // 
            this.mStatusMonitor.Name = "mStatusMonitor";
            this.mStatusMonitor.Size = new System.Drawing.Size(97, 15);
            this.mStatusMonitor.Text = "Status : None     ";
            this.mStatusMonitor.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // mStatusCommuncations
            // 
            this.mStatusCommuncations.Name = "mStatusCommuncations";
            this.mStatusCommuncations.Size = new System.Drawing.Size(108, 15);
            this.mStatusCommuncations.Text = "Connections : 0     ";
            this.mStatusCommuncations.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // mStatusStreams
            // 
            this.mStatusStreams.Name = "mStatusStreams";
            this.mStatusStreams.Size = new System.Drawing.Size(147, 15);
            this.mStatusStreams.Text = "Total Streams(Byte) : 0     ";
            this.mStatusStreams.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // mStatusLastPacketTime
            // 
            this.mStatusLastPacketTime.Name = "mStatusLastPacketTime";
            this.mStatusLastPacketTime.Size = new System.Drawing.Size(197, 15);
            this.mStatusLastPacketTime.Text = "Last Packet Arrival Time :  None     ";
            // 
            // mToolStrip_Monitor
            // 
            this.mToolStrip_Monitor.AutoSize = false;
            this.mToolStrip_Monitor.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(224)))), ((int)(((byte)(224)))), ((int)(((byte)(224)))));
            this.mToolStrip_Monitor.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.mToolStrip_Monitor.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.mToolStrip_Monitor.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripSeparator5,
            this.mBtnSelectInterface,
            this.toolStripSeparator4,
            this.mBtnStartMonitor,
            this.toolStripSeparator1,
            this.mBtnStopMonitor,
            this.toolStripSeparator2,
            this.mBtnOpenFolder,
            this.toolStripSeparator8});
            this.mToolStrip_Monitor.Location = new System.Drawing.Point(0, 0);
            this.mToolStrip_Monitor.Name = "mToolStrip_Monitor";
            this.mToolStrip_Monitor.Size = new System.Drawing.Size(1101, 32);
            this.mToolStrip_Monitor.TabIndex = 12;
            this.mToolStrip_Monitor.Text = "toolStrip1";
            // 
            // toolStripSeparator5
            // 
            this.toolStripSeparator5.Name = "toolStripSeparator5";
            this.toolStripSeparator5.Size = new System.Drawing.Size(6, 32);
            // 
            // mBtnSelectInterface
            // 
            this.mBtnSelectInterface.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.mBtnSelectInterface.Font = new System.Drawing.Font("Microsoft JhengHei UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(136)));
            this.mBtnSelectInterface.Image = global::PacketMonitor.Properties.Resources.computer_setting;
            this.mBtnSelectInterface.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.mBtnSelectInterface.Name = "mBtnSelectInterface";
            this.mBtnSelectInterface.Size = new System.Drawing.Size(24, 29);
            this.mBtnSelectInterface.Text = "Select Interface";
            this.mBtnSelectInterface.Click += new System.EventHandler(this.mBtnSelectInterface_Click);
            // 
            // toolStripSeparator4
            // 
            this.toolStripSeparator4.Name = "toolStripSeparator4";
            this.toolStripSeparator4.Size = new System.Drawing.Size(6, 32);
            // 
            // mBtnStartMonitor
            // 
            this.mBtnStartMonitor.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.mBtnStartMonitor.Image = global::PacketMonitor.Properties.Resources._1495655970_Play01;
            this.mBtnStartMonitor.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.mBtnStartMonitor.Name = "mBtnStartMonitor";
            this.mBtnStartMonitor.Size = new System.Drawing.Size(24, 29);
            this.mBtnStartMonitor.Text = "Start";
            this.mBtnStartMonitor.TextImageRelation = System.Windows.Forms.TextImageRelation.TextAboveImage;
            this.mBtnStartMonitor.Click += new System.EventHandler(this.mBtnStartMonitor_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(6, 32);
            // 
            // mBtnStopMonitor
            // 
            this.mBtnStopMonitor.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.mBtnStopMonitor.Image = global::PacketMonitor.Properties.Resources.stop;
            this.mBtnStopMonitor.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.mBtnStopMonitor.Name = "mBtnStopMonitor";
            this.mBtnStopMonitor.Size = new System.Drawing.Size(24, 29);
            this.mBtnStopMonitor.Text = "  Stop  ";
            this.mBtnStopMonitor.Click += new System.EventHandler(this.mBtnStopMonitor_Click);
            // 
            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(6, 32);
            // 
            // mBtnOpenFolder
            // 
            this.mBtnOpenFolder.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.mBtnOpenFolder.Image = global::PacketMonitor.Properties.Resources.open_folder;
            this.mBtnOpenFolder.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.mBtnOpenFolder.Name = "mBtnOpenFolder";
            this.mBtnOpenFolder.Size = new System.Drawing.Size(24, 29);
            this.mBtnOpenFolder.Text = "Open Folder";
            this.mBtnOpenFolder.Click += new System.EventHandler(this.mBtnOpenFolder_Click);
            // 
            // toolStripSeparator8
            // 
            this.toolStripSeparator8.Name = "toolStripSeparator8";
            this.toolStripSeparator8.Size = new System.Drawing.Size(6, 32);
            // 
            // mPanelIpInfo
            // 
            this.mPanelIpInfo.Controls.Add(this.mTxtCettificateContent);
            this.mPanelIpInfo.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.mPanelIpInfo.Location = new System.Drawing.Point(0, 446);
            this.mPanelIpInfo.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mPanelIpInfo.Name = "mPanelIpInfo";
            this.mPanelIpInfo.Size = new System.Drawing.Size(1101, 138);
            this.mPanelIpInfo.TabIndex = 17;
            // 
            // mTxtCettificateContent
            // 
            this.mTxtCettificateContent.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(240)))), ((int)(((byte)(240)))), ((int)(((byte)(240)))));
            this.mTxtCettificateContent.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mTxtCettificateContent.Font = new System.Drawing.Font("新細明體", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(136)));
            this.mTxtCettificateContent.Location = new System.Drawing.Point(0, 0);
            this.mTxtCettificateContent.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mTxtCettificateContent.Multiline = true;
            this.mTxtCettificateContent.Name = "mTxtCettificateContent";
            this.mTxtCettificateContent.ReadOnly = true;
            this.mTxtCettificateContent.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.mTxtCettificateContent.Size = new System.Drawing.Size(1101, 138);
            this.mTxtCettificateContent.TabIndex = 11;
            // 
            // mSplitterPage1
            // 
            this.mSplitterPage1.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.mSplitterPage1.Location = new System.Drawing.Point(0, 444);
            this.mSplitterPage1.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mSplitterPage1.Name = "mSplitterPage1";
            this.mSplitterPage1.Size = new System.Drawing.Size(1101, 2);
            this.mSplitterPage1.TabIndex = 18;
            this.mSplitterPage1.TabStop = false;
            // 
            // mPanelIpTrace
            // 
            this.mPanelIpTrace.Controls.Add(this.mPacketTrace);
            this.mPanelIpTrace.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mPanelIpTrace.Location = new System.Drawing.Point(0, 32);
            this.mPanelIpTrace.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mPanelIpTrace.Name = "mPanelIpTrace";
            this.mPanelIpTrace.Size = new System.Drawing.Size(1101, 412);
            this.mPanelIpTrace.TabIndex = 19;
            // 
            // mReadFileProgressBar
            // 
            this.mReadFileProgressBar.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.mReadFileProgressBar.Location = new System.Drawing.Point(934, 586);
            this.mReadFileProgressBar.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mReadFileProgressBar.Name = "mReadFileProgressBar";
            this.mReadFileProgressBar.Size = new System.Drawing.Size(150, 16);
            this.mReadFileProgressBar.TabIndex = 20;
            // 
            // mPacketTrace
            // 
            this.mPacketTrace.AllowColumnReorder = true;
            this.mPacketTrace.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader9,
            this.columnHeader1,
            this.columnHeader2,
            this.columnHeader4,
            this.columnHeader5,
            this.columnHeader3,
            this.columnHeader6,
            this.columnHeader7,
            this.columnHeader8});
            this.mPacketTrace.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mPacketTrace.Font = new System.Drawing.Font("新細明體", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(136)));
            this.mPacketTrace.FullRowSelect = true;
            this.mPacketTrace.GridLines = true;
            this.mPacketTrace.HideSelection = false;
            this.mPacketTrace.Location = new System.Drawing.Point(0, 0);
            this.mPacketTrace.Margin = new System.Windows.Forms.Padding(2);
            this.mPacketTrace.MultiSelect = false;
            this.mPacketTrace.Name = "mPacketTrace";
            this.mPacketTrace.Size = new System.Drawing.Size(1101, 412);
            this.mPacketTrace.TabIndex = 6;
            this.mPacketTrace.UseCompatibleStateImageBehavior = false;
            this.mPacketTrace.View = System.Windows.Forms.View.Details;
            this.mPacketTrace.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.mPacketTrace_ColumnClick);
            this.mPacketTrace.ItemSelectionChanged += new System.Windows.Forms.ListViewItemSelectionChangedEventHandler(this.mPacketTrace_ItemSelectionChanged);
            this.mPacketTrace.DoubleClick += new System.EventHandler(this.mPacketTrace_SelectedDoubleClick);
            // 
            // columnHeader9
            // 
            this.columnHeader9.Text = "No";
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "IP Address 1";
            this.columnHeader1.Width = 135;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "IP Address 2";
            this.columnHeader2.Width = 135;
            // 
            // columnHeader4
            // 
            this.columnHeader4.Text = "IP1 Country ";
            this.columnHeader4.Width = 200;
            // 
            // columnHeader5
            // 
            this.columnHeader5.Text = "IP2 Country ";
            this.columnHeader5.Width = 200;
            // 
            // columnHeader3
            // 
            this.columnHeader3.Text = "IP1 >> IP2 ( Byte )";
            this.columnHeader3.Width = 130;
            // 
            // columnHeader6
            // 
            this.columnHeader6.Text = "IP1 << IP2 ( Byte )";
            this.columnHeader6.Width = 130;
            // 
            // columnHeader7
            // 
            this.columnHeader7.Text = "Certificate";
            this.columnHeader7.Width = 70;
            // 
            // columnHeader8
            // 
            this.columnHeader8.Text = "Information";
            this.columnHeader8.Width = 365;
            // 
            // PacketMonitorForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.Control;
            this.ClientSize = new System.Drawing.Size(1101, 604);
            this.Controls.Add(this.mReadFileProgressBar);
            this.Controls.Add(this.mPanelIpTrace);
            this.Controls.Add(this.mSplitterPage1);
            this.Controls.Add(this.mPanelIpInfo);
            this.Controls.Add(this.mToolStrip_Monitor);
            this.Controls.Add(this.mStatusStrip_Monitor);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.Name = "PacketMonitorForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.Manual;
            this.Text = "Packets Monitor";
            this.TransparencyKey = System.Drawing.SystemColors.GradientActiveCaption;
            this.WindowState = System.Windows.Forms.FormWindowState.Maximized;
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.FormClosing_EventHandler);
            this.mStatusStrip_Monitor.ResumeLayout(false);
            this.mStatusStrip_Monitor.PerformLayout();
            this.mToolStrip_Monitor.ResumeLayout(false);
            this.mToolStrip_Monitor.PerformLayout();
            this.mPanelIpInfo.ResumeLayout(false);
            this.mPanelIpInfo.PerformLayout();
            this.mPanelIpTrace.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        /******************************  For Common ******************************/
        DatabaseReader GeoIP_DatabaseReader = new DatabaseReader("..\\..\\DLL\\GeoIP\\GeoLite2-City.mmdb");  // open the GeoIP Datebase. Find location by IP
        private System.Windows.Forms.OpenFileDialog mOpenFileDialog;
        private const long PcapFileMaxSizeOfByte = 200000000;

        /******************************  For Page 1  ******************************/
        #region Page1
        private EnumStatus Status;
        private SelectInterface SelectInterfaceForm = null;
        private LibPcapLiveDevice Device = null;
        private CaptureFileWriterDevice AllPcapFileWriter = null;
        private string LastPacketArrivalTime;
        private long TotalPacketStream;
        private Thread trdGetPacketFromQueue;           // Open the thread to get packets from the queue.
        private Thread trdUpdateListUI;                 // Open the thread to update IP list.
        private bool trdGetPacketFromQueueAct = false;  // Used to contol the thread to stop.
        private bool trdUpdateListUIAct = false;        // Used to contol the thread to stop.
        private bool PcapFileEOF = false;               // When reading file mode,if EOF  it will be true.
        private object PacketQueueLock = new object();  // The object is used to be locked.
        private Queue<RawCapture> PacketQueue;          // Push raw packet to the queue.
        public List<IPTraceInfo> listIPTrace;               // Push the IP data contents to list.
        private SIPTRACE SIPTrace ;                     // Used to handle SIP and RTP packets
        private SSLTracer SSLTrace;

        #endregion

        /******************************  For Page 2  ******************************/
        #region Page2
        #endregion

        /******************************  For Page 3  ******************************/
        #region Page3


        #endregion
        private System.Windows.Forms.Panel mPanelIpTrace;
        public NewListView mPacketTrace;
        private System.Windows.Forms.ColumnHeader columnHeader9;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.ColumnHeader columnHeader4;
        private System.Windows.Forms.ColumnHeader columnHeader5;
        private System.Windows.Forms.ColumnHeader columnHeader3;
        private System.Windows.Forms.ColumnHeader columnHeader6;
        private System.Windows.Forms.ColumnHeader columnHeader7;
        private System.Windows.Forms.ColumnHeader columnHeader8;
        private System.Windows.Forms.Splitter mSplitterPage1;
        private System.Windows.Forms.Panel mPanelIpInfo;
        private System.Windows.Forms.TextBox mTxtCettificateContent;
        private System.Windows.Forms.ToolStrip mToolStrip_Monitor;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator5;
        private System.Windows.Forms.ToolStripButton mBtnSelectInterface;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator4;
        private System.Windows.Forms.ToolStripButton mBtnStartMonitor;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripButton mBtnStopMonitor;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripButton mBtnOpenFolder;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator8;
        private System.Windows.Forms.StatusStrip mStatusStrip_Monitor;
        private System.Windows.Forms.ToolStripStatusLabel mStatusMonitor;
        private System.Windows.Forms.ToolStripStatusLabel mStatusCommuncations;
        private System.Windows.Forms.ToolStripStatusLabel mStatusStreams;
        private System.Windows.Forms.ToolStripStatusLabel mStatusLastPacketTime;
        private System.Windows.Forms.ProgressBar mReadFileProgressBar;
    }

    public enum Mode
    {
        Monitor,
        File
    }

    enum EnumStatus
    {
        Idle,
        Monitor,
        OpenFile
    }

    enum IP_List_Column : int
    {
        Column_No = 0,
        Column_Address_IP1 = 1,
        Column_Address_IP2 = 2,
        Column_Country_IP1 = 3,
        Column_Country_IP2 = 4,
        Column_Stream_IP1ToIP2 = 5,
        Column_Stream_IP2ToIP1 = 6,
        Column_Certificate = 7,
        Column_Info = 8
    }
}

