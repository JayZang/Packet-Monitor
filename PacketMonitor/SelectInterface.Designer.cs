using SharpPcap.LibPcap;

namespace PacketMonitor
{
    partial class SelectInterface
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SelectInterface));
            this.mDeviceList = new System.Windows.Forms.ListBox();
            this.SuspendLayout();
            // 
            // mDeviceList
            // 
            this.mDeviceList.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.mDeviceList.Font = new System.Drawing.Font("新細明體", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(136)));
            this.mDeviceList.FormattingEnabled = true;
            this.mDeviceList.ItemHeight = 16;
            this.mDeviceList.Location = new System.Drawing.Point(9, 10);
            this.mDeviceList.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.mDeviceList.Name = "mDeviceList";
            this.mDeviceList.Size = new System.Drawing.Size(1011, 324);
            this.mDeviceList.TabIndex = 0;
            this.mDeviceList.Tag = "";
            this.mDeviceList.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.mDeviceList_MouseDoubleClick);
            // 
            // SelectInterface
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1028, 338);
            this.Controls.Add(this.mDeviceList);
            this.ForeColor = System.Drawing.Color.Coral;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.Name = "SelectInterface";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Select Interface";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Form_Closing);
            this.ResumeLayout(false);

        }

        #endregion

        private bool isSelected = false;
        private LibPcapLiveDeviceList DeviceList;
        private System.Windows.Forms.ListBox mDeviceList;
    }
}