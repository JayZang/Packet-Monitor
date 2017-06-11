namespace PacketMonitor
{
    partial class ShowMapForm
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ShowMapForm));
            this.gMapControl1 = new GMap.NET.WindowsForms.GMapControl();
            this.mBtnIP1 = new System.Windows.Forms.Button();
            this.mBtnIP2 = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // gMapControl1
            // 
            this.gMapControl1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.gMapControl1.Bearing = 0F;
            this.gMapControl1.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.gMapControl1.CanDragMap = true;
            this.gMapControl1.EmptyTileColor = System.Drawing.Color.Navy;
            this.gMapControl1.GrayScaleMode = false;
            this.gMapControl1.HelperLineOption = GMap.NET.WindowsForms.HelperLineOptions.DontShow;
            this.gMapControl1.LevelsKeepInMemmory = 5;
            this.gMapControl1.Location = new System.Drawing.Point(12, 41);
            this.gMapControl1.MarkersEnabled = true;
            this.gMapControl1.MaxZoom = 2;
            this.gMapControl1.MinZoom = 2;
            this.gMapControl1.MouseWheelZoomType = GMap.NET.MouseWheelZoomType.MousePositionWithoutCenter;
            this.gMapControl1.Name = "gMapControl1";
            this.gMapControl1.NegativeMode = false;
            this.gMapControl1.PolygonsEnabled = true;
            this.gMapControl1.RetryLoadTile = 0;
            this.gMapControl1.RoutesEnabled = true;
            this.gMapControl1.ScaleMode = GMap.NET.WindowsForms.ScaleModes.Integer;
            this.gMapControl1.SelectedAreaFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(65)))), ((int)(((byte)(105)))), ((int)(((byte)(225)))));
            this.gMapControl1.ShowTileGridLines = false;
            this.gMapControl1.Size = new System.Drawing.Size(923, 526);
            this.gMapControl1.TabIndex = 0;
            this.gMapControl1.Zoom = 0D;
            // 
            // mBtnIP1
            // 
            this.mBtnIP1.Location = new System.Drawing.Point(12, 9);
            this.mBtnIP1.Name = "mBtnIP1";
            this.mBtnIP1.Size = new System.Drawing.Size(129, 23);
            this.mBtnIP1.TabIndex = 1;
            this.mBtnIP1.Text = "IP 1";
            this.mBtnIP1.UseVisualStyleBackColor = true;
            this.mBtnIP1.Click += new System.EventHandler(this.mBtnIP1_Click);
            // 
            // mBtnIP2
            // 
            this.mBtnIP2.Location = new System.Drawing.Point(163, 9);
            this.mBtnIP2.Name = "mBtnIP2";
            this.mBtnIP2.Size = new System.Drawing.Size(129, 23);
            this.mBtnIP2.TabIndex = 2;
            this.mBtnIP2.Text = "IP 2";
            this.mBtnIP2.UseVisualStyleBackColor = true;
            this.mBtnIP2.Click += new System.EventHandler(this.mBtnIP2_Click);
            // 
            // ShowMapForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(947, 579);
            this.Controls.Add(this.mBtnIP2);
            this.Controls.Add(this.mBtnIP1);
            this.Controls.Add(this.gMapControl1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "ShowMapForm";
            this.Text = "Form2";
            this.ResumeLayout(false);

        }

        private GMap.NET.WindowsForms.GMapControl gMapControl1;

        #endregion

        private string IP1, IP2;
        private double IP1_lat, IP1_lng, IP2_lat, IP2_lng;

        private System.Windows.Forms.Button mBtnIP1;
        private System.Windows.Forms.Button mBtnIP2;
    }
}