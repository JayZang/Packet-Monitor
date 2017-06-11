using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using SharpPcap.LibPcap;

namespace PacketMonitor
{
    public partial class SelectInterface : Form
    {
        public SelectInterface()
        {
            InitializeComponent();
            ShowDeviceList();
        }

        private void ShowDeviceList()
        {
            DeviceList = LibPcapLiveDeviceList.Instance;
            if (DeviceList.Count < 1)
            {
                MessageBox.Show("No devices were found on this machine");
                return;
            }

            // Show Devices
            List<string> bufList = new List<string>();
            int No = 1;
            foreach (var dev in DeviceList)
            {
                string _string = "No. " + No.ToString() + " " + dev.Name + " : " + dev.Description; 
                bufList.Add(_string);
                No++;
            }

            //mLabTotalInterfaces.Text = "Total Interfaces : " + DeviceList.Count.ToString();
            mDeviceList.DataSource = bufList;
        }

        public LibPcapLiveDevice GetDeviceList()
        {
            if (DeviceList != null)
            {
                return DeviceList[mDeviceList.SelectedIndex];
            }
            return null;
        }

        private void mDeviceList_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            isSelected = true;
            this.Close();
        }

        private void Form_Closing(object sender, FormClosingEventArgs e)
        {
            if(isSelected == false)
            {
                DeviceList = null;
            }
        }
    }
}
