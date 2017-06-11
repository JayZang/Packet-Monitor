using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

// 此 ListView 在更新畫面時不會閃爍
namespace PacketMonitor
{
    public class NewListView : ListView
    {

        public NewListView()
        {
            // Activate double buffering
            this.SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);

            // Enable the OnNotifyMessage event so we get a chance to filter out 
            // Windows messages before they get to the form's WndProc
            this.SetStyle(ControlStyles.EnableNotifyMessage, true);
        }

        protected override void OnNotifyMessage(Message m)
        {
            //Filter out the WM_ERASEBKGND message
            if (m.Msg != 0x14)
            {
                base.OnNotifyMessage(m);
            }
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);

        }
    }

    class ListViewItemComparer : System.Collections.IComparer
    {
        private int col;
        public ListViewItemComparer()
        {
            col = 0;
        }
        public ListViewItemComparer(int column)
        {
            col = column;
        }
        public int Compare(object x, object y)
        {
            try
            {
                switch ((IP_List_Column)col)
                {
                    case IP_List_Column.Column_No:
                        int No1, No2;
                        int.TryParse(((ListViewItem)x).SubItems[col].Text, out No1);
                        int.TryParse(((ListViewItem)y).SubItems[col].Text, out No2);
                        return No1 - No2;

                    case IP_List_Column.Column_Country_IP1:
                    case IP_List_Column.Column_Country_IP2:
                        //if (((ListViewItem)x).SubItems[col].Text == "Virtual IP" || ((ListViewItem)y).SubItems[col].Text == "Virtual IP")
                        //{
                        //    if (((ListViewItem)x).SubItems[col].Text == "Virtual IP" && ((ListViewItem)y).SubItems[col].Text == "Virtual IP")
                        //        return 0;
                        //    else if (((ListViewItem)x).SubItems[col].Text == "Virtual IP")
                        //        return String.Compare("A", ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);
                        //    else
                        //        return String.Compare(((ListViewItem)x).SubItems[col].Text, "A", StringComparison.Ordinal);
                        //}  // 使用"A"是因為為了使 Virtual IP 能夠排列至最前面
                        //else if (((ListViewItem)x).SubItems[col].Text == "Not Found" || ((ListViewItem)y).SubItems[col].Text == "Not Found")
                        //{
                        //    if (((ListViewItem)x).SubItems[col].Text == "Not Found" && ((ListViewItem)y).SubItems[col].Text == "Not Found")
                        //        return 0;
                        //    else if (((ListViewItem)x).SubItems[col].Text == "Not Found")
                        //        return String.Compare("AA", ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);
                        //    else
                        //        return String.Compare(((ListViewItem)x).SubItems[col].Text, "AA", StringComparison.Ordinal);
                        //} // 使用"AA"是因為為了使 Not Found 能夠排列至前面第二順位
                        if (((ListViewItem)x).SubItems[col].Text == "" || ((ListViewItem)y).SubItems[col].Text == "")
                        {
                            if (((ListViewItem)x).SubItems[col].Text == "" && ((ListViewItem)y).SubItems[col].Text == "")
                                return 0;
                            else if (((ListViewItem)x).SubItems[col].Text == "")
                                return String.Compare("ZZ", ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);
                            else
                                return String.Compare(((ListViewItem)x).SubItems[col].Text, "ZZ", StringComparison.Ordinal);
                        }
                        else
                            return String.Compare(((ListViewItem)x).SubItems[col].Text, ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);

                    case IP_List_Column.Column_Stream_IP1ToIP2:
                    case IP_List_Column.Column_Stream_IP2ToIP1:
                        try
                        {
                            int a = 0, b = 0;
                            string X = null, Y = null;
                            List<char> A = ((ListViewItem)x).SubItems[col].Text.ToList();
                            List<char> B = ((ListViewItem)y).SubItems[col].Text.ToList();
                            foreach (var par in A)
                            {
                                if (par == 0x2C)     // par == ","
                                    continue;
                                X += par.ToString();
                            }
                            foreach (var par in B)
                            {
                                if (par == 0x2C)     // par == ","
                                    continue;
                                Y += par.ToString();
                            }

                            int.TryParse(X, out a);
                            int.TryParse(Y, out b);
                            return b - a;
                        }
                        catch
                        {
                            return 0;
                        }

                    case IP_List_Column.Column_Certificate:
                        return -String.Compare(((ListViewItem)x).SubItems[col].Text, ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);

                    default:
                        return String.Compare(((ListViewItem)x).SubItems[col].Text, ((ListViewItem)y).SubItems[col].Text, StringComparison.Ordinal);
                }
            }
            catch
            {
                return 0;
            }
        }
    }
}
