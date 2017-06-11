using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketMonitor
{
    public class FileStoragePath
    {
        private static string CurrentPath = System.Windows.Forms.Application.StartupPath;
        private static string Main_Folder = "Packets";
        private static string Date_Folder;
        private static string TotalPacket_Folder = "Total Packets";
        private static string SSL_Folder = "SSL Packets";
        private static string SIP_Folder = "SIP Packets";
        private static string AppMail_Folder = "Application Mail Packets";

        private static void Create_Folder(List<string> Folder)
        {
            if (!Directory.Exists(Main_Folder))
                Directory.CreateDirectory(Main_Folder);

            if (Folder == null)
                return;

            string stringBuf = Main_Folder;
            foreach (var folder in Folder)
            {
                stringBuf = stringBuf + "\\" + folder;
                if (!Directory.Exists(stringBuf))
                    Directory.CreateDirectory(stringBuf);
            }
        }

        public static string GetPath_MainFolder()
        {
            List<string> SubFolder = new List<string>();
            Date_Folder = DateTime.Now.ToString("yyyy-MM-dd");

            SubFolder.Add(Date_Folder);
            Create_Folder(SubFolder);

            return Main_Folder + "\\" + Date_Folder;
        }

        public static string GetPath_TotalPackets()
        {
            List<string> SubFolder = new List<string>();
            Date_Folder = DateTime.Now.ToString("yyyy-MM-dd");

            SubFolder.Add(Date_Folder);
            SubFolder.Add(TotalPacket_Folder);
            Create_Folder(SubFolder);

            return CurrentPath + "\\"  + Main_Folder + "\\" + Date_Folder + "\\" + TotalPacket_Folder;
        }

        public static string GetPath_SIP()
        {
            List<string> SubFolder = new List<string>();
            Date_Folder = DateTime.Now.ToString("yyyy-MM-dd");

            SubFolder.Add(Date_Folder);
            SubFolder.Add(SIP_Folder);
            Create_Folder(SubFolder);

            return Main_Folder + "\\" + Date_Folder + "\\" + SIP_Folder;
        }

        public static string GetPath_AppMail()
        {
            List<string> SubFolder = new List<string>();
            Date_Folder = DateTime.Now.ToString("yyyy-MM-dd");

            SubFolder.Add(Date_Folder);
            SubFolder.Add(AppMail_Folder);
            Create_Folder(SubFolder);

            return Main_Folder + "\\" + Date_Folder + "\\" + AppMail_Folder;
        }

        public static string GetPath_SSL()
        {
            List<string> SubFolder = new List<string>();
            Date_Folder = DateTime.Now.ToString("yyyy-MM-dd");
            var Time_Folder = DateTime.Now.ToString("tt hh.mm");

            SubFolder.Add(Date_Folder);
            SubFolder.Add(SSL_Folder);
            SubFolder.Add(Time_Folder);
            Create_Folder(SubFolder);

            return CurrentPath + "\\" + Main_Folder + "\\" + Date_Folder + "\\" + SSL_Folder + "\\" + Time_Folder;
        }
    }

}
