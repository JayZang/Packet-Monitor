using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SQLite;
using System.IO;

namespace PacketMonitor
{
    public class DBManage
    {
        static public void GetDBHandler(DBDataType type, out SQLiteConnection connection, out SQLiteCommand cmd)
        {
            string path;
            string FileName;

            switch (type)
            {
                case DBDataType.SSL:
                    path = FileStoragePath.GetPath_SSL();
                    FileName = DateTime.Now.ToString("tt hh.mm.ss") + ".db";

                    if (!File.Exists( path + "\\" + FileName ) )
                    {
                        SQLiteConnection.CreateFile( path + "\\" + FileName );
                    }

                    connection = new SQLiteConnection("Data source=" + path + "\\" + FileName);
                    connection.Open();// Open
                    cmd = connection.CreateCommand();//create command
                    cmd.CommandText = @"CREATE TABLE IF NOT EXISTS SSL (UserIP TEXT, ServerIP TEXT, UserPort TEXT, ServerPort TEXT , CipherSuite TEXT, Pubkey TEXT, SessionKey TEXT, NewSeesionTicket TEXT,Country TEXT,StateOrProvince TEXT,Locality TEXT,Organization TEXT,CommonName TEXT)";
                    cmd.ExecuteNonQuery();

                    return;
            }

            connection = null;
            cmd = null;
        }      
    }

    public enum DBDataType : int
    {
        SSL
    }

}
