using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using GMap.NET;
using GMap.NET.WindowsForms;
using GMap.NET.MapProviders;
using GMap.NET.WindowsForms.Markers;

namespace PacketMonitor
{
    public partial class ShowMapForm : Form
    {
        private GMapOverlay markersOverlay = new GMapOverlay("markers"); //放置marker的图层

        public ShowMapForm(string _IP1, string _IP2, double _IP1_lat, double _IP1_lng, double _IP2_lat, double _IP2_lng)
        {
            InitializeComponent();

            IP1 = _IP1;
            IP2 = _IP2;
            IP1_lat = _IP1_lat;
            IP1_lng = _IP1_lng;
            IP2_lat = _IP2_lat;
            IP2_lng = _IP2_lng;

            this.Text = "IP 1 : " + IP1 + " ( " + IP1_lat + " , " + IP1_lng + " ) ";

            gMapControl1.CacheLocation = Environment.CurrentDirectory + "\\GMapCache\\"; //缓存位置
            gMapControl1.MapProvider = GMapProviders.GoogleChinaMap; //google china 地图
            gMapControl1.MinZoom = 2;  //最小比例
            gMapControl1.MaxZoom = 24; //最大比例
            gMapControl1.Zoom = 10;     //当前比例
            gMapControl1.ShowCenter = false; //不显示中心十字点
            gMapControl1.DragButton = System.Windows.Forms.MouseButtons.Left; //左键拖拽地图
            gMapControl1.Position = new PointLatLng(IP1_lat, IP1_lng); //地图中心位置
            GMapProvider.Language = LanguageType.ChineseTraditional;
            gMapControl1.Overlays.Add(markersOverlay);

            PointLatLng point = new PointLatLng(IP1_lat, IP1_lng);
            GeoCoderStatusCode statusCode = GeoCoderStatusCode.Unknow;
            var gp = gMapControl1.MapProvider as GeocodingProvider;
            Placemark? place = gp.GetPlacemark(point, out statusCode);
            if (statusCode == GeoCoderStatusCode.G_GEO_SUCCESS)
            {
                GMapMarker marker = new GMarkerGoogle(point, GMarkerGoogleType.green);
                marker.ToolTipText = place.Value.Address;
                marker.ToolTipMode = MarkerTooltipMode.Always;

                markersOverlay.Markers.Add(marker);
            }

            //gMapControl1.MouseClick += new MouseEventHandler(mapControl_MouseClick);
        }

        // do something when mouse clicked
        void mapControl_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == System.Windows.Forms.MouseButtons.Right)
            {
                PointLatLng point = gMapControl1.FromLocalToLatLng(e.X, e.Y);
                GMapMarker marker = new GMarkerGoogle(point, GMarkerGoogleType.green);
                markersOverlay.Markers.Add(marker);
            }
        }

        private void mBtnIP1_Click(object sender, EventArgs e)
        {
            this.Text = "IP 1 : " + IP1 + " ( " + IP1_lat + " , " + IP1_lng + " ) ";

            gMapControl1.CacheLocation = Environment.CurrentDirectory + "\\GMapCache\\"; //缓存位置
            gMapControl1.MapProvider = GMapProviders.GoogleChinaMap; //google china 地图
            gMapControl1.MinZoom = 2;  //最小比例
            gMapControl1.MaxZoom = 24; //最大比例
            gMapControl1.Zoom = 10;     //当前比例
            gMapControl1.ShowCenter = false; //不显示中心十字点
            gMapControl1.DragButton = System.Windows.Forms.MouseButtons.Left; //左键拖拽地图
            gMapControl1.Position = new PointLatLng(IP1_lat, IP1_lng); //地图中心位置
            GMapProvider.Language = LanguageType.ChineseTraditional;
            gMapControl1.Overlays.Add(markersOverlay);

            PointLatLng point = new PointLatLng(IP1_lat, IP1_lng);
            GeoCoderStatusCode statusCode = GeoCoderStatusCode.Unknow;
            var gp = gMapControl1.MapProvider as GeocodingProvider;
            Placemark? place = gp.GetPlacemark(point, out statusCode);
            if (statusCode == GeoCoderStatusCode.G_GEO_SUCCESS)
            {
                GMapMarker marker = new GMarkerGoogle(point, GMarkerGoogleType.green);
                marker.ToolTipText = place.Value.Address;
                marker.ToolTipMode = MarkerTooltipMode.Always;

                markersOverlay.Markers.Add(marker);
            }
        }

        private void mBtnIP2_Click(object sender, EventArgs e)
        {
            this.Text = "IP 2 : " + IP2 + " ( " + IP2_lat + " , " + IP2_lng + " ) ";

            gMapControl1.CacheLocation = Environment.CurrentDirectory + "\\GMapCache\\"; //缓存位置
            gMapControl1.MapProvider = GMapProviders.GoogleChinaMap; //google china 地图
            gMapControl1.MinZoom = 2;  //最小比例
            gMapControl1.MaxZoom = 24; //最大比例
            gMapControl1.Zoom = 10;     //当前比例
            gMapControl1.ShowCenter = false; //不显示中心十字点
            gMapControl1.DragButton = System.Windows.Forms.MouseButtons.Left; //左键拖拽地图
            gMapControl1.Position = new PointLatLng(IP2_lat, IP2_lng); //地图中心位置
            GMapProvider.Language = LanguageType.ChineseTraditional;
            gMapControl1.Overlays.Add(markersOverlay);

            PointLatLng point = new PointLatLng(IP2_lat, IP2_lng);
            GeoCoderStatusCode statusCode = GeoCoderStatusCode.Unknow;
            var gp = gMapControl1.MapProvider as GeocodingProvider;
            Placemark? place = gp.GetPlacemark(point, out statusCode);
            if (statusCode == GeoCoderStatusCode.G_GEO_SUCCESS)
            {
                GMapMarker marker = new GMarkerGoogle(point, GMarkerGoogleType.green);
                marker.ToolTipText = place.Value.Address;
                marker.ToolTipMode = MarkerTooltipMode.Always;

                markersOverlay.Markers.Add(marker);
            }
        }
    }
}
