using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections;
using structure;

namespace GUI_PE_Viewer
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        public const int IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        public MainWindow()
        {
            InitializeComponent();
        }

        public class global
        {
            public static IMAGE_DOS_HEADER IDH;
            public static IMAGE_NT_HEADERS INH32;
            public static IMAGE_NT_HEADERS64 INH64;
            public static ArrayList ISH = new ArrayList();
            public static IMAGE_SECTION_HEADER temp_ISH;

            public static TreeViewItem sectionHeader = new TreeViewItem();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            List<Data> data = new List<Data>();
            listView.Items.Add(new Data() { Offset = "0x00", Value = "5A4D", Description = "dddddddddddddddddddddddddddddd" });



            global.sectionHeader.Header = "IMAGE SECTION HEADER";

            // sectionHeader.Items.Add(new TreeViewItem() { Header = ".data" });

            TreeView.Items.Add(global.sectionHeader);
        }

        public string Select_File()
        {
            string filePath;

            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            // Set filter for file extension and default file extension 
            dlg.DefaultExt = ".exe";
            dlg.Filter = "exe Files (*.exe)|*.exe";

            // Display OpenFileDialog by calling ShowDialog method 
            bool? result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                filePath = dlg.FileName;

                return filePath;
            }
            else
            {
                return "";
            }
        }
        public static object ByteToStructure(byte[] data, Type type)
        {
            IntPtr buff = Marshal.AllocHGlobal(data.Length); // 배열의 크기만큼 비관리 메모리 영역에 메모리를 할당한다.

            Marshal.Copy(data, 0, buff, data.Length); // 배열에 저장된 데이터를 위에서 할당한 메모리 영역에 복사한다.
            object obj = Marshal.PtrToStructure(buff, type); // 복사된 데이터를 구조체 객체로 변환한다.

            Marshal.FreeHGlobal(buff); // 비관리 메모리 영역에 할당했던 메모리를 해제함

            if (Marshal.SizeOf(obj) != data.Length) // (((PACKET_DATA)obj).TotalBytes != data.Length) // 구조체와 원래의 데이터의 크기 비교
            {
                return null; // 크기가 다르면 null 리턴
            }
            return obj; // 구조체 리턴
        }

        public int Load(string path)
        {
            int is_64 = 0;

            if (!File.Exists(@path))
            {
                return -1;
            }

            using (BinaryReader rdr = new BinaryReader(File.Open(@path, FileMode.Open)))
            {
                byte[] IDH_byte = rdr.ReadBytes(Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));

                global.IDH = (IMAGE_DOS_HEADER)ByteToStructure(IDH_byte, typeof(IMAGE_DOS_HEADER));

                rdr.BaseStream.Seek(global.IDH.e_lfanew, SeekOrigin.Begin);

                byte[] INH_byte32 = rdr.ReadBytes(Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)));

                global.INH32 = (IMAGE_NT_HEADERS)ByteToStructure(INH_byte32, typeof(IMAGE_NT_HEADERS));

                int INH_size = Marshal.SizeOf(global.INH32);

                if (global.INH32.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    is_64 = 1;

                    rdr.BaseStream.Seek(global.IDH.e_lfanew, SeekOrigin.Begin);

                    byte[] INH_byte64 = rdr.ReadBytes(Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));

                    global.INH64 = (IMAGE_NT_HEADERS64)ByteToStructure(INH_byte64, typeof(IMAGE_NT_HEADERS64));

                    INH_size = Marshal.SizeOf(global.INH64);
                }
                ArrayList ISH = new ArrayList();

                for (int i = 0; i < global.INH32.FileHeader.NumberOfSections; i++)
                {
                    rdr.BaseStream.Seek(global.IDH.e_lfanew + INH_size + Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * i, SeekOrigin.Begin);

                    byte[] ISH_byte = rdr.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));

                    global.temp_ISH = (IMAGE_SECTION_HEADER)ByteToStructure(ISH_byte, typeof(IMAGE_SECTION_HEADER));

                    ISH.Add(global.temp_ISH);
                }
            }
            return is_64;
        }
       
        public void Insert_DOS(IMAGE_DOS_HEADER IDH)
        {
            int num = 0;
            List<Data> data = new List<Data>();

            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_magic), Description = "Signature" });
            num += Marshal.SizeOf(IDH.e_magic);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_cblp), Description = "Bytes on last page of file" });
            num += Marshal.SizeOf(IDH.e_cblp);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_cp), Description = "Pages in file" });
            num += Marshal.SizeOf(IDH.e_cp);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_crlc), Description = "Relecations" });
            num += Marshal.SizeOf(IDH.e_crlc);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_cparhdr), Description = "Size of header in paragraphs" });
            num += Marshal.SizeOf(IDH.e_cparhdr);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_minalloc), Description = "Minimum extra paragraphs needed" });
            num += Marshal.SizeOf(IDH.e_minalloc);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_maxalloc), Description = "Maximum extra paragraphs needed" });
            num += Marshal.SizeOf(IDH.e_maxalloc);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_ss), Description = "Initial (relative) SS value" });
            num += Marshal.SizeOf(IDH.e_ss);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_sp), Description = "Initial SP value" });
            num += Marshal.SizeOf(IDH.e_sp);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_csum), Description = "Checksum" });
            num += Marshal.SizeOf(IDH.e_csum);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_ip), Description = "Initial IP value" });
            num += Marshal.SizeOf(IDH.e_ip);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_cs), Description = "Initial (relative) CS value" });
            num += Marshal.SizeOf(IDH.e_cs);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_lfarlc), Description = "File address of relocation table" });
            num += Marshal.SizeOf(IDH.e_lfarlc);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_ovno), Description = "Overlay number" });
            num += Marshal.SizeOf(IDH.e_ovno);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X16}", IDH.e_res), Description = "Reserved words" });
            num += Marshal.SizeOf(IDH.e_res);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_oemid), Description = "OEM identifier (for e_oeminfo)" });
            num += Marshal.SizeOf(IDH.e_oemid);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_oeminfo), Description = "OEM information; e_oemid specific" });
            num += Marshal.SizeOf(IDH.e_oeminfo);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X40}", IDH.e_res2), Description = "Reserved words" });
            num += Marshal.SizeOf(IDH.e_res2);
            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X4}", IDH.e_lfanew), Description = "File address of new exe header" });
            num += Marshal.SizeOf(IDH.e_lfanew);
        }

        public void insert_NT32(IMAGE_NT_HEADERS INH)
        {
            int num = global.IDH.e_lfanew;
            List<Data> data = new List<Data>();

            listView.Items.Add(new Data() { Offset = string.Format("{0:X8}", num), Value = string.Format("{0:X8}", INH.Signature), Description = "Signature" });
            num += Marshal.SizeOf(INH.Signature);
        }

        public void insert_NT64(IMAGE_NT_HEADERS64 INH)
        {

        }

        private void OpenFile(object sender, RoutedEventArgs e)
        {
            string path;
            int res;
            List<Data> data = new List<Data>();

            path = Select_File();

            res = Load(path);

            if (res != -1)
            {
                listView.Items.Add(new Data() { Offset = "0x00", Value = "5A4D", Description = "dddddddddddddddddddddddddddddd" });
            }
        }

        public class Data
        {
            public string Offset { get; set; }
            
            public string Value { get; set; }

            public string Description { get; set; }
        }

    }
}