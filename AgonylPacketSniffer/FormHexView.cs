using System;
using System.IO;
using System.Windows.Forms;
using Be.Windows.Forms;

namespace AgonylPacketSniffer
{
    public partial class FormHexView : Form
    {
        public string DataFile { get; set; }

        public FormHexView()
        {
            InitializeComponent();
        }

        private void FormHexView_Load(object sender, System.EventArgs e)
        {
            try
            {
                if (File.Exists(this.DataFile))
                {
                    this.Text = "Viewing - " + Path.GetFileName(this.DataFile);
                    this.hexBox.ByteProvider = new DynamicByteProvider(File.ReadAllBytes(this.DataFile));
                }
            }
            catch { }
        }

        private void hexBox_Copied(object sender, EventArgs e)
        {
            this.hexBox.CopyHex();
        }
    }
}
