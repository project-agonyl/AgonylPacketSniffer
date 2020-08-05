using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Newtonsoft.Json;
using PcapDotNet.Core;

namespace AgonylPacketSniffer
{
    public partial class FormMain : Form
    {
        private bool _running;
        private Queue<A3Packet> _packetQueue = new Queue<A3Packet>();
        private PacketCommunicator _communicator;
        private string _sessionName = string.Empty;
        private Crypt _crypt = new Crypt();
        private Queue<A3PacketInfo> _a3Packets = new Queue<A3PacketInfo>();
        private BindingList<A3PacketInfo> _boundA3Packets = new BindingList<A3PacketInfo>();
        private uint _packetsCaptured;
        private ushort[] _packetCapturePorts;
        private ushort[] _loginPorts;
        private ushort[] _zonePorts;

        private delegate void UpdatePacketsCapturedTextDelegate(string text);

        public FormMain()
        {
            InitializeComponent();
        }

        private void FormMain_Load(object sender, EventArgs e)
        {
            if (!File.Exists(Utils.ConfigFile))
            {
                _ = MessageBox.Show("Config.json not found!", "Agonyl Packet Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }

            this._packetCapturePorts = Utils.GetPacketCapturePorts();
            this._loginPorts = Utils.GetLoginPorts();
            this._zonePorts = Utils.GetZonePorts();

            foreach (var device in LivePacketDevice.AllLocalMachine)
            {
                this.deviceList.Items.Add(Utils.GetFriendlyDeviceName(device));
            }

            this.dataGridView.AutoGenerateColumns = false;
            this.dataGridView.DataSource = this._boundA3Packets;
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "Name",
                Name = "Name",
                Width = 150,
            });
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "ServerPort",
                Name = "Port",
                Width = 50,
            });
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "Time",
                Name = "Time",
                Width = 150,
            });
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "DataLength",
                Name = "Length",
                Width = 100,
            });
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "HexProtocol",
                Name = "Protocol",
                Width = 100,
            });
            this.dataGridView.Columns.Add(new DataGridViewTextBoxColumn()
            {
                DataPropertyName = "ServerIPAddress",
                Name = "Server IP",
                Width = 100,
            });
            this.packetProcessBgWorker.RunWorkerAsync();
            var inputFile = Utils.GetFirstInputFileName();
            if (inputFile != string.Empty)
            {
                try
                {
                    foreach (var packet in JsonConvert.DeserializeObject<BindingList<A3PacketInfo>>(File.ReadAllText(inputFile)))
                    {
                        this._boundA3Packets.Add(packet);
                    }
                }
                catch
                {
                    Utils.ShowHexView(inputFile);
                }
            }
        }

        private void startButton_Click(object sender, EventArgs e)
        {
            if (!this._running)
            {
                var selectedIndex = this.deviceList.SelectedIndex;
                if (selectedIndex == -1)
                {
                    _ = MessageBox.Show("Please select a network interface to start sniffing packets!", "Agonyl Packet Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else if (this.packetCaptureBgWorker.IsBusy)
                {
                    _ = MessageBox.Show("Application is busy from previous operation!", "Agonyl Packet Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    this.Text = "Agonyl Packet Sniffer - Capturing";
                    this._packetQueue.Clear();
                    this._a3Packets.Clear();
                    this._boundA3Packets.Clear();
                    this._packetsCaptured = 0;
                    this._running = true;
                    this.startButton.Enabled = false;
                    this.stopButton.Enabled = true;
                    var device = LivePacketDevice.AllLocalMachine[this.deviceList.SelectedIndex];
                    this._communicator = device.Open(65536, PacketDeviceOpenAttributes.None, 500);
                    this._communicator.SetFilter(Utils.BuildPacketCaptureFilter());
                    this._sessionName = "session-" + Utils.GetEpochTime();
                    if (!Directory.Exists(this.GetCurrentSessionDirectory()))
                    {
                        Directory.CreateDirectory(this.GetCurrentSessionDirectory());
                    }

                    this.packetCaptureBgWorker.RunWorkerAsync();
                }
            }
        }

        private void stopButton_Click(object sender, EventArgs e)
        {
            if (this._running)
            {
                this.packetCaptureBgWorker.CancelAsync();
            }
        }

        private void packetCaptureBgWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            var worker = sender as BackgroundWorker;
            while (this._running)
            {
                if (worker.CancellationPending)
                {
                    e.Cancel = true;
                    break;
                }

                var result = this._communicator.ReceivePacket(out var currentPacket);
                if (result == PacketCommunicatorReceiveResult.Timeout)
                {
                    continue;
                }
                else if (result == PacketCommunicatorReceiveResult.BreakLoop)
                {
                    break;
                }

                var ip = currentPacket.Ethernet.IpV4;
                var tcp = ip.Tcp;
                var data = tcp.Payload.ToMemoryStream();
                if (data.Length < 12)
                {
                    // Packet got dropped or invalid
                    continue;
                }

                var isIncoming = false;
                if (this._packetCapturePorts.Contains(tcp.SourcePort))
                {
                    isIncoming = true;
                }

                var port = isIncoming ? tcp.SourcePort : tcp.DestinationPort;
                var shouldEnqueue = true;
                foreach (var enqueuedPacket in this._packetQueue)
                {
                    if (enqueuedPacket.Tcp.SequenceNumber == tcp.SequenceNumber)
                    {
                        // Duplicate packet hence do not enqueue
                        shouldEnqueue = false;
                    }
                }

                if (shouldEnqueue)
                {
                    this._packetQueue.Enqueue(new A3Packet(currentPacket, tcp, isIncoming, port));
                    this._packetsCaptured++;
                    worker.ReportProgress((int)this._packetsCaptured);
                }
            }
        }

        private void packetCaptureBgWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            // Do UI updates if any
        }

        private void packetCaptureBgWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            this._running = false;
            this._communicator.Break();
            this._communicator.Dispose();
            while (this._packetQueue.Count > 0)
            {
            }

            File.WriteAllText(
                    this.GetCurrentSessionDirectory() + Path.DirectorySeparatorChar + "session.apsp",
                    JsonConvert.SerializeObject(this._a3Packets, Formatting.Indented));
            this.dataGridView.RefreshEdit();
            this.dataGridView.Refresh();
            this.stopButton.Enabled = false;
            this.startButton.Enabled = true;
            this.Text = "Agonyl Packet Sniffer - Stopped";
        }

        private void packetProcessBgWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            var worker = sender as BackgroundWorker;
            while (true)
            {
                if (this._packetQueue.Count > 0)
                {
                    var a3packet = this._packetQueue.Dequeue();
                    var ipAddress = a3packet.IsIncoming ? a3packet.Packet.Ethernet.IpV4.Source : a3packet.Packet.Ethernet.IpV4.Destination;
                    var fileName = a3packet.Timestamp.ToString() + "_";
                    var data = a3packet.Tcp.Payload.ToArray();
                    var protocol = Utils.GetPacketProtocol(ref data);
                    var hexProtocol = $"0x{protocol:X}";
                    if (this._loginPorts.Contains(a3packet.Port))
                    {
                        fileName += "LOGIN_";
                        protocol = Convert.ToUInt16(data.Length);
                        hexProtocol = $"0x{protocol:X}";
                    }
                    else
                    {
                        fileName += "ZONE_";
                        if (data.Length != 56)
                        {
                            this._crypt.Decrypt(ref data);
                        }
                    }

                    var packetName = Utils.GetPacketProtocolName(ref data, a3packet.IsIncoming);
                    fileName += packetName + ".a3p";
                    var packetInfo = new A3PacketInfo
                    {
                        Name = packetName,
                        ServerPort = a3packet.Port,
                        Protocol = protocol,
                        DataLength = data.Length,
                        DataFile = this.GetCurrentSessionDirectory() + Path.DirectorySeparatorChar + fileName,
                        Time = a3packet.Packet.Timestamp.ToString(),
                        HexProtocol = hexProtocol,
                        ServerIPAddress = ipAddress.ToString(),
                    };
                    File.WriteAllBytes(packetInfo.DataFile, data);
                    this._a3Packets.Enqueue(packetInfo);
                    worker.ReportProgress(this._a3Packets.Count);
                }
            }
        }

        private void packetProcessBgWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            this._boundA3Packets.Add(this._a3Packets.Dequeue());
        }

        private void dataGridView_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            var dataIndexNo = this.dataGridView.Rows[e.RowIndex].Index;
            if (File.Exists(this._boundA3Packets[dataIndexNo].DataFile))
            {
                Utils.ShowHexView(this._boundA3Packets[dataIndexNo].DataFile);
            }
            else
            {
                _ = MessageBox.Show("Packet file not found!", "Agonyl Packet Sniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void dataGridView_DragEnter(object sender, DragEventArgs e)
        {
            if (!this._running)
            {
                // Check if the Data format of the file(s) can be accepted
                // (we only accept file drops from Windows Explorer, etc.)
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    // modify the drag drop effects to Move
                    e.Effect = DragDropEffects.All;
                }
                else
                {
                    // no need for any drag drop effect
                    e.Effect = DragDropEffects.None;
                }
            }
        }

        private void dataGridView_DragDrop(object sender, DragEventArgs e)
        {
            if (!this._running)
            {
                // still check if the associated data from the file(s) can be used for this purpose
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    // Fetch the file(s) names with full path here to be processed
                    var fileList = (string[])e.Data.GetData(DataFormats.FileDrop);
                    try
                    {
                        // Process the 1st file from the list
                        this._boundA3Packets.Clear();
                        foreach (var packet in JsonConvert.DeserializeObject<BindingList<A3PacketInfo>>(File.ReadAllText(fileList[0])))
                        {
                            this._boundA3Packets.Add(packet);
                        }
                    }
                    catch
                    {
                        Utils.ShowHexView(fileList[0]);
                    }
                }
            }
        }

        private string GetCurrentSessionDirectory()
        {
            return Utils.GetMyDirectory() + Path.DirectorySeparatorChar + this._sessionName;
        }
    }
}
