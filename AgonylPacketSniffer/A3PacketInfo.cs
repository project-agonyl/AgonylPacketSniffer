namespace AgonylPacketSniffer
{
    public class A3PacketInfo
    {
        public string Time { get; set; }

        public ushort ServerPort { get; set; }

        public string Name { get; set; }

        public int DataLength { get; set; }

        public string DataFile { get; set; }

        public ushort Protocol { get; set; }

        public string HexProtocol { get; set; }

        public string ServerIPAddress { get; set; }
    }
}
