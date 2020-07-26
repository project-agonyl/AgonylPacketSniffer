using PcapDotNet.Packets;
using PcapDotNet.Packets.Transport;

namespace AgonylPacketSniffer
{
    public class A3Packet
    {
        public Packet Packet;
        public TcpDatagram Tcp;
        public bool IsIncoming;
        public ushort Port;
        public int Timestamp;

        public A3Packet(Packet packet, TcpDatagram tcp, bool inc, ushort port)
        {
            this.Packet = packet;
            this.Tcp = tcp;
            this.IsIncoming = inc;
            this.Port = port;
            this.Timestamp = Utils.GetEpochTime();
        }
    }
}
