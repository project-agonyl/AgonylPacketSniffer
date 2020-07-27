using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using Newtonsoft.Json;
using PcapDotNet.Core;

namespace AgonylPacketSniffer
{
    public static class Utils
    {
        public static string ConfigFile = Utils.GetMyDirectory() + Path.DirectorySeparatorChar + "Config.json";

        public static string GetFriendlyDeviceName(PacketDevice device)
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (device.Name.EndsWith(networkInterface.Id))
                {
                    return networkInterface.Name;
                }
            }

            return device.Name;
        }

        public static string GetMyDirectory()
        {
            return Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
        }

        public static string BuildPacketCaptureFilter()
        {
            var config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigFile));
            var filter = string.Empty;

            if (config.Hosts.Length == 0)
            {
                filter += "ip";
            }
            else
            {
                filter += "(";
                for (var i = 0; i < config.Hosts.Length; i++)
                {
                    config.Hosts[i] = "ip host " + config.Hosts[i];
                }

                filter += string.Join(" or ", config.Hosts) + ")";
            }

            filter += " and tcp";

            if (config.Ports.Length != 0)
            {
                filter += " and (";
                var ports = new List<string>();
                for (var i = 0; i < config.Ports.Length; i++)
                {
                    ports.Add("port " + config.Ports[i]);
                }

                filter += string.Join(" or ", ports) + ")";
            }

            return filter;
        }

        public static ushort[] GetPacketCapturePorts()
        {
            return JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigFile)).Ports;
        }

        public static int GetEpochTime()
        {
            var t = DateTime.Now - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }

        public static ushort GetPacketProtocol(ref byte[] packet)
        {
            return BitConverter.ToUInt16(packet.Skip(10).Take(2).ToArray(), 0);
        }

        public static string GetFirstInputFileName()
        {
            var args = Environment.GetCommandLineArgs();
            var inputFile = string.Empty;
            for (var i = 0; i <= args.Length - 1; i++)
            {
                if (!args[i].EndsWith(".exe"))
                {
                    inputFile = args[i];
                    break;
                }
            }

            return inputFile;
        }

        public static void ShowHexView(string fileName)
        {
            var hexView = new FormHexView();
            hexView.DataFile = fileName;
            hexView.Show();
        }
    }
}
