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

            if (config.Login.Length != 0 || config.Zone.Length != 0)
            {
                filter += " and (";
                var ports = new List<string>();
                for (var i = 0; i < config.Login.Length; i++)
                {
                    ports.Add("port " + config.Login[i]);
                }

                for (var i = 0; i < config.Zone.Length; i++)
                {
                    ports.Add("port " + config.Zone[i]);
                }

                filter += string.Join(" or ", ports) + ")";
            }

            return filter;
        }

        public static ushort[] GetPacketCapturePorts()
        {
            var config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigFile));
            var ports = new List<ushort>();
            for (var i = 0; i < config.Login.Length; i++)
            {
                ports.Add(config.Login[i]);
            }

            for (var i = 0; i < config.Zone.Length; i++)
            {
                ports.Add(config.Zone[i]);
            }

            return ports.ToArray();
        }

        public static ushort[] GetLoginPorts()
        {
            return JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigFile)).Login;
        }

        public static ushort[] GetZonePorts()
        {
            return JsonConvert.DeserializeObject<Config>(File.ReadAllText(ConfigFile)).Zone;
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

        public static string GetPacketProtocolName(ref byte[] buffer, bool isIncoming)
        {
            var opCode = isIncoming ? "S2C_" : "C2S_";
            switch (buffer[11])
            {
                case 0x0F:
                    switch (buffer[10])
                    {
                        case 0xF2:
                            opCode += "KEEP_ALIVE";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x11:
                    switch (buffer[10])
                    {
                        case 0x05:
                            opCode += "CHAR_LIST";
                            break;

                        case 0x06:
                            opCode += "CHAR_LOGIN";
                            break;

                        case 0x07:
                            opCode += "WORLD_LOGIN";
                            break;

                        case 0x08:
                            opCode += "CHAR_LOGOUT";
                            break;

                        case 0x11:
                            opCode += "WARP";
                            break;

                        case 0x12:
                            opCode += "RETURN2HERE";
                            break;

                        case 0x14:
                            opCode += "SUBMAP_INFO";
                            break;

                        case 0x15:
                            opCode += "ENTER";
                            break;

                        case 0xA1:
                            opCode += "ACTIVE_PET";
                            break;

                        case 0xA2:
                            opCode += "INACTIVE_PET";
                            break;

                        case 0xA5:
                            opCode += "PET_BUY";
                            break;

                        case 0xA6:
                            opCode += "PET_SELL";
                            break;

                        case 0xA7:
                            opCode += "FEED_PET";
                            break;

                        case 0xA8:
                            opCode += "REVIVE_PET";
                            break;

                        case 0xB0:
                            opCode += "SHUE_COMBINATION";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x12:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "ASK_MOVE";
                            break;

                        case 0x02:
                            opCode += "PC_MOVE";
                            break;

                        case 0x05:
                            opCode += "ASK_HS_MOVE";
                            break;

                        case 0x08:
                            opCode += "HS_MOVE";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x13:
                    switch (buffer[10])
                    {
                        case 0x07:
                            opCode += "OBJECT_NPC";
                            break;

                        case 0x08:
                            opCode += "ASK_NPC_FAVOR";
                            break;

                        case 0x09:
                            opCode += "NPC_FAVOR_UP";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x14:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "ASK_ATTACK";
                            break;

                        case 0x51:
                            opCode += "LEARN_SKILL";
                            break;

                        case 0x53:
                            opCode += "ASK_SKILL";
                            break;

                        case 0x61:
                            opCode += "SKILL_SLOT_INFO";
                            break;

                        case 0x62:
                            opCode += "ANS_RECALL";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x16:
                    switch (buffer[10])
                    {
                        case 0x02:
                            opCode += "ALLOT_POINT";
                            break;

                        case 0x06:
                            opCode += "ASK_HEAL";
                            break;

                        case 0x09:
                            opCode += "RETRIEVE_POINT";
                            break;

                        case 0x0C:
                            opCode += "RESTORE_EXP";
                            break;

                        case 0x11:
                            opCode += "LEARN_PSKILL";
                            break;

                        case 0x13:
                            opCode += "FORGET_ALL_PSKILL";
                            break;

                        case 0x51:
                            opCode += "ASK_OPEN_STORAGE";
                            break;

                        case 0x52:
                            opCode += "ASK_INVEN2STORAGE";
                            break;

                        case 0x53:
                            opCode += "ASK_STORAGE2INVEN";
                            break;

                        case 0x54:
                            opCode += "ASK_DEPOSITE_MONEY";
                            break;

                        case 0x55:
                            opCode += "ASK_WITHDRAW_MONEY";
                            break;

                        case 0x56:
                            opCode += "ASK_CLOSE_STORAGE";
                            break;

                        case 0x57:
                            opCode += "ASK_MOVE_ITEMINSTORAGE";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x17:
                    switch (buffer[10])
                    {
                        case 0x02:
                            opCode += "PICKUP_ITEM";
                            break;

                        case 0x04:
                            opCode += "DROP_ITEM";
                            break;

                        case 0x06:
                            opCode += "MOVE_ITEM";
                            break;

                        case 0x08:
                            opCode += "WEAR_ITEM";
                            break;

                        case 0x11:
                            opCode += "STRIP_ITEM";
                            break;

                        case 0x14:
                            opCode += "BUY_ITEM";
                            break;

                        case 0x16:
                            opCode += "SELL_ITEM";
                            break;

                        case 0x18:
                            opCode += "GIVE_ITEM";
                            break;

                        case 0x21:
                            opCode += "USE_POTION";
                            break;

                        case 0x23:
                            opCode += "ASK_DEAL";
                            break;

                        case 0x25:
                            opCode += "ANS_DEAL";
                            break;

                        case 0x27:
                            opCode += "PUTIN_ITEM";
                            break;

                        case 0x29:
                            opCode += "PUTOUT_ITEM";
                            break;

                        case 0x31:
                            opCode += "DECIDE_DEAL";
                            break;

                        case 0x33:
                            opCode += "CONFIRM_DEAL";
                            break;

                        case 0x36:
                            opCode += "USE_ITEM";
                            break;

                        case 0x42:
                            opCode += "CONFIRM_ITEM";
                            break;

                        case 0x44:
                            opCode += "REMODEL_ITEM";
                            break;

                        case 0x48:
                            opCode += "USESCROLL";
                            break;

                        case 0x50:
                            opCode += "PUTIN_PET";
                            break;

                        case 0x51:
                            opCode += "PUTOUT_PET";
                            break;

                        case 0x53:
                            opCode += "ITEM_COMBINATION";
                            break;

                        case 0x54:
                            opCode += "LOTTO_PURCHASE";
                            break;

                        case 0x55:
                            opCode += "LOTTO_QUERY_PRIZE";
                            break;

                        case 0x56:
                            opCode += "LOTTO_QUERY_HISTORY";
                            break;

                        case 0x57:
                            opCode += "LOTTO_SALE";
                            break;

                        case 0x60:
                            opCode += "TAKEITEM_IN_BOX";
                            break;

                        case 0x61:
                            opCode += "TAKEITEM_OUT_BOX";
                            break;

                        case 0x67:
                            opCode += "USE_POTION_EX";
                            break;

                        case 0x70:
                            opCode += "OPEN_MARKET";
                            break;

                        case 0x71:
                            opCode += "CLOSE_MARKET";
                            break;

                        case 0x73:
                            opCode += "ENTER_MARKET";
                            break;

                        case 0x75:
                            opCode += "BUYITEM_MARKET";
                            break;

                        case 0x76:
                            opCode += "LEAVE_MARKET";
                            break;

                        case 0x77:
                            opCode += "MODIFY_MARKET";
                            break;

                        case 0x80:
                            opCode += "ASK_ITEM_SERIAL";
                            break;

                        case 0x81:
                            opCode += "SOCKET_ITEM";
                            break;

                        case 0x85:
                            opCode += "BUY_BATTLEFIELD_ITEM";
                            break;

                        case 0x90:
                            opCode += "BUY_CASH_ITEM";
                            break;

                        case 0x91:
                            opCode += "CASH_INFO";
                            break;

                        case 0xA9:
                            opCode += "DERBY_INDEX_QUERY";
                            break;

                        case 0xAA:
                            opCode += "DERBY_MONSTER_QUERY";
                            break;

                        case 0xAB:
                            opCode += "DERBY_RATIO_QUERY";
                            break;

                        case 0xAC:
                            opCode += "DERBY_PURCHASE";
                            break;

                        case 0xAE:
                            opCode += "DERBY_RESULT_QUERY";
                            break;

                        case 0xAF:
                            opCode += "DERBY_HISTORY_QUERY";
                            break;

                        case 0xB0:
                            opCode += "DERBY_EXCHANGE";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x18:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "SAY";
                            break;

                        case 0x01:
                            opCode += "GESTURE";
                            break;

                        case 0x03:
                            opCode += "CHAT_WINDOW_OPT";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x19:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "OPTION";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x21:
                    switch (buffer[10])
                    {
                        case 0x10:
                            opCode += "PARTY_QUEST";
                            break;

                        case 0x20:
                            opCode += "QUESTEX_DIALOGUE_REQ";
                            break;

                        case 0x22:
                            opCode += "QUESTEX_DIALOGUE_ANS";
                            break;

                        case 0x26:
                            opCode += "QUESTEX_CANCEL";
                            break;

                        case 0x28:
                            opCode += "QUESTEX_LIST";
                            break;

                        case 0x40:
                            opCode += "SQUEST_START";
                            break;

                        case 0x44:
                            opCode += "SQUEST_STEP_END";
                            break;

                        case 0x45:
                            opCode += "SQUEST_HISTORY";
                            break;

                        case 0x49:
                            opCode += "SQUEST_MINIGAME_MOVE";
                            break;

                        case 0x4A:
                            opCode += "SQUEST_WALL_QUIZ";
                            break;

                        case 0x4C:
                            opCode += "SQUEST_WALL_OK";
                            break;

                        case 0x4E:
                            opCode += "SQUEST_A3_QUIZ_SELECT";
                            break;

                        case 0x4F:
                            opCode += "SQUEST_A3_QUIZ";
                            break;

                        case 0x51:
                            opCode += "SQUEST_A3_QUIZ_OK";
                            break;

                        case 0x52:
                            opCode += "SQUEST_END_OK";
                            break;

                        case 0x53:
                            opCode += "SQUEST_222_NUM_QUIZ";
                            break;

                        case 0x55:
                            opCode += "SQUEST_312_ITEM_CREATE";
                            break;

                        case 0x57:
                            opCode += "SQUEST_HBOY_RUNE";
                            break;

                        case 0x59:
                            opCode += "SQUEST_HBOY_HANOI";
                            break;

                        case 0x5E:
                            opCode += "SQUEST_346_ITEM_COMBI";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x22:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "ASK_PARTY";
                            break;

                        case 0x02:
                            opCode += "ANS_PARTY";
                            break;

                        case 0x05:
                            opCode += "OUT_PARTY";
                            break;

                        case 0xA0:
                            opCode += "ASK_APPRENTICE_IN";
                            break;

                        case 0xA1:
                            opCode += "ANS_APPRENTICE_IN";
                            break;

                        case 0xA4:
                            opCode += "ASK_APPRENTICE_OUT";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x23:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "CLAN";
                            break;

                        case 0x01:
                            opCode += "JOIN_CLAN";
                            break;

                        case 0x02:
                            opCode += "ANS_CLAN";
                            break;

                        case 0x03:
                            opCode += "BOLT_CLAN";
                            break;

                        case 0x04:
                            opCode += "REQ_CLAN_INFO";
                            break;

                        case 0x20:
                            opCode += "C2Z_REGISTER_MARK";
                            break;

                        case 0x22:
                            opCode += "TRANSFER_MARK";
                            break;

                        case 0x23:
                            opCode += "ASK_MARK";
                            break;

                        case 0x31:
                            opCode += "FRIEND_INFO";
                            break;

                        case 0x32:
                            opCode += "FRIEND_STATE";
                            break;

                        case 0x33:
                            opCode += "FRIEND_GROUP";
                            break;

                        case 0x34:
                            opCode += "ASK_FRIEND";
                            break;

                        case 0x35:
                            opCode += "ANS_FRIEND";
                            break;

                        case 0x40:
                            opCode += "ASK_CLAN_BATTLE";
                            break;

                        case 0x41:
                            opCode += "ANS_CLAN_BATTLE";
                            break;

                        case 0x42:
                            opCode += "ASK_CLAN_BATTLE_END";
                            break;

                        case 0x43:
                            opCode += "ANS_CLAN_BATTLE_END";
                            break;

                        case 0x45:
                            opCode += "ASK_CLAN_BATTLE_SCORE";
                            break;

                        case 0x50:
                            opCode += "LETTER_BASE_INFO";
                            break;

                        case 0x51:
                            opCode += "LETTER_SIMPLE_INFO";
                            break;

                        case 0x53:
                            opCode += "LETTER_DEL";
                            break;

                        case 0x54:
                            opCode += "LETTER_SEND";
                            break;

                        case 0x56:
                            opCode += "LETTER_KEEPING";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x24:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "CHANGE_NATION";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x25:
                    switch (buffer[10])
                    {
                        case 0x10:
                            opCode += "CAO_MITIGATION";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x26:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "AGIT_INFO";
                            break;

                        case 0x01:
                            opCode += "AUCTION_INFO";
                            break;

                        case 0x02:
                            opCode += "AGIT_ENTER";
                            break;

                        case 0x03:
                            opCode += "AGIT_PUTUP_AUCTION";
                            break;

                        case 0x04:
                            opCode += "AGIT_BIDON";
                            break;

                        case 0x05:
                            opCode += "AGIT_PAY_EXPENSE";
                            break;

                        case 0x06:
                            opCode += "AGIT_CHANGE_NAME";
                            break;

                        case 0x07:
                            opCode += "AGIT_REPAY_MONEY";
                            break;

                        case 0x08:
                            opCode += "AGIT_OBTAIN_SALEMONEY";
                            break;

                        case 0x0A:
                            opCode += "AGIT_MANAGE_INFO";
                            break;

                        case 0x0B:
                            opCode += "AGIT_OPTION";
                            break;

                        case 0x0C:
                            opCode += "AGIT_OPTION_INFO";
                            break;

                        case 0x0D:
                            opCode += "AGIT_PC_BAN";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x27:
                    switch (buffer[10])
                    {
                        case 0x30:
                            opCode += "CHRISTMAS_CARD";
                            break;

                        case 0x31:
                            opCode += "SPEAK_CARD";
                            break;

                        case 0x40:
                            opCode += "PROCESS_INFO";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x28:
                    switch (buffer[10])
                    {
                        case 0x95:
                            opCode += "PREPARE_USER";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x35:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "ASK_WARP_Z2B";
                            break;

                        case 0x10:
                            opCode += "ASK_WARP_B2Z";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x38:
                    switch (buffer[10])
                    {
                        case 0x11:
                            opCode += "PREPARE_USER";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x39:
                    switch (buffer[10])
                    {
                        case 0x15:
                            opCode += "ASK_SHOP_INFO";
                            break;

                        case 0x16:
                            opCode += "ASK_GIVE_MY_TAX";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x40:
                    switch (buffer[10])
                    {
                        case 0x01:
                            opCode += "TYR_UNIT_LIST";
                            break;

                        case 0x02:
                            opCode += "TYR_UNIT_INFO";
                            break;

                        case 0x03:
                            opCode += "TYR_ENTRY";
                            break;

                        case 0x04:
                            opCode += "TYR_JOIN";
                            break;

                        case 0x80:
                            opCode += "TYR_REWARD_INFO";
                            break;

                        case 0x81:
                            opCode += "TYR_REWARD";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x41:
                    switch (buffer[10])
                    {
                        case 0x02:
                            opCode += "TYR_UPGRADE";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x42:
                    switch (buffer[10])
                    {
                        case 0x03:
                            opCode += "TYR_RTMM_END";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x50:
                    switch (buffer[10])
                    {
                        case 0x01:
                            opCode += "HS_SEAL";
                            break;

                        case 0x02:
                            opCode += "HS_RECALL";
                            break;

                        case 0x05:
                            opCode += "HS_REVIVE";
                            break;

                        case 0x06:
                            opCode += "HS_ASK_ATTACK";
                            break;

                        case 0x08:
                            opCode += "HSSTONE_BUY";
                            break;

                        case 0x09:
                            opCode += "HSSTONE_SELL";
                            break;

                        case 0x0A:
                            opCode += "HS_LEARN_SKILL";
                            break;

                        case 0x0B:
                            opCode += "HS_ALLOT_POINT";
                            break;

                        case 0x0C:
                            opCode += "HS_RETRIEVE_POINT";
                            break;

                        case 0x0D:
                            opCode += "HS_WEAR_ITEM";
                            break;

                        case 0x10:
                            opCode += "HS_STRIP_ITEM";
                            break;

                        case 0x1B:
                            opCode += "HS_OPTION";
                            break;

                        case 0x1C:
                            opCode += "HS_HEAL";
                            break;

                        case 0x1E:
                            opCode += "HS_SKILL_RESET";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0x90:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "ASK_MIGRATION";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0xA0:
                    switch (buffer[10])
                    {
                        case 0x01:
                            opCode += "ASK_CREATE_PLAYER";
                            break;

                        case 0x02:
                            opCode += "ASK_DELETE_PLAYER";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0xA3:
                    switch (buffer[10])
                    {
                        case 0x40:
                            opCode += "LEAGUE";
                            break;

                        case 0x45:
                            opCode += "REQ_LEAGUE_CLAN_INFO";
                            break;

                        case 0x47:
                            opCode += "LEAGUE_ALLOW";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                case 0xC0:
                    switch (buffer[10])
                    {
                        case 0x00:
                            opCode += "PAYINFO";
                            break;

                        default:
                            opCode += "UNKNOWN_PROTOCOL";
                            break;
                    }

                    break;

                default:

                    if (buffer.Length == 22)
                    {
                        opCode += "PING";
                    }
                    else
                    {
                        opCode += "UNKNOWN_PROTOCOL";
                    }

                    break;
            }

            return opCode;
        }
    }
}
