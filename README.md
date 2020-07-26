# Agonyl Packet Sniffer

Requirements
------------
1. WinPcap or NPcap installed with WinPcap compatible API mode.
2. Dot net 4.5

Running the Project
-------------------
1. Build the project using Visual Studio 2019 or download binary from latest release.
2. Update `Config.json` with ports and hosts.

Restrictions
-------------
* Only `x86` platform build works as PcapDotNet library included is x86 version.
* Though HexView library has been included it not possible to view a captured packet yet in the application.
* There is no way to open existing `session.json` file using this application to get the list of packets captured for that session.
