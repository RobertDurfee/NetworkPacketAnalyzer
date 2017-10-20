#include "NetworkPacketAnalyzer.h"

int main()
{
    char ErrorBuffer[PCAP_ERRBUF_SIZE];

    char * DeviceName = pcap_lookupdev(ErrorBuffer);

    NetworkPacketAnalyzer networkPacketAnalyzer(DeviceName, 1000);

    networkPacketAnalyzer.Run(false, "Time: {HOUR{LEADING:{0},{2};}}:{MINUTE{LEADING:{0},{2};}}:{SECOND{LEADING:{0},{2};}}\n{IF:{NOT:{EQUALS:{ETHERNET},{0};};};{ETHERNET}}{IF:{NOT:{EQUALS:{ARP},{0};};};{ARP}}{IF:{NOT:{EQUALS:{IPV4},{0};};};{IPV4}}{IF:{NOT:{EQUALS:{IPV6},{0};};};{IPV6}}{IF:{NOT:{EQUALS:{TCP},{0};};};{TCP}}{IF:{NOT:{EQUALS:{UDP},{0};};};{UDP}}{CONTENT}\n", "1");

    return 0;
}
