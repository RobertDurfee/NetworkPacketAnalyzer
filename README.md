# NetworkPacketAnalyzer
C++ class for displaying parsed internet packet headers according to a given format string.

### Disclaimer
This is not production-worthy code! View this simply as a proof-of-concept.

### Initialization
```C++
NetworkPacketAnalyzer(char * deviceName, int timeout);
```

### Run
```C++
void Run(int numberOfPackets, char * formatString, char * filterString);
```

### Deinitialization
```C++
~NetworkPacketAnalyzer();
```

### Example
```C++
#include "NetworkPacketAnalyzer.h"

int main()
{
	NetworkPacketAnalyzer networkPacketAnalyzer("\\Device\\NPF_{14090526-0B6F-4B14-B801-2AF0CECF917A}", 1000);

	networkPacketAnalyzer.Run(false, "Time: {HOUR{LEADING:{0},{2};}}:{MINUTE{LEADING:{0},{2};}}:{SECOND{LEADING:{0},{2};}}\n{IF:{NOT:{EQUALS:{ETHERNET},{0};};};{ETHERNET}}{IF:{NOT:{EQUALS:{ARP},{0};};};{ARP}}{IF:{NOT:{EQUALS:{IPV4},{0};};};{IPV4}}{IF:{NOT:{EQUALS:{IPV6},{0};};};{IPV6}}{IF:{NOT:{EQUALS:{TCP},{0};};};{TCP}}{IF:{NOT:{EQUALS:{UDP},{0};};};{UDP}}{CONTENT}\n", "1");
	
	return 0;
}
```
