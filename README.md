# NetworkPacketAnalyzer
C++ class for displaying parsed internet packet headers according to given format and filter strings.

### Disclaimer
This is not production-worthy code! View this simply as a proof-of-concept. Preconditions are implicit. No error checking exists.

### Initialization
```C++
NetworkPacketAnalyzer(char * deviceName, int timeout);
```
The parameters of the only constructor are necessary to initialize a `pcap` connection. The `deviceName` is a string that represents the driver name of the network adapter used. The timeout specifies how long to wait for a response.

### Run
```C++
void Run(int numberOfPackets, char * formatString, char * filterString);
```
When the `Run` method is called, the number of packets to be parsed needs to be specified. If all packets should be collected (i.e. never stop) then this field should be set to `false`. The `formatString` depicts what the output of the `Run` method to the standard output stream. The `filterString` functions in the same way with the same syntax as the `formatString`, however, the results of the parsing will only be displayed if this `filterString` evaluates to `1`.

### Tags
<pre>
{IF:{<b>0/1</b>};}
{EQUALS:{<b>A</b>},{<b>B</b>},...,{<b>N</b>};}
{NOT:{<b>0/1</b>};}
{OR:{<b>0/1</b>},{<b>0/1</b>},...,{<b>0/1</b>};}
{AND:{<b>0/1</b>},{<b>0/1</b>},...,{<b>0/1</b>};}
{ODD:{<b>0/1</b>},{<b>0/1</b>},...,{<b>0/1</b>};}
{XOR:{<b>0/1</b>},{<b>0/1</b>},...,{<b>0/1</b>};}

{LEADING:{<b>CHARACTER</b>},{<b>WIDTH</b>};}
{TRAILING:{<b>CHARACTER</b>},{<b>WIDTH</b>};}

{HOUR}
{MINUTE}
{SECOND}

{ETHERNET}
{ETHERNET_DESTINATION_ADDRESS}
{ETHERNET_SOURCE_ADDRESS}
{ETHERNET_TYPE}

{ARP}
{ARP_HARDWARE_TYPE}
{ARP_PROTOCOL_TYPE}
{ARP_HARDWARE_ADDRESS_LENGTH}
{ARP_PROTOCOL_ADDRESS_LENGTH}
{ARP_OPERATION_CODE}
{ARP_SENDER_MAC_ADDRESS}
{ARP_SENDER_IPV4_ADDRESS}
{ARP_TARGET_MAC_ADDRESS}
{ARP_TARGET_IPV4_ADDRESS}

{IPV4}
{IPV4_VERSIONS}
{IPV4_VERSIONS_VERSION}
{IPV4_VERSIONS_HEADER_LENGTH}
{IPV4_DIFFERENTIATED_SERVICES_FIELD}
{IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP}
{IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT}
{IPV4_DIFFERENTIATED_SERVICES_FIELD_CE}
{IPV4_TOTAL_LENGTH}
{IPV4_IDENTIFICATION}
{IPV4_FRAGMENT_FLAGS}
{IPV4_FRAGMENT_FLAGS_DF}
{IPV4_FRAGMENT_FLAGS_MF}
{IPV4_FRAGMENT_FLAGS_OFFSET}
{IPV4_TIME_TO_LIVE}
{IPV4_NEXT_PROTOCOL}
{IPV4_CHECKSUM}
{IPV4_SOURCE_ADDRESS}
{IPV4_DESTINATION_ADDRESS}

{IPV6}
{IPV6_VERSIONS}
{IPV6_VERSIONS_VERSION}
{IPV6_VERSIONS_DSCP}
{IPV6_VERSIONS_ECT}
{IPV6_VERSIONS_CE}
{IPV6_VERISONS_FLOW_LABEL}
{IPV6_PAYLOAD_LENGTH}
{IPV6_NEXT_PROTOCOL}
{IPV6_HOP_LIMIT}
{IPV6_SOURCE_ADDRESS}
{IPV6_DESTINATION_ADDRESS}

{TCP}
{TCP_SOURCE_PORT}
{TCP_DESTINATION_PORT}
{TCP_PAYLOAD_LENGTH}
{TCP_ACKNOWLEDGEMENT_NUMBER}
{TCP_SEQUENCE_NUMBER}
{TCP_DATA_OFFSET}
{TCP_FLAGS}
{TCP_FLAGS_FIN}
{TCP_FLAGS_SYN}
{TCP_FLAGS_RST}
{TCP_FLAGS_PSH}
{TCP_FLAGS_ACK}
{TCP_FLAGS_URG}
{TCP_FLAGS_ECE}
{TCP_FLAGS_CWR}
{TCP_WINDOW}
{TCP_CHECKSUM}
{TCP_URGENT_POINTER}

{UDP}
{UDP_SOURCE_PORT}
{UDP_DESTINATION_PORT}
{UDP_LENGTH}
{UDP_CHECKSUM}

{CONTENT}
</pre>
Above is a list of all supported tag specifiers. Information on the formating of the specifiers and parameters can be found in the [FormatStringProcessor project](https://github.com/RobertDurfee/FormatStringProcessor).

### Deinitialization
```C++
~NetworkPacketAnalyzer();
```
The tag function and tag arrays are created on the heap and, after the `NetworkPacketAnalyzer` is deconstructed, need to be removed from the heap. Additionally, the `FormatStringProcessor` was created dynamically to provide constructor parameters. Lastly, the `pcap` connection needs to be closed after it is no longer used. All this is completed by the method above.

### Example
```C++
#include "NetworkPacketAnalyzer.h"

int main()
{
	NetworkPacketAnalyzer networkPacketAnalyzer("\\Device\\NPF_{14090526-0B6F-4B14-B801-2AF0CECF917A}", 1000);

	networkPacketAnalyzer.Run(false, "Time: {HOUR{LEADING:{0},{2};}}:{MINUTE{LEADING:{0},{2};}}:{SECOND{LEADING:
	{0},{2};}}\n{IF:{NOT:{EQUALS:{ETHERNET},{0};};};{ETHERNET}}{IF:{NOT:{EQUALS:{ARP},{0};};};{ARP}}{IF:{NOT:
	{EQUALS:{IPV4},{0};};};{IPV4}}{IF:{NOT:{EQUALS:{IPV6},{0};};};{IPV6}}{IF:{NOT:{EQUALS:{TCP},{0};};};{TCP}}
	{IF:{NOT:{EQUALS:{UDP},{0};};};{UDP}}{CONTENT}\n", "1");
	
	return 0;
}
```
Here is an example that outputs each header (for which a parsing function exists) for a collected packet. The headers are only printed if the information exists with a hexadeciaml output of the payload at the end. Since no filtering is required as all information is desired, this field is simply `1`. 

### Output
```
Time: 12:28:15
|-Ethernet:
| |-DestinationAddress: b4-ae-2b-e0-91-5f
| |-SourceAddress: ec-4f-82-11-d8-53
| `-Type: 0x0800
|-IPv4:
| |-Versions: 0x45
| | |-Version: 0x4
| | `-HeaderLength: 0x5
| |-DifferentiatedServicesField: 0x00
| | |-DSCP: 0x00
| | |-ECT: 0x0
| | `-CE: 0x0
| |-TotalLength: 0x0172
| |-Identification: 0x4ef9
| |-FragmentFlags: 0x0000
| | |-DF: 0x0
| | |-MF: 0x0
| | `-Offset: 0x0000
| |-TimeToLive: 0x6f
| |-NextProtocol: 0x06
| |-Checksum: 0xc2bd
| |-SourceAddress: 064.004.054.254
| `-DestinationAddress: 192.168.001.037
|-TCP:
| |-SourcePort: 0x1bb
| |-DestinationPort: 0xf96b
| |-SeqeunceNumber: 0x29a5ed43
| |-AcknowledgementNumber: 0x6cdff1d9
| |-DataOffset: 0x50
| |-Flags: 0x18
| | |-FIN: 0x0
| | |-SYN: 0x0
| | |-RST: 0x0
| | |-PSH: 0x1
| | |-ACK: 0x1
| | |-URG: 0x0
| | |-ECE: 0x0
| | `-CWR: 0x0
| |-Window: 0x0201
| |-Checksum: 0xb0a8
| `-UrgentPointer: 0x0000
|-Content:
| |-0x00000036  17 03 01 00 20 f1 b9 88  de 3f be 84 24 f7 b7 d0  .........?..$...
| |-0x00000046  de 5d 51 b1 03 f1 af eb  e8 03 ef 97 e2 1b df ec  .]Q.............
| |-0x00000056  dc 04 ea 9d fa 17 03 01  01 20 3a 90 7b 62 72 c0  ..........:.{br.
| |-0x00000066  58 95 bd 7e 56 61 17 ae  b9 a4 17 24 d5 db 34 78  X..~Va.....$..4x
| |-0x00000076  54 f2 10 f5 67 a8 a9 95  4d 05 13 a1 f7 67 6f bf  T...g...M....go.
| |-0x00000086  32 9a 0a c5 82 f1 69 43  2b 56 5d 29 b5 93 c8 d1  2.....iC+V])....
| |-0x00000096  28 39 29 0a e2 55 bd 29  84 ed 28 bf 48 a9 8d 83  (9)..U.)..(.H...
| |-0x000000a6  0f 13 0f d7 3c 2f 0b 0d  0f fc f9 8c 14 9f 8a 32  ....</.........2
| |-0x000000b6  6b 62 ac a6 1b b2 44 75  0f dc 97 47 20 bf 1b 9a  kb....Du...G....
| |-0x000000c6  b7 c6 cd f7 97 85 29 11  cb d4 db f9 c5 eb 3e d5  ......).......>.
| |-0x000000d6  e6 32 9a a1 4f 6e 69 30  2b d3 2f ba 22 aa 52 71  .2..Oni0+./.".Rq
| |-0x000000e6  ef 0e 6b d2 8e 30 f7 b1  25 78 2f d7 9a bc 90 9b  ..k..0..%x/.....
| |-0x000000f6  89 16 fc c5 75 8a 08 ab  c7 51 22 13 f1 7a e2 5f  ....u....Q"..z._
| |-0x00000106  91 52 74 2b 28 61 2d 02  58 fd f8 b4 d2 09 40 2a  .Rt+(a-.X.....@*
| |-0x00000116  be 2f c9 dd 15 40 31 9c  98 e0 a1 57 4c 00 5a 08  ./...@1....WL.Z.
| |-0x00000126  d7 ec 8a f4 b1 7a f5 bc  a5 09 50 9e 07 ae 50 96  .....z....P...P.
| |-0x00000136  aa 43 67 53 01 8d 14 c8  80 65 d8 64 39 ef 94 cd  .CgS.....e.d9...
| |-0x00000146  b9 f2 02 7b b5 ac db c4  a4 76 ea 0b 2d ac 93 46  ...{.....v..-..F
| |-0x00000156  1e da d4 85 5d 4f 35 f3  f6 27 51 1a 9b 27 f8 e0  ....]O5..'Q..'..
| |-0x00000166  44 08 a3 23 4f 6a f4 42  fc 3c 35 37 af a6 63 96  D..#Oj.B.<57..c.
| `-0x00000176  d2 6b 35 c3 7f 16 04 d1  9d 93                    .k5.......
`-
```
### Example
```C++
#include "NetworkPacketAnalyzer.h"

#define MY_IP_ADDRESS 192.168.001.037

int main()
{
	NetworkPacketAnalyzer networkPacketAnalyzer("\\Device\\NPF_{14090526-0B6F-4B14-B801-2AF0CECF917A}", 1000);

	networkPacketAnalyzer.Run(false, "| {HOUR{LEADING:{0},{2};}}:{MINUTE{LEADING:{0},{2};}}:{SECOND{LEADING:{0},
	{2};}} | {IF:{EQUALS:{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{IPV4_SOURCE_ADDRESS}}{IF:{EQUALS:
	{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{IPV4_DESTINATION_ADDRESS}}:{IF:{EQUALS:{IPV4_SOURCE_ADDRESS},
	{MY_IP_ADDRESS};};{TCP_SOURCE_PORT{LEADING:{0},{5};}}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},
	{MY_IP_ADDRESS};};{TCP_DESTINATION_PORT{LEADING:{0},{5};}}} {IF:{EQUALS:{IPV4_SOURCE_ADDRESS},
	{MY_IP_ADDRESS};};{-->}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{<--}} {IF:{EQUALS:
	{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{IPV4_DESTINATION_ADDRESS}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},
	{MY_IP_ADDRESS};};{IPV4_SOURCE_ADDRESS}}:{IF:{EQUALS:{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};
	{TCP_DESTINATION_PORT{LEADING:{0},{5};}}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};
	{TCP_SOURCE_PORT{LEADING:{0},{5};}}} | {TCP_PAYLOAD_LENGTH{LEADING:{0},{5};}} | {IF:{EQUALS:
	{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{A}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{S}}
	{IF:{EQUALS:{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{TCP_ACKNOWLEDGEMENT_NUMBER{LEADING:{0},{10};}}}{IF:
	{EQUALS:{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{TCP_SEQUENCE_NUMBER{LEADING:{0},{10};}}} - {IF:
	{EQUALS:{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{TCP_SEQUENCE_NUMBER{LEADING:{0},{10};}}}{IF:{EQUALS:
	{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{TCP_ACKNOWLEDGEMENT_NUMBER{LEADING:{0},{10};}}}{IF:{EQUALS:
	{IPV4_SOURCE_ADDRESS},{MY_IP_ADDRESS};};{S}}{IF:{EQUALS:{IPV4_DESTINATION_ADDRESS},{MY_IP_ADDRESS};};{A}}
	 | {IF:{EQUALS:{TCP_FLAGS_FIN},{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_FIN},{1};};{F}}{IF:{EQUALS:{TCP_FLAGS_SYN},
	{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_SYN},{1};};{S}}{IF:{EQUALS:{TCP_FLAGS_RST},{0};};{-}}{IF:{EQUALS:
	{TCP_FLAGS_RST},{1};};{R}}{IF:{EQUALS:{TCP_FLAGS_PSH},{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_PSH},{1};};{P}}
	{IF:{EQUALS:{TCP_FLAGS_ACK},{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_ACK},{1};};{A}}{IF:{EQUALS:{TCP_FLAGS_URG},
	{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_URG},{1};};{U}}{IF:{EQUALS:{TCP_FLAGS_ECE},{0};};{-}}{IF:{EQUALS:
	{TCP_FLAGS_ECE},{1};};{E}}{IF:{EQUALS:{TCP_FLAGS_CWR},{0};};{-}}{IF:{EQUALS:{TCP_FLAGS_CWR},{1};};{C}}
	 |\n", "{AND:{NOT:{EQUALS:{ETHERNET},{0};};},{NOT:{EQUALS:{IPV4},{0};};},{NOT:{EQUALS:{TCP},{0};};};}");

	return 0;
}
```
This example works in the same way as the previous but the incredibly more complex format and filter strings condenses the information for TCP traffic increasing readability.

### Output
```
| 12:35:45 | 192.168.001.037:63992 --> 104.198.052.053:00080 | 00000 | A0000000000 - 2631563217S | -S------ |
| 12:35:45 | 192.168.001.037:63993 --> 104.198.052.053:00080 | 00000 | A0000000000 - 0712897240S | -S------ |
| 12:35:45 | 192.168.001.037:63994 --> 104.198.052.053:00080 | 00000 | A0000000000 - 0460232259S | -S------ |
| 12:35:45 | 192.168.001.037:63995 --> 104.198.052.053:00080 | 00000 | A0000000000 - 0888852985S | -S------ |
| 12:35:45 | 192.168.001.037:63996 --> 104.198.052.053:00080 | 00000 | A0000000000 - 3855152499S | -S------ |
| 12:35:45 | 192.168.001.037:63997 --> 104.198.052.053:00080 | 00000 | A0000000000 - 4179721005S | -S------ |
| 12:35:45 | 192.168.001.037:63993 <-- 104.198.052.053:00080 | 00000 | S0308831719 - 0712897241A | -S--A--- |
| 12:35:45 | 192.168.001.037:63995 <-- 104.198.052.053:00080 | 00000 | S3457599476 - 0888852986A | -S--A--- |
| 12:35:45 | 192.168.001.037:63994 <-- 104.198.052.053:00080 | 00000 | S1464946427 - 0460232260A | -S--A--- |
| 12:35:45 | 192.168.001.037:63996 <-- 104.198.052.053:00080 | 00000 | S0072066264 - 3855152500A | -S--A--- |
| 12:35:45 | 192.168.001.037:63993 --> 104.198.052.053:00080 | 00000 | A0308831720 - 0712897241S | ----A--- |
| 12:35:45 | 192.168.001.037:63995 --> 104.198.052.053:00080 | 00000 | A3457599477 - 0888852986S | ----A--- |
| 12:35:45 | 192.168.001.037:63994 --> 104.198.052.053:00080 | 00000 | A1464946428 - 0460232260S | ----A--- |
| 12:35:45 | 192.168.001.037:63996 --> 104.198.052.053:00080 | 00000 | A0072066265 - 3855152500S | ----A--- |
| 12:35:45 | 192.168.001.037:63992 <-- 104.198.052.053:00080 | 00000 | S0585466802 - 2631563218A | -S--A--- |
| 12:35:45 | 192.168.001.037:63992 --> 104.198.052.053:00080 | 00000 | A0585466803 - 2631563218S | ----A--- |
| 12:35:45 | 192.168.001.037:63997 <-- 104.198.052.053:00080 | 00000 | S0564015420 - 4179721006A | -S--A--- |
| 12:35:45 | 192.168.001.037:63997 --> 104.198.052.053:00080 | 00000 | A0564015421 - 4179721006S | ----A--- |
| 12:35:45 | 192.168.001.037:63992 --> 104.198.052.053:00080 | 00383 | A0585466803 - 2631563218S | ---PA--- |
| 12:35:45 | 192.168.001.037:63992 <-- 104.198.052.053:00080 | 00000 | S0585466803 - 2631563601A | ----A--- |
| 12:35:45 | 192.168.001.037:63992 <-- 104.198.052.053:00080 | 01420 | S0585466803 - 2631563601A | ----A--- |
| 12:35:46 | 192.168.001.037:63992 <-- 104.198.052.053:00080 | 01420 | S0585468223 - 2631563601A | ----A--- |
| 12:37:46 | 192.168.001.037:63992 <-- 104.198.052.053:00080 | 00000 | S0585480577 - 2631564311A | F---A--- |
| 12:37:46 | 192.168.001.037:63992 --> 104.198.052.053:00080 | 00000 | A0585480578 - 2631564311S | ----A--- |
| 12:37:46 | 192.168.001.037:63996 <-- 104.198.052.053:00080 | 00000 | S0072068651 - 3855153216A | F---A--- |
| 12:37:46 | 192.168.001.037:63996 --> 104.198.052.053:00080 | 00000 | A0072068652 - 3855153216S | ----A--- |
| 12:37:46 | 192.168.001.037:63995 <-- 104.198.052.053:00080 | 00000 | S3457613538 - 0888854109A | F---A--- |
| 12:37:46 | 192.168.001.037:63995 --> 104.198.052.053:00080 | 00000 | A3457613539 - 0888854109S | ----A--- |
| 12:37:46 | 192.168.001.037:63997 <-- 104.198.052.053:00080 | 00000 | S0564055901 - 4179721755A | F---A--- |
| 12:37:46 | 192.168.001.037:63997 --> 104.198.052.053:00080 | 00000 | A0564055902 - 4179721755S | ----A--- |
| 12:37:46 | 192.168.001.037:63994 <-- 104.198.052.053:00080 | 00000 | S1464951747 - 0460233362A | F---A--- |
| 12:37:46 | 192.168.001.037:63994 --> 104.198.052.053:00080 | 00000 | A1464951748 - 0460233362S | ----A--- |
| 12:37:46 | 192.168.001.037:63993 <-- 104.198.052.053:00080 | 00000 | S0308861845 - 0712899852A | F---A--- |
| 12:37:46 | 192.168.001.037:63993 --> 104.198.052.053:00080 | 00000 | A0308861846 - 0712899852S | ----A--- |
```
The incredibily different outputs demonstrate just how flexible this class can be. However, the format strings can quickly become complex.
