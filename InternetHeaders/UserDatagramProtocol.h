#ifndef USER_DATAGRAM_PROTOCOL_HEADER
#define USER_DATAGRAM_PROTOCOL_HEADER

#include "InternetTypes.h"     //word
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndianWord()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define UDP_HEADER_SIZE 8

class UDPHeader
{
public:
	UDPHeader();
	UDPHeader(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

#define UDP_FTP_DATA_PORT 20
#define UDP_FTP_CONTROL_PORT 21
#define UDP_SSH_PORT 22
#define UDP_TELNET_PORT 23
#define UDP_SMTP_PORT 25
#define UDP_DNS_PORT 53
#define UDP_BOOTPS_PORT 67
#define UDP_BOOTPC_PORT 68
#define UDP_HTTP_PORT 80
#define UDP_POP3_PORT 110
#define UDP_NNTP_PORT 119
#define UDP_NTP_PORT 123
#define UDP_NETBIOS_NS_PORT 137
#define UDP_NETBIOS_DGM_PORT 138
#define UDP_NETBIOS_SSN_PORT 139
#define UDP_IMAP4_PORT 143
#define UDP_SNMP_PORT 161
#define UDP_IRC_PORT 194
#define UDP_HTTPS_PORT 443
#define UDP_MICROSOFT_DS_PORT 445
#define UDP_SMTPS_PORT 465
#define UDP_IMAPS_PORT 993
#define UDP_IRCS_PORT 994
#define UDP_POP3S_PORT 995
	word SourcePort;
	word DestinationPort;
	word Length;
	word Checksum;
};

UDPHeader::UDPHeader()
{
	Clear();
}
UDPHeader::UDPHeader(void * location)
{
	Assign(location);
}
void UDPHeader::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding.
	SourcePort = Select<word>(location, &index);
	DestinationPort = Select<word>(location, &index);
	Length = Select<word>(location, &index);
	Checksum = Select<word>(location, &index);

	SwitchEndianness();
}
void UDPHeader::Clear()
{
	//memset() can be used as padding can be zero
	memset(this, 0, sizeof(UDPHeader));
}
void UDPHeader::SwitchEndianness()
{
	SwitchEndianWord(&SourcePort);
	SwitchEndianWord(&DestinationPort);
	SwitchEndianWord(&Length);
	SwitchEndianWord(&Checksum);
}
char * UDPHeader::ToString()
{
	char * output = (char *)malloc(99 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-UDP:\n");
	sprintfi(output, &index, "| |-SourcePort: 0x%02x\n", SourcePort);
	sprintfi(output, &index, "| |-DestinationPort: 0x%02x\n", DestinationPort);
	sprintfi(output, &index, "| |-Length: 0x%02x\n", Length);
	sprintfi(output, &index, "| `-Checksum: 0x%02x\n", Checksum);

	return output;
}

#endif