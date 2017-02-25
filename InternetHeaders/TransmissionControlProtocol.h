#ifndef TRANSMISSION_CONTROL_PROTOCOL_HEADER
#define TRANSMISSION_CONTROL_PROTOCOL_HEADER

#include "InternetTypes.h"     //byte, word, dword
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndianWord(), SwitchEndianDword()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define TCP_HEADER_SIZE 20

class TCPHeader
{
public:
	TCPHeader();
	TCPHeader(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

#define TCP_FTP_DATA_PORT 20
#define TCP_FTP_CONTROL_PORT 21
#define TCP_SSH_PORT 22
#define TCP_TELNET_PORT 23
#define TCP_SMTP_PORT 25
#define TCP_DNS_PORT 53
#define TCP_BOOTPS_PORT 67
#define TCP_BOOTPC_PORT 68
#define TCP_HTTP_PORT 80
#define TCP_POP3_PORT 110
#define TCP_NNTP_PORT 119
#define TCP_NTP_PORT 123
#define TCP_NETBIOS_NS_PORT 137
#define TCP_NETBIOS_DGM_PORT 138
#define TCP_NETBIOS_SSN_PORT 139
#define TCP_IMAP4_PORT 143
#define TCP_SNMP_PORT 161
#define TCP_IRC_PORT 194
#define TCP_HTTPS_PORT 443
#define TCP_MICROSOFT_DS_PORT 445
#define TCP_SMTPS_PORT 465
#define TCP_IMAPS_PORT 993
#define TCP_IRCS_PORT 994
#define TCP_POP3S_PORT 995
	word SourcePort;
	word DestinationPort;
	dword SequenceNumber;
	dword AcknowledgementNumber;
	byte DataOffset;
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
	byte Flags;
		byte FIN;
		byte SYN;
		byte RST;
		byte PSH;
		byte ACK;
		byte URG;
		byte ECE;
		byte CWR;
	word Window;
	word Checksum;
	word UrgentPointer;
};

TCPHeader::TCPHeader()
{
	Clear();
}
TCPHeader::TCPHeader(void * location)
{
	Assign(location);
}
void TCPHeader::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding.
	SourcePort = Select<word>(location, &index);
	DestinationPort = Select<word>(location, &index);
	SequenceNumber = Select<dword>(location, &index);
	AcknowledgementNumber = Select<dword>(location, &index);
	DataOffset = Select<byte>(location, &index);
	Flags = Select<byte>(location, &index);
	Window = Select<word>(location, &index);
	Checksum = Select<word>(location, &index);
	UrgentPointer = Select<word>(location, &index);

	SwitchEndianness();
	
	FIN = Flags & 0x1;
	SYN = (Flags >> 1) & 0x1;
	RST = (Flags >> 2) & 0x1;
	PSH = (Flags >> 3) & 0x1;
	ACK = (Flags >> 4) & 0x1;
	URG = (Flags >> 5) & 0x1;
	ECE = (Flags >> 6) & 0x1;
	CWR = (Flags >> 7) & 0x1;
}
void TCPHeader::Clear()
{
	memset(this, 0, sizeof(TCPHeader));
}
void TCPHeader::SwitchEndianness()
{
	SwitchEndianWord(&SourcePort);
	SwitchEndianWord(&DestinationPort);
	SwitchEndianDword(&SequenceNumber);
	SwitchEndianDword(&AcknowledgementNumber);
	SwitchEndianWord(&Window);
	SwitchEndianWord(&Checksum);
	SwitchEndianWord(&UrgentPointer);
}
char * TCPHeader::ToString()
{
	char * output = (char *)malloc(359 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-TCP:\n");
	sprintfi(output, &index, "| |-SourcePort: 0x%02x\n", SourcePort);
	sprintfi(output, &index, "| |-DestinationPort: 0x%02x\n", DestinationPort);
	sprintfi(output, &index, "| |-SeqeunceNumber: 0x%08x\n", SequenceNumber);
	sprintfi(output, &index, "| |-AcknowledgementNumber: 0x%08x\n", AcknowledgementNumber);
	sprintfi(output, &index, "| |-DataOffset: 0x%02x\n", DataOffset);
	sprintfi(output, &index, "| |-Flags: 0x%02x\n", Flags);
	sprintfi(output, &index, "| | |-FIN: 0x%01x\n", FIN);
	sprintfi(output, &index, "| | |-SYN: 0x%01x\n", SYN);
	sprintfi(output, &index, "| | |-RST: 0x%01x\n", RST);
	sprintfi(output, &index, "| | |-PSH: 0x%01x\n", PSH);
	sprintfi(output, &index, "| | |-ACK: 0x%01x\n", ACK);
	sprintfi(output, &index, "| | |-URG: 0x%01x\n", URG);
	sprintfi(output, &index, "| | |-ECE: 0x%01x\n", ECE);
	sprintfi(output, &index, "| | `-CWR: 0x%01x\n", CWR);
	sprintfi(output, &index, "| |-Window: 0x%04x\n", Window);
	sprintfi(output, &index, "| |-Checksum: 0x%04x\n", Checksum);
	sprintfi(output, &index, "| `-UrgentPointer: 0x%04x\n", UrgentPointer);

	return output;
}

#endif