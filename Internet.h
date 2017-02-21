#ifndef INTERNET_HEADERS_HEADER
#define INTERNET_HEADERS_HEADER

#include <stdio.h>
#include <string.h>

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long long qword;

void SwitchEndianWord(word * input)
{
	(*input) = (((*input) >> 8) & 0x00FF) | (((*input) << 8) & 0xFF00);
}
void SwitchEndianDword(dword * input)
{
	(*input) = (((*input) >> 24) & 0x000000FF) | (((*input) >> 8) & 0x0000FF00) | (((*input) << 8) & 0x00FF0000) | (((*input) << 24) & 0xFF000000);
}
void SwitchEndianQword(qword * input)
{
	(*input) = (((*input) >> 56) & 0x00000000000000FF) | (((*input) >> 40) & 0x000000000000FF00) | (((*input) >> 24) & 0x0000000000FF0000) | (((*input) >> 8) & 0x00000000FF000000) | (((*input) << 8) & 0x000000FF00000000) | (((*input) << 24) & 0x0000FF0000000000) | (((*input) << 40) & 0x00FF000000000000) | (((*input) << 56) & 0xFF00000000000000);
}

word SwitchEndianWord(word input)
{
	input = ((input >> 8) & 0x00FF) | ((input << 8) & 0xFF00);
	return input;
}
dword SwitchEndianDword(dword input)
{
	input = ((input >> 24) & 0x000000FF) | ((input >> 8) & 0x0000FF00) | ((input << 8) & 0x00FF0000) | ((input << 24) & 0xFF000000);
	return input;
}
qword SwitchEndianQword(qword input)
{
	input = ((input >> 56) & 0x00000000000000FF) | ((input >> 40) & 0x000000000000FF00) | ((input >> 24) & 0x0000000000FF0000) | ((input >> 8) & 0x00000000FF000000) | ((input << 8) & 0x000000FF00000000) | ((input << 24) & 0x0000FF0000000000) | ((input << 40) & 0x00FF000000000000) | ((input << 56) & 0xFF00000000000000);
	return input;
}

struct EthernetHeader
{
#define ETHERNET_IPV4 0x0800
#define ETHERNET_IPV6 0x86DD
#define ETHERNET_ARP  0x0806
	EthernetHeader()
	{

	}
	EthernetHeader(void * location)
	{
		memcpy(&this->DestinationAddress, location, sizeof(EthernetHeader));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->DestinationAddress, location, sizeof(EthernetHeader));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->DestinationAddress, 0, sizeof(EthernetHeader));
	}
	void SwitchEndianness()
	{
		SwitchEndianWord(&this->Type);
	}
	void Print()
	{
		printf("%c%cEthernet:\n", '|', '-');
		printf("%c %c%cDestinationAddress: %02x-%02x-%02x-%02x-%02x-%02x\n", '|', '|', '-', this->DestinationAddress[0], this->DestinationAddress[1], this->DestinationAddress[2], this->DestinationAddress[3], this->DestinationAddress[4], this->DestinationAddress[5]);
		printf("%c %c%cSourceAddress: %02x-%02x-%02x-%02x-%02x-%02x\n", '|', '|', '-', this->SourceAddress[0], this->SourceAddress[1], this->SourceAddress[2], this->SourceAddress[3], this->SourceAddress[4], this->SourceAddress[5]);
		printf("%c %c%cType: 0x%04x\n", '|', '`', '-', this->Type);
	}
	byte DestinationAddress[6];
	byte SourceAddress[6];
	word Type;
};

struct ARPHeader
{
#define ARP_ETHERNET 0x01
#define ARP_IEEE_802 0x06
#define ARP_FIBRE    0x12
#define ARP_SERIAL   0x14
#define ARP_IPV4	 0x0800
#define ARP_IPV6	 0x86DD
	ARPHeader()
	{

	}
	ARPHeader(void * location)
	{
		memcpy(&this->HardwareType, location, sizeof(ARPHeader));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->HardwareType, location, sizeof(ARPHeader));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->HardwareType, 0, sizeof(ARPHeader));
	}
	void SwitchEndianness()
	{
		SwitchEndianWord(&this->HardwareType);
		SwitchEndianWord(&this->ProtocolType);
		SwitchEndianWord(&this->OpCode);
	}
	void Print()
	{
		printf("%c%cARP:\n", '|', '-');
		printf("%c %c%cHardwareType: 0x%04x\n", '|', '|', '-', this->HardwareType);
		printf("%c %c%cProtocolType: 0x%04x\n", '|', '|', '-', this->ProtocolType);
		printf("%c %c%cHardwareAddressLength: 0x%02x\n", '|', '|', '-', this->HardwareAddressLen);
		printf("%c %c%cProtocolAddressLength: 0x%02x\n", '|', '|', '-', this->ProtocolAddressLen);
		printf("%c %c%cOpcode: 0x%04x\n", '|', '|', '-', this->OpCode);
		printf("%c %c%cSenderMACAddress: %02x-%02x-%02x-%02x-%02x-%02x\n", '|', '|', '-', this->SenderMACAddress[0], this->SenderMACAddress[1], this->SenderMACAddress[2], this->SenderMACAddress[3], this->SenderMACAddress[4], this->SenderMACAddress[5]);
		printf("%c %c%cSenderIPv4Addres: %d.%d.%d.%d\n", '|', '|', '-', this->SenderIPv4Address[0], this->SenderIPv4Address[1], this->SenderIPv4Address[2], this->SenderIPv4Address[3]);
		printf("%c %c%cTargetMACAddress: %02x-%02x-%02x-%02x-%02x-%02x\n", '|', '|', '-', this->TargetMACAddress[0], this->TargetMACAddress[1], this->TargetMACAddress[2], this->TargetMACAddress[3], this->TargetMACAddress[4], this->TargetMACAddress[5]);
		printf("%c %c%cTargetIPv4Addres: %d.%d.%d.%d\n", '|', '`', '-', this->TargetIPv4Address[0], this->TargetIPv4Address[1], this->TargetIPv4Address[2], this->TargetIPv4Address[3]);
	}
	word HardwareType;
	word ProtocolType;
	byte HardwareAddressLen;
	byte ProtocolAddressLen;
	word OpCode;
	byte SenderMACAddress[6];
	byte SenderIPv4Address[4];
	byte TargetMACAddress[6];
	byte TargetIPv4Address[4];
};

struct IPV4Header
{
#define IPV4_TCP		0x06
#define IPV4_UDP		0x11
#define IPV4_ICMP		0x01
	IPV4Header()
	{

	}
	IPV4Header(void * location)
	{
		memcpy(&this->Versions, location, sizeof(IPV4Header));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->Versions, location, sizeof(IPV4Header));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->Versions, 0, sizeof(IPV4Header));
	}
	void SwitchEndianness()
	{
		SwitchEndianWord(&this->TotalLength);
		SwitchEndianWord(&this->Identification);
		SwitchEndianWord(&this->FragmentFlags);
		SwitchEndianWord(&this->Checksum);
	}
	void Print()
	{
		byte Version = (this->Versions >> 4) & 0xF;
		byte HeaderLength = this->Versions & 0xF;
		byte DifferentiatedServicesCodePoint = (this->DifferentiatedServicesField >> 2) & 0x3F;
		byte ECNCapableTransport = (this->DifferentiatedServicesField >> 1) & 0x1;
		byte ECNCE = this->DifferentiatedServicesField & 0x1;
		byte DontFragment = (this->FragmentFlags >> 14) & 0x1;
		byte MoreFragments = (this->FragmentFlags >> 13) & 0x1;
		word Offset = this->FragmentFlags & 0x1FFF;
		printf("%c%cIPv4:\n", '|', '-');
		printf("%c %c%cVersions: 0x%02x\n", '|', '|', '-', this->Versions);
		printf("%c %c %c%cVersion: 0x%01x\n", '|', '|', '|', '-', Version);
		printf("%c %c %c%cHeaderLength: 0x%01x\n", '|', '|', '`', '-', HeaderLength);
		printf("%c %c%cDifferentiatedServicesField: 0x%02x\n", '|', '|', '-', this->DifferentiatedServicesField);
		printf("%c %c %c%cDSCP: 0x%02x\n", '|', '|', '|', '-', DifferentiatedServicesCodePoint);
		printf("%c %c %c%cECT: 0x%01x\n", '|', '|', '|', '-', ECNCapableTransport);
		printf("%c %c %c%cCE: 0x%01x\n", '|', '|', '`', '-', ECNCE);
		printf("%c %c%cTotalLength: 0x%04x\n", '|', '|', '-', this->TotalLength);
		printf("%c %c%cIdentification: 0x%04x\n", '|', '|', '-', this->Identification);
		printf("%c %c%cFragmentFlags: 0x%04x\n", '|', '|', '-', this->FragmentFlags);
		printf("%c %c %c%cDF: 0x%01x\n", '|', '|', '|', '-', DontFragment);
		printf("%c %c %c%cMF: 0x%01x\n", '|', '|', '|', '-', MoreFragments);
		printf("%c %c %c%cOffset: 0x%04x\n", '|', '|', '`', '-', Offset);
		printf("%c %c%cTimeToLive: 0x%02x\n", '|', '|', '-', this->TimeToLive);
		printf("%c %c%cNextProtocol: 0x%02x\n", '|', '|', '-', this->NextProtocol);
		printf("%c %c%cChecksum: 0x%04x\n", '|', '|', '-', this->Checksum);
		printf("%c %c%cSourceAddress: %03d.%03d.%03d.%03d\n", '|', '|', '-', this->SourceAddress[0], this->SourceAddress[1], this->SourceAddress[2], this->SourceAddress[3]);
		printf("%c %c%cDestinationAddress: %03d.%03d.%03d.%03d\n", '|', '`', '-', this->DestinationAddress[0], this->DestinationAddress[1], this->DestinationAddress[2], this->DestinationAddress[3]);
	}
	byte Versions;
	byte DifferentiatedServicesField;
	word TotalLength;
	word Identification;
	word FragmentFlags;
	byte TimeToLive;
	byte NextProtocol;
	word Checksum;
	byte SourceAddress[4];
	byte DestinationAddress[4];
};

struct IPV6Header
{
#define IPV6_TCP		0x06
#define IPV6_UDP		0x11
#define IPV6_ICMP		0x01
	IPV6Header()
	{

	}
	IPV6Header(void * location)
	{
		memcpy(&this->Versions, location, sizeof(IPV6Header));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->Versions, location, sizeof(IPV6Header));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->Versions, 0, sizeof(IPV6Header));
	}
	void SwitchEndianness()
	{
		SwitchEndianDword(&this->Versions);
		SwitchEndianWord(&this->PayloadLength);
		for (int i = 0; i < 8; i++)
		{
			SwitchEndianWord(&this->SourceAddress[i]);
			SwitchEndianWord(&this->DestinationAddress[i]);
		}
	}
	void Print()
	{
		byte Version = (this->Versions >> 28) & 0xF;
		byte DifferentiatedServicesCodePoint = (this->Versions >> 22) & 0x3F;
		byte ECNCapableTransport = (this->Versions >> 21) & 0x1;
		byte ECNCE = (this->Versions >> 20) & 0x1;
		dword FlowLabel = this->Versions & 0xFFFFF;

		printf("%c%cIPv6:\n", '|', '-');
		printf("%c %c%cVersions: 0x%08x\n", '|', '|', '-', this->Versions);
		printf("%c %c %c%cVersion: 0x%01x\n", '|', '|', '|', '-', Version);
		printf("%c %c %c%cDSCP: 0x%02x\n", '|', '|', '|', '-', DifferentiatedServicesCodePoint);
		printf("%c %c %c%cECT: 0x%01x\n", '|', '|', '|', '-', ECNCapableTransport);
		printf("%c %c %c%cCE: 0x%01x\n", '|', '|', '|', '-', ECNCE);
		printf("%c %c %c%cFlowLabel: 0x%05x\n", '|', '|', '`', '-', FlowLabel);
		printf("%c %c%cPayloadLength: 0x%04x\n", '|', '|', '-', this->PayloadLength);
		printf("%c %c%cNextProtocol: 0x%02x\n", '|', '|', '-', this->NextProtocol);
		printf("%c %c%cHopLimit: 0x%02x\n", '|', '|', '-', this->HopLimit);
		printf("%c %c%cSourceAddress: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", '|', '|', '-', this->SourceAddress[0], this->SourceAddress[1], this->SourceAddress[2], this->SourceAddress[3], this->SourceAddress[4], this->SourceAddress[5], this->SourceAddress[6], this->SourceAddress[7]);
		printf("%c %c%cDestinationAddress: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", '|', '`', '-', this->DestinationAddress[0], this->DestinationAddress[1], this->DestinationAddress[2], this->DestinationAddress[3], this->DestinationAddress[4], this->DestinationAddress[5], this->DestinationAddress[6], this->DestinationAddress[7]);
	}
	dword Versions;
	word PayloadLength;
	byte NextProtocol;
	byte HopLimit;
	word SourceAddress[8];
	word DestinationAddress[8];
};

struct TCPHeader
{
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
	TCPHeader()
	{

	}
	TCPHeader(void * location)
	{
		memcpy(&this->SourcePort, location, sizeof(TCPHeader));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->SourcePort, location, sizeof(TCPHeader));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->SourcePort, 0, sizeof(TCPHeader));
	}
	void SwitchEndianness()
	{
		SwitchEndianWord(&this->SourcePort);
		SwitchEndianWord(&this->DestinationPort);
		SwitchEndianDword(&this->SequenceNumber);
		SwitchEndianDword(&this->AcknowledgementNumber);
		SwitchEndianWord(&this->Window);
		SwitchEndianWord(&this->Checksum);
		SwitchEndianWord(&this->UrgentPointer);
	}
	void Print()
	{
		byte FIN = this->Flags & 0x1;
		byte SYN = (this->Flags >> 1) & 0x1;
		byte RST = (this->Flags >> 2) & 0x1;
		byte PUSH = (this->Flags >> 3) & 0x1;
		byte ACK = (this->Flags >> 4) & 0x1;
		byte URG = (this->Flags >> 5) & 0x1;
		byte ECE = (this->Flags >> 6) & 0x1;
		byte CWR = (this->Flags >> 7) & 0x1;

		printf("%c%cTCP:\n", '|', '-');
		printf("%c %c%cSourcePort: 0x%02x\n", '|', '|', '-', this->SourcePort);
		printf("%c %c%cDestinationPort: 0x%02x\n", '|', '|', '-', this->DestinationPort);
		printf("%c %c%cSeqeunceNumber: 0x%08x\n", '|', '|', '-', this->SequenceNumber);
		printf("%c %c%cAcknowledgementNumber: 0x%08x\n", '|', '|', '-', this->AcknowledgementNumber);
		printf("%c %c%cDataOffset: 0x%02x\n", '|', '|', '-', this->DataOffset);
		printf("%c %c%cFlags: 0x%02x\n", '|', '|', '-', this->Flags);
		printf("%c %c %c%cFIN: 0x%01x\n", '|', '|', '|', '-', FIN);
		printf("%c %c %c%cSYN: 0x%01x\n", '|', '|', '|', '-', SYN);
		printf("%c %c %c%cRST: 0x%01x\n", '|', '|', '|', '-', RST);
		printf("%c %c %c%cPUSH: 0x%01x\n", '|', '|', '|', '-', PUSH);
		printf("%c %c %c%cACK: 0x%01x\n", '|', '|', '|', '-', ACK);
		printf("%c %c %c%cURG: 0x%01x\n", '|', '|', '|', '-', URG);
		printf("%c %c %c%cECE: 0x%01x\n", '|', '|', '|', '-', ECE);
		printf("%c %c %c%cCWR: 0x%01x\n", '|', '|', '`', '-', CWR);
		printf("%c %c%cWindow: 0x%04x\n", '|', '|', '-', this->Window);
		printf("%c %c%cChecksum: 0x%04x\n", '|', '|', '-', this->Checksum);
		printf("%c %c%cUrgentPointer: 0x%04x\n", '|', '`', '-', this->UrgentPointer);
	}
	word SourcePort;
	word DestinationPort;
	dword SequenceNumber;
	dword AcknowledgementNumber;
	byte DataOffset;
	byte Flags;
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
	word Window;
	word Checksum;
	word UrgentPointer;
};

struct UDPHeader
{
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
	UDPHeader()
	{

	}
	UDPHeader(void * location)
	{
		memcpy(&this->SourcePort, location, sizeof(UDPHeader));
		this->SwitchEndianness();
	}
	void Assign(void * location)
	{
		memcpy(&this->SourcePort, location, sizeof(UDPHeader));
		this->SwitchEndianness();
	}
	void Clear()
	{
		memset(&this->SourcePort, 0, sizeof(UDPHeader));
	}
	void SwitchEndianness()
	{
		SwitchEndianWord(&this->SourcePort);
		SwitchEndianWord(&this->DestinationPort);
		SwitchEndianWord(&this->Length);
		SwitchEndianWord(&this->Checksum);
	}
	void Print()
	{
		printf("%c%cUDP:\n", '|', '-');
		printf("%c %c%cSourcePort: 0x%02x\n", '|', '|', '-', this->SourcePort);
		printf("%c %c%cDestinationPort: 0x%02x\n", '|', '|', '-', this->DestinationPort);
		printf("%c %c%cLength: 0x%02x\n", '|', '|', '-', this->Length);
		printf("%c %c%cChecksum: 0x%02x\n", '|', '`', '-', this->Checksum);
	}
	word SourcePort;
	word DestinationPort;
	word Length;
	word Checksum;
};

#endif
