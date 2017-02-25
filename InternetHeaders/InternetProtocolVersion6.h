#ifndef INTERNET_PROTOCOL_VERSION_6_HEADER
#define INTERNET_PROTOCOL_VERSION_6_HEADER

#include "InternetTypes.h"     //byte, word, dword
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndianWord(), SwitchEndianDword()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define IPV6_HEADER_SIZE 40

class IPV6Header
{
public:
	IPV6Header();
	IPV6Header(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

	dword Versions;
		byte Version;
		byte DifferentiatedServicesCodePoint;
		byte ECNCapableTransport;
		byte ECNCE;
		dword FlowLabel;
	word PayloadLength;
#define IPV6_TCP		0x06
#define IPV6_UDP		0x11
#define IPV6_ICMP		0x01
	byte NextProtocol;
	byte HopLimit;
	word SourceAddress[8];
	word DestinationAddress[8];
};

IPV6Header::IPV6Header()
{
	Clear();
}
IPV6Header::IPV6Header(void * location)
{
	Assign(location);
}
void IPV6Header::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding.
	Versions = Select<dword>(location, &index);
	PayloadLength = Select<word>(location, &index);
	NextProtocol = Select<byte>(location, &index);
	HopLimit = Select<byte>(location, &index);
	for (int i = 0; i < 8; i++)
		SourceAddress[i] = Select<word>(location, &index);
	for (int i = 0; i < 8; i++)
		DestinationAddress[i] = Select<word>(location, &index);

	SwitchEndianness();
	
	Version = (Versions >> 28) & 0xF;
	DifferentiatedServicesCodePoint = (Versions >> 22) & 0x3F;
	ECNCapableTransport = (Versions >> 21) & 0x1;
	ECNCE = (Versions >> 20) & 0x1;
	FlowLabel = Versions & 0xFFFFF;
}
void IPV6Header::Clear()
{
	//memset() can be used as padding can be zero
	memset(this, 0, sizeof(IPV6Header));
}
void IPV6Header::SwitchEndianness()
{
	SwitchEndianDword(&Versions);
	SwitchEndianWord(&PayloadLength);
	for (int i = 0; i < 8; i++)
	{
		SwitchEndianWord(&SourceAddress[i]);
		SwitchEndianWord(&DestinationAddress[i]);
	}
}
char * IPV6Header::ToString()
{
	char * output = (char *)malloc(321 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-IPv6:\n");
	sprintfi(output, &index, "| |-Versions: 0x%08x\n", Versions);
	sprintfi(output, &index, "| | |-Version: 0x%01x\n", Version);
	sprintfi(output, &index, "| | |-DSCP: 0x%02x\n", DifferentiatedServicesCodePoint);
	sprintfi(output, &index, "| | |-ECT: 0x%01x\n", ECNCapableTransport);
	sprintfi(output, &index, "| | |-CE: 0x%01x\n", ECNCE);
	sprintfi(output, &index, "| | `-FlowLabel: 0x%05x\n", FlowLabel);
	sprintfi(output, &index, "| |-PayloadLength: 0x%04x\n", PayloadLength);
	sprintfi(output, &index, "| |-NextProtocol: 0x%02x\n", NextProtocol);
	sprintfi(output, &index, "| |-HopLimit: 0x%02x\n", HopLimit);
	sprintfi(output, &index, "| |-SourceAddress: ");
	for(int i = 0; i < 8; i++)
		sprintfi(output, &index, "%04x:", SourceAddress[i]);
	sprintfi(output, &(--index), "\n| `-DestinationAddress: "); 
	for(int i = 0; i < 8; i++)
		sprintfi(output, &index, "%04x:", DestinationAddress[i]);
	sprintfi(output, &(--index), "\n");

	return output;
}

#endif