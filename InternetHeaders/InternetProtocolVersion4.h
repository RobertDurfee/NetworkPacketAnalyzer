#ifndef INTERNET_PROTOCOL_VERSION_4_HEADER
#define INTERNET_PROTOCOL_VERSION_4_HEADER

#include "InternetTypes.h"     //byte, word
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndianWord()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define IPV4_HEADER_SIZE 20

class IPV4Header
{
public:
	IPV4Header();
	IPV4Header(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

	byte Versions;
		byte Version;
		byte HeaderLength;
	byte DifferentiatedServicesField;
		byte DifferentiatedServicesCodePoint;
		byte ECNCapableTransport;
		byte ECNCE;
	word TotalLength;
	word Identification;
	word FragmentFlags;
		byte DontFragment;
		byte MoreFragments;
		word Offset;
	byte TimeToLive;
#define IPV4_TCP		0x06
#define IPV4_UDP		0x11
#define IPV4_ICMP		0x01
	byte NextProtocol;
	word Checksum;
	byte SourceAddress[4];
	byte DestinationAddress[4];
};

IPV4Header::IPV4Header()
{
	Clear();
}
IPV4Header::IPV4Header(void * location)
{
	Assign(location);
}
void IPV4Header::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding.
	Versions = Select<byte>(location, &index);
	DifferentiatedServicesField = Select<byte>(location, &index);
	TotalLength = Select<word>(location, &index);
	Identification = Select<word>(location, &index);
	FragmentFlags = Select<word>(location, &index);
	TimeToLive = Select<byte>(location, &index);
	NextProtocol = Select<byte>(location, &index);
	Checksum = Select<word>(location, &index);
	for (int i = 0; i < 4; i++) 
		SourceAddress[i] = Select<byte>(location, &index);
	for (int i = 0; i < 4; i++) 
		DestinationAddress[i] = Select<byte>(location, &index);
	

	SwitchEndianness();

	Version = (Versions >> 4) & 0xF;
	HeaderLength = Versions & 0xF;

	DifferentiatedServicesCodePoint = (DifferentiatedServicesField >> 2) & 0x3F;
	ECNCapableTransport = (DifferentiatedServicesField >> 1) & 0x1;
	ECNCE = DifferentiatedServicesField & 0x1;

	DontFragment = (FragmentFlags >> 14) & 0x1;
	MoreFragments = (FragmentFlags >> 13) & 0x1;
	Offset = FragmentFlags & 0x1FFF;
}
void IPV4Header::Clear()
{
	//memset() can be used as padding can be zero
	memset(this, 0, sizeof(IPV4Header));
}
void IPV4Header::SwitchEndianness()
{
	SwitchEndianWord(&TotalLength);
	SwitchEndianWord(&Identification);
	SwitchEndianWord(&FragmentFlags);
	SwitchEndianWord(&Checksum);
}
char * IPV4Header::ToString()
{
	char * output = (char *)malloc(427 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-IPv4:\n");
	sprintfi(output, &index, "| |-Versions: 0x%02x\n", Versions);
	sprintfi(output, &index, "| | |-Version: 0x%01x\n", Version);
	sprintfi(output, &index, "| | `-HeaderLength: 0x%01x\n", HeaderLength);
	sprintfi(output, &index, "| |-DifferentiatedServicesField: 0x%02x\n", DifferentiatedServicesField);
	sprintfi(output, &index, "| | |-DSCP: 0x%02x\n", DifferentiatedServicesCodePoint);
	sprintfi(output, &index, "| | |-ECT: 0x%01x\n", ECNCapableTransport);
	sprintfi(output, &index, "| | `-CE: 0x%01x\n", ECNCE);
	sprintfi(output, &index, "| |-TotalLength: 0x%04x\n", TotalLength);
	sprintfi(output, &index, "| |-Identification: 0x%04x\n", Identification);
	sprintfi(output, &index, "| |-FragmentFlags: 0x%04x\n", FragmentFlags);
	sprintfi(output, &index, "| | |-DF: 0x%01x\n", DontFragment);
	sprintfi(output, &index, "| | |-MF: 0x%01x\n", MoreFragments);
	sprintfi(output, &index, "| | `-Offset: 0x%04x\n", Offset);
	sprintfi(output, &index, "| |-TimeToLive: 0x%02x\n", TimeToLive);
	sprintfi(output, &index, "| |-NextProtocol: 0x%02x\n", NextProtocol);
	sprintfi(output, &index, "| |-Checksum: 0x%04x\n", Checksum);
	sprintfi(output, &index, "| |-SourceAddress: ");
	for(int i = 0; i < 4; i++)
		sprintfi(output, &index, "%03d.", SourceAddress[i]);
	sprintfi(output, &(--index), "\n| `-DestinationAddress: "); 
	for(int i = 0; i < 4; i++)
		sprintfi(output, &index, "%03d.", DestinationAddress[i]);
	sprintfi(output, &(--index), "\n");

	return output;
}

#endif