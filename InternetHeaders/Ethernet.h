#ifndef ETHERNET_HEADER
#define ETHERNET_HEADER

#include "InternetTypes.h"     //byte, word
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndiannWord()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define ETHERNET_HEADER_SIZE 14

class EthernetHeader
{
public:
	EthernetHeader();
	EthernetHeader(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

	byte DestinationAddress[6];
	byte SourceAddress[6];
#define ETHERNET_IPV4 0x0800
#define ETHERNET_IPV6 0x86DD
#define ETHERNET_ARP  0x0806
	word Type;
};
EthernetHeader::EthernetHeader()
{
	Clear();
}
EthernetHeader::EthernetHeader(void * location)
{
	Assign(location);
}

void EthernetHeader::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding.
	for (int i = 0; i < 6; i++) 
		DestinationAddress[i] = Select<byte>(location, &index);
	for (int i = 0; i < 6; i++) 
		SourceAddress[i] = Select<byte>(location, &index);
	Type = Select<word>(location, &index);

	SwitchEndianness();
}

void EthernetHeader::Clear()
{
	//memset() can be used as padding can be zero
	memset(this, 0, sizeof(EthernetHeader));
}

void EthernetHeader::SwitchEndianness()
{
	SwitchEndianWord(&Type);
}

char * EthernetHeader::ToString()
{
	char * output = (char *)malloc(109 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-Ethernet:\n");
	sprintfi(output, &index, "| |-DestinationAddress: ");
	for (int i = 0; i < 6; i++) 
		sprintfi(output, &index, "%02x-", DestinationAddress[i]);
	sprintfi(output, &(--index) /*to overwrite last '-'*/, "\n| |-SourceAddress: ");
	for (int i = 0; i < 6; i++)	
		sprintfi(output, &index, "%02x-", SourceAddress[i]);
	sprintfi(output, &(--index) /*to overwrite last '-'*/, "\n| `-Type: 0x%04x\n", Type);

	return output;
}

#endif