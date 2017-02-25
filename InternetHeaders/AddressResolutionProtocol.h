#ifndef ADDRESS_RESOLUTION_PROTOCOL_HEADER
#define ADDRESS_RESOLUTION_PROTOCOL_HEADER

#include "InternetTypes.h"     //byte, word
#include "InternetFunctions.h" //Select<>(), sprintfi()
#include "EndianConversions.h" //SwitchEndianWord()
#include <string.h>            //memset()
#include <stdlib.h>            //malloc()

#define ARP_HEADER_SIZE 28

class ARPHeader
{
public:
	ARPHeader();
	ARPHeader(void * location);

	void Assign(void * location);

	void Clear();

	void SwitchEndianness();

	char * ToString();

#define ARP_ETHERNET 0x01
#define ARP_IEEE_802 0x06
#define ARP_FIBRE    0x12
#define ARP_SERIAL   0x14
#define ARP_IPV4	 0x0800
#define ARP_IPV6	 0x86DD
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

ARPHeader::ARPHeader()
{
	Clear();
}
ARPHeader::ARPHeader(void * location)
{
	Assign(location);
}
void ARPHeader::Assign(void * location)
{
	int index = 0;

	//memcpy() is not used due to compiler-specific structure padding
	HardwareType = Select<word>(location, &index); 
	ProtocolType = Select<word>(location, &index);
	HardwareAddressLen = Select<byte>(location, &index);
	ProtocolAddressLen = Select<byte>(location, &index);
	OpCode = Select<word>(location, &index);
	for (int i = 0; i < 6; i++) 
		SenderMACAddress[i] = Select<byte>(location, &index);
	for (int i = 0; i < 4; i++) 
		SenderIPv4Address[i] = Select<byte>(location, &index);
	for (int i = 0; i < 6; i++) 
		TargetMACAddress[i] = Select<byte>(location, &index);
	for (int i = 0; i < 4; i++) 
		TargetIPv4Address[i] = Select<byte>(location, &index);

	SwitchEndianness();
}
void ARPHeader::Clear()
{
	//memset() can be used as padding can be zero.
	memset(this, 0, sizeof(ARPHeader));
}
void ARPHeader::SwitchEndianness()
{
	SwitchEndianWord(&HardwareType);
	SwitchEndianWord(&ProtocolType);
	SwitchEndianWord(&OpCode);
}
char * ARPHeader::ToString()
{
	char * output = (char *)malloc(299 * sizeof(char));

	int index = 0;

	sprintfi(output, &index, "|-ARP:\n");
	sprintfi(output, &index, "| |-HardwareType: 0x%04x\n", HardwareType);
	sprintfi(output, &index, "| |-ProtocolType: 0x%04x\n", ProtocolType);
	sprintfi(output, &index, "| |-HardwareAddressLength: 0x%02x\n", HardwareAddressLen);
	sprintfi(output, &index, "| |-ProtocolAddressLength: 0x%02x\n", ProtocolAddressLen);
	sprintfi(output, &index, "| |-Opcode: 0x%04x\n", OpCode);
	sprintfi(output, &index, "| |-SenderMACAddress: ");
	for (int i = 0; i < 6; i++)
		sprintfi(output, &index, "%02x-", SenderMACAddress[i]);
	sprintfi(output, &(--index), "\n| |-SenderIPv4Address: ");
	for (int i = 0; i < 4; i++)
		sprintfi(output, &index, "%03d.", SenderIPv4Address[i]);
	sprintfi(output, &(--index), "\n| |-TargetMACAddress: ");
	for (int i = 0; i < 6; i++)
		sprintfi(output, &index, "%02x-", TargetMACAddress[i]);
	sprintfi(output, &(--index), "\n| `-TargetIPv4Address: ");
	for(int i = 0; i < 4; i++)
		sprintfi(output, &index, "%03d.", TargetIPv4Address[i]);
	sprintfi(output, &(--index), "\n");

	return output;
}

#endif