#ifndef NETWORK_PACKET_ANALYZER_HEADER
#define NETWORK_PACKET_ANALYZER_HEADER

#define _CRT_SECURE_NO_WARNINGS

#define PCAP_WHOLE_PACKET 0x010000
#define NUMBER_OF_TAGS 83

#include "InternetHeaders/Internet.h" //EthernetHeader, ARPHeader, IPV4Header, IPV6Header, TCPHeader, UDPHeader
#include "FormatStringProcessor.h"    //FormatStringProcessor
#include <math.h>                     //pow()
#include <pcap.h>                     //PCAP_ERRBUF_SIZE, pcap_t, pcap_pkthdr, u_char, pcap_open_live(), pcap_close(), pcap_next_ex()
#include <time.h>                     //tm, time_t, time(), localtime()

int IntegerLength(unsigned int tagFunctionInput)
{
	unsigned int output = 1;
	unsigned int i = 1; unsigned long long j = 0;
	while (j = (unsigned long long)pow(10, i++))
		if (tagFunctionInput >= j) output++;
		else return output;
	
	return -1;
}
unsigned int StringToInteger(char * tagFunctionInput)
{
	int length = -1, counter = 0; unsigned int output = 0;
	while (tagFunctionInput[++length] != '\0');
	while (--length >= 0 && ++counter)
		output += (tagFunctionInput[length] - 48) * (unsigned int)pow(10, counter - 1);

	return output;
}

class NetworkPacketAnalyzer
{
public:
	NetworkPacketAnalyzer(char * deviceName, int timeout);
	~NetworkPacketAnalyzer();
	void Run(int numberOfPackets, char * formatString, char * filterString);
	tm * timeInfo;
	EthernetHeader ethernet;
	ARPHeader arp;
	IPV4Header ipv4;
	IPV6Header ipv6;
	TCPHeader tcp;
	UDPHeader udp;
	bool bETH, bARP, bIPv4, bIPv6, bTCP, bUDP;

private:
	char ** definedTags;
	void(**definedTagFunctions)(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	char * deviceName;
	pcap_t * adapterHandle;
	pcap_pkthdr * header; 
	u_char * packet;
	int startingPoint;
	FormatStringProcessor * formatStringProcessor;

	static void GENERAL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void IF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void EQUALS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void NOT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void OR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void AND_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ODD_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void XOR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void LEADING_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TRAILING_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void HOUR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void MINUTE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void SECOND_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void ETHERNET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ETHERNET_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ETHERNET_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ETHERNET_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void ARP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_HARDWARE_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_PROTOCOL_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_HARDWARE_ADDRESS_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_PROTOCOL_ADDRESS_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_OPERATION_CODE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_SENDER_MAC_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_SENDER_IPV4_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_TARGET_MAC_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void ARP_TARGET_IPV4_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void IPV4_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_VERSIONS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_VERSIONS_VERSION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_VERSIONS_HEADER_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_TOTAL_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_IDENTIFICATION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_FRAGMENT_FLAGS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_FRAGMENT_FLAGS_DF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_FRAGMENT_FLAGS_MF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_FRAGMENT_FLAGS_OFFSET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_TIME_TO_LIVE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_NEXT_PROTOCOL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV4_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void IPV6_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERSIONS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERSIONS_VERSION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERSIONS_DSCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERSIONS_ECT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERSIONS_CE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_VERISONS_FLOW_LABEL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_PAYLOAD_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_NEXT_PROTOCOL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_HOP_LIMIT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void IPV6_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void TCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_SOURCE_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_DESTINATION_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_PAYLOAD_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_SEQUENCE_NUMBER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_ACKNOWLEDGEMENT_NUMBER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_DATA_OFFSET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_FIN_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_SYN_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_RST_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_PSH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_ACK_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_URG_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_ECE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_FLAGS_CWR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_WINDOW_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void TCP_URGENT_POINTER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void UDP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void UDP_SOURCE_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void UDP_DESTINATION_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void UDP_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
	static void UDP_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);

	static void CONTENT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput);
};

NetworkPacketAnalyzer::NetworkPacketAnalyzer(char * deviceName, int timeout)
{
	this->deviceName = deviceName;

	char ErrorBuffer[PCAP_ERRBUF_SIZE];

	adapterHandle = pcap_open_live(deviceName, PCAP_WHOLE_PACKET, true, timeout, ErrorBuffer);

	definedTags = (char **)malloc(NUMBER_OF_TAGS * sizeof(char *));
	definedTagFunctions = (void (**)(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput))malloc(NUMBER_OF_TAGS * sizeof(void* (*)(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)));
	
	definedTags[0] = "GENERAL";

	definedTags[1] = "IF";
	definedTags[2] = "EQUALS";
	definedTags[3] = "NOT";
	definedTags[4] = "OR";
	definedTags[5] = "AND";
	definedTags[6] = "ODD";
	definedTags[7] = "XOR";

	definedTags[8] = "LEADING";
	definedTags[9] = "TRAILING";

	definedTags[10] = "HOUR";
	definedTags[11] = "MINUTE";
	definedTags[12] = "SECOND";
		
	definedTags[13] = "ETHERNET";
	definedTags[14] = "ETHERNET_DESTINATION_ADDRESS";
	definedTags[15] = "ETHERNET_SOURCE_ADDRESS";
	definedTags[16] = "ETHERNET_TYPE";

	definedTags[17] = "ARP";
	definedTags[18] = "ARP_HARDWARE_TYPE";
	definedTags[19] = "ARP_PROTOCOL_TYPE";
	definedTags[20] = "ARP_HARDWARE_ADDRESS_LENGTH";
	definedTags[21] = "ARP_PROTOCOL_ADDRESS_LENGTH";
	definedTags[22] = "ARP_OPERATION_CODE";
	definedTags[23] = "ARP_SENDER_MAC_ADDRESS";
	definedTags[24] = "ARP_SENDER_IPV4_ADDRESS";
	definedTags[25] = "ARP_TARGET_MAC_ADDRESS";
	definedTags[26] = "ARP_TARGET_IPV4_ADDRESS";

	definedTags[27] = "IPV4";
	definedTags[28] = "IPV4_VERSIONS";
	definedTags[29] = "IPV4_VERSIONS_VERSION";
	definedTags[30] = "IPV4_VERSIONS_HEADER_LENGTH";
	definedTags[31] = "IPV4_DIFFERENTIATED_SERVICES_FIELD";
	definedTags[32] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP";
	definedTags[33] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT";
	definedTags[34] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_CE";
	definedTags[35] = "IPV4_TOTAL_LENGTH";
	definedTags[36] = "IPV4_IDENTIFICATION";
	definedTags[37] = "IPV4_FRAGMENT_FLAGS";
	definedTags[38] = "IPV4_FRAGMENT_FLAGS_DF";
	definedTags[39] = "IPV4_FRAGMENT_FLAGS_MF";
	definedTags[40] = "IPV4_FRAGMENT_FLAGS_OFFSET";
	definedTags[41] = "IPV4_TIME_TO_LIVE";
	definedTags[42] = "IPV4_NEXT_PROTOCOL";
	definedTags[43] = "IPV4_CHECKSUM";
	definedTags[44] = "IPV4_SOURCE_ADDRESS";
	definedTags[45] = "IPV4_DESTINATION_ADDRESS";

	definedTags[46] = "IPV6";
	definedTags[47] = "IPV6_VERSIONS";
	definedTags[48] = "IPV6_VERSIONS_VERSION";
	definedTags[49] = "IPV6_VERSIONS_DSCP";
	definedTags[50] = "IPV6_VERSIONS_ECT";
	definedTags[51] = "IPV6_VERSIONS_CE";
	definedTags[52] = "IPV6_VERISONS_FLOW_LABEL";
	definedTags[53] = "IPV6_PAYLOAD_LENGTH";
	definedTags[54] = "IPV6_NEXT_PROTOCOL";
	definedTags[55] = "IPV6_HOP_LIMIT";
	definedTags[56] = "IPV6_SOURCE_ADDRESS";
	definedTags[57] = "IPV6_DESTINATION_ADDRESS";

	definedTags[58] = "TCP";
	definedTags[59] = "TCP_SOURCE_PORT";
	definedTags[60] = "TCP_DESTINATION_PORT";
	definedTags[61] = "TCP_PAYLOAD_LENGTH";
	definedTags[62] = "TCP_ACKNOWLEDGEMENT_NUMBER";
	definedTags[63] = "TCP_SEQUENCE_NUMBER";
	definedTags[64] = "TCP_DATA_OFFSET";
	definedTags[65] = "TCP_FLAGS";
	definedTags[66] = "TCP_FLAGS_FIN";
	definedTags[67] = "TCP_FLAGS_SYN";
	definedTags[68] = "TCP_FLAGS_RST";
	definedTags[69] = "TCP_FLAGS_PSH";
	definedTags[70] = "TCP_FLAGS_ACK";
	definedTags[71] = "TCP_FLAGS_URG";
	definedTags[72] = "TCP_FLAGS_ECE";
	definedTags[73] = "TCP_FLAGS_CWR";
	definedTags[74] = "TCP_WINDOW";
	definedTags[75] = "TCP_CHECKSUM";
	definedTags[76] = "TCP_URGENT_POINTER";

	definedTags[77] = "UDP";
	definedTags[78] = "UDP_SOURCE_PORT";
	definedTags[79] = "UDP_DESTINATION_PORT";
	definedTags[80] = "UDP_LENGTH";
	definedTags[81] = "UDP_CHECKSUM";
	definedTags[82] = "CONTENT";
	
	definedTagFunctions[0] = &GENERAL_TAG_FUNCTION;

	definedTagFunctions[1] = &IF_TAG_FUNCTION;
	definedTagFunctions[2] = &EQUALS_TAG_FUNCTION;
	definedTagFunctions[3] = &NOT_TAG_FUNCTION;
	definedTagFunctions[4] = &OR_TAG_FUNCTION;
	definedTagFunctions[5] = &AND_TAG_FUNCTION;
	definedTagFunctions[6] = &ODD_TAG_FUNCTION;
	definedTagFunctions[7] = &XOR_TAG_FUNCTION;

	definedTagFunctions[8] = &LEADING_TAG_FUNCTION;
	definedTagFunctions[9] = &TRAILING_TAG_FUNCTION;

	definedTagFunctions[10] = &HOUR_TAG_FUNCTION;
	definedTagFunctions[11] = &MINUTE_TAG_FUNCTION;
	definedTagFunctions[12] = &SECOND_TAG_FUNCTION;
	
	definedTagFunctions[13] = &ETHERNET_TAG_FUNCTION;
	definedTagFunctions[14] = &ETHERNET_DESTINATION_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[15] = &ETHERNET_SOURCE_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[16] = &ETHERNET_TYPE_TAG_FUNCTION;

	definedTagFunctions[17] = &ARP_TAG_FUNCTION;
	definedTagFunctions[18] = &ARP_HARDWARE_TYPE_TAG_FUNCTION;
	definedTagFunctions[19] = &ARP_PROTOCOL_TYPE_TAG_FUNCTION;
	definedTagFunctions[20] = &ARP_HARDWARE_ADDRESS_LENGTH_TAG_FUNCTION;
	definedTagFunctions[21] = &ARP_PROTOCOL_ADDRESS_LENGTH_TAG_FUNCTION;
	definedTagFunctions[22] = &ARP_OPERATION_CODE_TAG_FUNCTION;
	definedTagFunctions[23] = &ARP_SENDER_MAC_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[24] = &ARP_SENDER_IPV4_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[25] = &ARP_TARGET_MAC_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[26] = &ARP_TARGET_IPV4_ADDRESS_TAG_FUNCTION;

	definedTagFunctions[27] = &IPV4_TAG_FUNCTION;
	definedTagFunctions[28] = &IPV4_VERSIONS_TAG_FUNCTION;
	definedTagFunctions[29] = &IPV4_VERSIONS_VERSION_TAG_FUNCTION;
	definedTagFunctions[30] = &IPV4_VERSIONS_HEADER_LENGTH_TAG_FUNCTION;
	definedTagFunctions[31] = &IPV4_DIFFERENTIATED_SERVICES_FIELD_TAG_FUNCTION;
	definedTagFunctions[32] = &IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_TAG_FUNCTION;
	definedTagFunctions[33] = &IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_TAG_FUNCTION;
	definedTagFunctions[34] = &IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_TAG_FUNCTION;
	definedTagFunctions[35] = &IPV4_TOTAL_LENGTH_TAG_FUNCTION;
	definedTagFunctions[36] = &IPV4_IDENTIFICATION_TAG_FUNCTION;
	definedTagFunctions[37] = &IPV4_FRAGMENT_FLAGS_TAG_FUNCTION;
	definedTagFunctions[38] = &IPV4_FRAGMENT_FLAGS_DF_TAG_FUNCTION;
	definedTagFunctions[39] = &IPV4_FRAGMENT_FLAGS_MF_TAG_FUNCTION;
	definedTagFunctions[40] = &IPV4_FRAGMENT_FLAGS_OFFSET_TAG_FUNCTION;
	definedTagFunctions[41] = &IPV4_TIME_TO_LIVE_TAG_FUNCTION;
	definedTagFunctions[42] = &IPV4_NEXT_PROTOCOL_TAG_FUNCTION;
	definedTagFunctions[43] = &IPV4_CHECKSUM_TAG_FUNCTION;
	definedTagFunctions[44] = &IPV4_SOURCE_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[45] = &IPV4_DESTINATION_ADDRESS_TAG_FUNCTION;

	definedTagFunctions[46] = &IPV6_TAG_FUNCTION;
	definedTagFunctions[47] = &IPV6_VERSIONS_TAG_FUNCTION;
	definedTagFunctions[48] = &IPV6_VERSIONS_VERSION_TAG_FUNCTION;
	definedTagFunctions[49] = &IPV6_VERSIONS_DSCP_TAG_FUNCTION;
	definedTagFunctions[50] = &IPV6_VERSIONS_ECT_TAG_FUNCTION;
	definedTagFunctions[51] = &IPV6_VERSIONS_CE_TAG_FUNCTION;
	definedTagFunctions[52] = &IPV6_VERISONS_FLOW_LABEL_TAG_FUNCTION;
	definedTagFunctions[53] = &IPV6_PAYLOAD_LENGTH_TAG_FUNCTION;
	definedTagFunctions[54] = &IPV6_NEXT_PROTOCOL_TAG_FUNCTION;
	definedTagFunctions[55] = &IPV6_HOP_LIMIT_TAG_FUNCTION;
	definedTagFunctions[56] = &IPV6_SOURCE_ADDRESS_TAG_FUNCTION;
	definedTagFunctions[57] = &IPV6_DESTINATION_ADDRESS_TAG_FUNCTION;

	definedTagFunctions[58] = &TCP_TAG_FUNCTION;
	definedTagFunctions[59] = &TCP_SOURCE_PORT_TAG_FUNCTION;
	definedTagFunctions[60] = &TCP_DESTINATION_PORT_TAG_FUNCTION;
	definedTagFunctions[61] = &TCP_PAYLOAD_LENGTH_TAG_FUNCTION;
	definedTagFunctions[62] = &TCP_ACKNOWLEDGEMENT_NUMBER_TAG_FUNCTION;
	definedTagFunctions[63] = &TCP_SEQUENCE_NUMBER_TAG_FUNCTION;
	definedTagFunctions[64] = &TCP_DATA_OFFSET_TAG_FUNCTION;
	definedTagFunctions[65] = &TCP_FLAGS_TAG_FUNCTION;
	definedTagFunctions[66] = &TCP_FLAGS_FIN_TAG_FUNCTION;
	definedTagFunctions[67] = &TCP_FLAGS_SYN_TAG_FUNCTION;
	definedTagFunctions[68] = &TCP_FLAGS_RST_TAG_FUNCTION;
	definedTagFunctions[69] = &TCP_FLAGS_PSH_TAG_FUNCTION;
	definedTagFunctions[70] = &TCP_FLAGS_ACK_TAG_FUNCTION;
	definedTagFunctions[71] = &TCP_FLAGS_URG_TAG_FUNCTION;
	definedTagFunctions[72] = &TCP_FLAGS_ECE_TAG_FUNCTION;
	definedTagFunctions[73] = &TCP_FLAGS_CWR_TAG_FUNCTION;
	definedTagFunctions[74] = &TCP_WINDOW_TAG_FUNCTION;
	definedTagFunctions[75] = &TCP_CHECKSUM_TAG_FUNCTION;
	definedTagFunctions[76] = &TCP_URGENT_POINTER_TAG_FUNCTION;

	definedTagFunctions[77] = &UDP_TAG_FUNCTION;
	definedTagFunctions[78] = &UDP_SOURCE_PORT_TAG_FUNCTION;
	definedTagFunctions[79] = &UDP_DESTINATION_PORT_TAG_FUNCTION;
	definedTagFunctions[80] = &UDP_LENGTH_TAG_FUNCTION;
	definedTagFunctions[81] = &UDP_CHECKSUM_TAG_FUNCTION;
	definedTagFunctions[82] = &CONTENT_TAG_FUNCTION;

	formatStringProcessor = new FormatStringProcessor((void *)this, NUMBER_OF_TAGS, definedTags, definedTagFunctions);
}
NetworkPacketAnalyzer::~NetworkPacketAnalyzer()
{
	delete formatStringProcessor;

	free(definedTagFunctions);
	free(definedTags);

	pcap_close(adapterHandle);
}

void NetworkPacketAnalyzer::Run(int numberOfPackets, char * formatString, char * filterString)
{
	for (int i = 0; (numberOfPackets) ? i < numberOfPackets : true; i++)
	{
		packet = NULL;
		pcap_next_ex(adapterHandle, &header, (const u_char **)&packet);

		if (packet)
		{
			time_t rawtime;

			time(&rawtime);
			timeInfo = localtime(&rawtime);

			bETH = false; ethernet.Clear();
			bARP = false; arp.Clear();
			bIPv4 = false; ipv4.Clear();
			bIPv6 = false; ipv6.Clear();
			bTCP = false; tcp.Clear();
			bUDP = false; udp.Clear();

			startingPoint = 0;

			ethernet.Assign((void *)packet);
			bETH = true;
			startingPoint += ETHERNET_HEADER_SIZE;

			switch (ethernet.Type)
			{
			case ETHERNET_ARP:
				arp.Assign((void *)(packet + startingPoint));
				bARP = true;
				startingPoint += ARP_HEADER_SIZE;
				break;
			case ETHERNET_IPV4:
				ipv4.Assign((void *)(packet + startingPoint));
				bIPv4 = true;
				startingPoint += IPV4_HEADER_SIZE;
				switch (ipv4.NextProtocol)
				{
				case IPV4_TCP:
					tcp.Assign((void *)(packet + startingPoint));
					bTCP = true;
					startingPoint += TCP_HEADER_SIZE;
					break;
				case IPV4_UDP:
					udp.Assign((void *)(packet + startingPoint));
					bUDP = true;
					startingPoint += UDP_HEADER_SIZE;
					break;
				}
				break;
			case ETHERNET_IPV6:
				ipv6.Assign((void *)(packet + startingPoint));
				bIPv6 = true;
				startingPoint += IPV6_HEADER_SIZE;
				switch (ipv6.NextProtocol)
				{
				case IPV6_TCP:
					tcp.Assign((void *)(packet + startingPoint));
					bTCP = true;
					startingPoint += TCP_HEADER_SIZE;
					break;
				case IPV6_UDP:
					udp.Assign((void *)(packet + startingPoint));
					bUDP = true;
					startingPoint += UDP_HEADER_SIZE;
					break;
				}
				break;
			}
			char * filter = formatStringProcessor->Resolve(filterString);
			if (filter[0] == '1')
			{
				char * outputString = formatStringProcessor->Resolve(formatString);
				printf("%s", outputString);
				free(outputString);
			}
			free(filter);
		}
	}
}

void NetworkPacketAnalyzer::GENERAL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = -1;
	while (formatTag->Specifier[++length] != '\0');

	formatTag->Output = (char *)malloc(length + 1);

	for (int i = 0; i <= length; i++)
		formatTag->Output[i] = formatTag->Specifier[i];
}

void NetworkPacketAnalyzer::IF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (formatTag->Parameters[0][0] == '0')
	{
		formatTag->Output = (char *)malloc(1 * sizeof(char));
		formatTag->Output[0] = '\0';
		formatTag->NextFormatTag->Free();
		free(formatTag->NextFormatTag);
		formatTag->NextFormatTag = NULL;
	}
}
void NetworkPacketAnalyzer::EQUALS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 1; i < formatTag->NumberOfParameters; i++)
		if (strcmp(formatTag->Parameters[i], formatTag->Parameters[0]))
		{
			formatTag->Output[0] = '0';
			formatTag->Output[1] = '\0';
			return;
		}
	formatTag->Output[0] = '1';
	formatTag->Output[1] = '\0';
}
void NetworkPacketAnalyzer::NOT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	if (formatTag->Parameters[0][0] == '1')
		formatTag->Output[0] = '0';
	else
		formatTag->Output[0] = '1';
	formatTag->Output[1] = '\0';
}
void NetworkPacketAnalyzer::OR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 0; i < formatTag->NumberOfParameters; i++)
		if (formatTag->Parameters[i][0] == '1')
		{
			formatTag->Output[0] = '1';
			formatTag->Output[1] = '\0';
			return;
		}
	formatTag->Output[0] = '0';
	formatTag->Output[1] = '\0';
}
void NetworkPacketAnalyzer::AND_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 0; i < formatTag->NumberOfParameters; i++)
		if (formatTag->Parameters[i][0] == '0')
		{
			formatTag->Output[0] = '0';
			formatTag->Output[1] = '\0';
			return;
		}
	formatTag->Output[0] = '1';
	formatTag->Output[1] = '\0';
}
void NetworkPacketAnalyzer::ODD_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	int count = 0;
	for (int i = 0; i < formatTag->NumberOfParameters; i++)
		if (formatTag->Parameters[i]) count++;

	if (count % 2)
		formatTag->Output[0] = '1';
	else
		formatTag->Output[0] = '0';
	formatTag->Output[1] = '\0';
}
void NetworkPacketAnalyzer::XOR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(2 * sizeof(char));

	int count = 0;
	for (int i = 0; i < formatTag->NumberOfParameters; i++)
		if (formatTag->Parameters[i]) count++;

	if (count == 1)
		formatTag->Output[0] = '1';
	else
		formatTag->Output[0] = '0';
	formatTag->Output[1] = '\0';
}

void NetworkPacketAnalyzer::LEADING_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	unsigned int spaces = StringToInteger(formatTag->Parameters[1]);
	formatTag->Output = (char *)malloc(spaces + 1);

	int length = -1;
	while (tagFunctionInput[++length] != '\0');

	unsigned int i = 0;
	for (i; i < spaces - length; i++)
		formatTag->Output[i] = formatTag->Parameters[0][0];
	for (i; i < spaces; i++)
		formatTag->Output[i] = tagFunctionInput[i - (spaces - length)];

	formatTag->Output[i] = '\0';
}
void NetworkPacketAnalyzer::TRAILING_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	unsigned int spaces = StringToInteger(formatTag->Parameters[1]);
	formatTag->Output = (char *)malloc(spaces + 1);

	int length = -1;
	while (tagFunctionInput[++length] != '\0');

	int i = 0;
	for (i; i < length; i++)
		formatTag->Output[i] = tagFunctionInput[i];
	for (i; i < (int)spaces; i++)
		formatTag->Output[i] = formatTag->Parameters[0][0];

	formatTag->Output[i] = '\0';
}

void NetworkPacketAnalyzer::HOUR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_hour);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_hour);
}
void NetworkPacketAnalyzer::MINUTE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_min);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_min);
}
void NetworkPacketAnalyzer::SECOND_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_sec);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->timeInfo->tm_sec);
}

void NetworkPacketAnalyzer::ETHERNET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bETH)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::ETHERNET_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(18);

	sprintf(formatTag->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.DestinationAddress[5]);
}
void NetworkPacketAnalyzer::ETHERNET_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(18);

	sprintf(formatTag->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.SourceAddress[5]);
}
void NetworkPacketAnalyzer::ETHERNET_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.Type);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ethernet.Type);
}

void NetworkPacketAnalyzer::ARP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bARP)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::ARP_HARDWARE_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.HardwareType);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.HardwareType);
}
void NetworkPacketAnalyzer::ARP_PROTOCOL_TYPE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.ProtocolType);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.ProtocolType);
}
void NetworkPacketAnalyzer::ARP_HARDWARE_ADDRESS_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.HardwareAddressLen);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.HardwareAddressLen);
}
void NetworkPacketAnalyzer::ARP_PROTOCOL_ADDRESS_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.ProtocolAddressLen);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.ProtocolAddressLen);
}
void NetworkPacketAnalyzer::ARP_OPERATION_CODE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.OpCode);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.OpCode);
}
void NetworkPacketAnalyzer::ARP_SENDER_MAC_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(18);

	sprintf(formatTag->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderMACAddress[5]);
}
void NetworkPacketAnalyzer::ARP_SENDER_IPV4_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(16);

	sprintf(formatTag->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderIPv4Address[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderIPv4Address[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderIPv4Address[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.SenderIPv4Address[3]);
}
void NetworkPacketAnalyzer::ARP_TARGET_MAC_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(18);

	sprintf(formatTag->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetMACAddress[5]);
}
void NetworkPacketAnalyzer::ARP_TARGET_IPV4_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(16);

	sprintf(formatTag->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetIPv4Address[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetIPv4Address[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetIPv4Address[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->arp.TargetIPv4Address[3]);
}

void NetworkPacketAnalyzer::IPV4_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bIPv4)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::IPV4_VERSIONS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions);
}
void NetworkPacketAnalyzer::IPV4_VERSIONS_VERSION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions >> 4) & 0XF);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions >> 4) & 0xF);
}
void NetworkPacketAnalyzer::IPV4_VERSIONS_HEADER_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions & 0xF);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions & 0xF);
}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField);
}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField >> 2) & 0x3F);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField >> 2) & 0x3F);
}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField >> 1) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField >> 1) & 0x1);
}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DifferentiatedServicesField & 0x1);
}
void NetworkPacketAnalyzer::IPV4_TOTAL_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TotalLength);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TotalLength);
}
void NetworkPacketAnalyzer::IPV4_IDENTIFICATION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Identification);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Identification);
}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags);
}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_DF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags >> 14) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags >> 14) & 0x1);
}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_MF_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags >> 13) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags >> 13) & 0x1);
}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_OFFSET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags & 0x1FFF);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.FragmentFlags & 0x1FFF);
}
void NetworkPacketAnalyzer::IPV4_TIME_TO_LIVE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TimeToLive);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TimeToLive);
}
void NetworkPacketAnalyzer::IPV4_NEXT_PROTOCOL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.NextProtocol);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.NextProtocol);
}
void NetworkPacketAnalyzer::IPV4_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Checksum);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Checksum);
}
void NetworkPacketAnalyzer::IPV4_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(16 * sizeof(char));

	sprintf(formatTag->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.SourceAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.SourceAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.SourceAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.SourceAddress[3]);
}
void NetworkPacketAnalyzer::IPV4_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(16 * sizeof(char));

	sprintf(formatTag->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DestinationAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DestinationAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DestinationAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.DestinationAddress[3]);
}

void NetworkPacketAnalyzer::IPV6_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bIPv6)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions);
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_VERSION_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 28) & 0xF);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 28) & 0xF);
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_DSCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 22) & 0x3F);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 22) & 0x3F);
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_ECT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 21) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 21) & 0x1);
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_CE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 20) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions >> 20) & 0x1);
}
void NetworkPacketAnalyzer::IPV6_VERISONS_FLOW_LABEL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions & 0xFFFFF);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.Versions & 0xFFFFF);
}
void NetworkPacketAnalyzer::IPV6_PAYLOAD_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.PayloadLength);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.PayloadLength);
}
void NetworkPacketAnalyzer::IPV6_NEXT_PROTOCOL_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.NextProtocol);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.NextProtocol);
}
void NetworkPacketAnalyzer::IPV6_HOP_LIMIT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.HopLimit);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.HopLimit);
}
void NetworkPacketAnalyzer::IPV6_SOURCE_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(40);

	sprintf(formatTag->Output, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[5], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[6], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.SourceAddress[7]);
}
void NetworkPacketAnalyzer::IPV6_DESTINATION_ADDRESS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	formatTag->Output = (char *)malloc(40);

	sprintf(formatTag->Output, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[0], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[1], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[2], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[3], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[4], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[5], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[6], ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv6.DestinationAddress[7]);
}

void NetworkPacketAnalyzer::TCP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bTCP)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::TCP_SOURCE_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.SourcePort);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.SourcePort);
}
void NetworkPacketAnalyzer::TCP_DESTINATION_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DestinationPort);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DestinationPort);
}
void NetworkPacketAnalyzer::TCP_PAYLOAD_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TotalLength - ((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions & 0x0F) * 4) - (((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset >> 4) & 0x0F) * 4));

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TotalLength - ((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions & 0x0F) * 4) - (((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset >> 4) & 0x0F) * 4));
}
void NetworkPacketAnalyzer::TCP_ACKNOWLEDGEMENT_NUMBER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.AcknowledgementNumber);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.AcknowledgementNumber);
}
void NetworkPacketAnalyzer::TCP_SEQUENCE_NUMBER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.SequenceNumber);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.SequenceNumber);
}
void NetworkPacketAnalyzer::TCP_DATA_OFFSET_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset);
}
void NetworkPacketAnalyzer::TCP_FLAGS_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags);
}
void NetworkPacketAnalyzer::TCP_FLAGS_FIN_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_SYN_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 1) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 1) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_RST_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 2) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 2) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_PSH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 3) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 3) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_ACK_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 4) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 4) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_URG_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 5) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 5) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_ECE_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 6) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 6) & 0x1);
}
void NetworkPacketAnalyzer::TCP_FLAGS_CWR_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 7) & 0x1);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%d", (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Flags >> 7) & 0x1);
}
void NetworkPacketAnalyzer::TCP_WINDOW_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Window);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Window);
}
void NetworkPacketAnalyzer::TCP_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Checksum);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.Checksum);
}
void NetworkPacketAnalyzer::TCP_URGENT_POINTER_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.UrgentPointer);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.UrgentPointer);
}

void NetworkPacketAnalyzer::UDP_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bUDP)
		formatTag->Output = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.ToString();
	else
	{
		formatTag->Output = (char *)malloc(2);
		formatTag->Output[0] = '0';
		formatTag->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::UDP_SOURCE_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.SourcePort);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.SourcePort);
}
void NetworkPacketAnalyzer::UDP_DESTINATION_PORT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.DestinationPort);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.DestinationPort);
}
void NetworkPacketAnalyzer::UDP_LENGTH_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.Length);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.Length);
}
void NetworkPacketAnalyzer::UDP_CHECKSUM_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.Checksum);

	formatTag->Output = (char *)malloc(length);

	sprintf(formatTag->Output, "%u", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->udp.Checksum);
}

void NetworkPacketAnalyzer::CONTENT_TAG_FUNCTION(void * networkPacketAnalyzer, FormatTag * formatTag, char * tagFunctionInput)
{
	int contentLength = 0;

	if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->bTCP)
	{
		contentLength = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.TotalLength - (((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset >> 4) & 0x0F) * 4) - ((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.HeaderLength) * 4);
		((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint = (((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->tcp.DataOffset >> 4) & 0x0F) * 4) + ((((NetworkPacketAnalyzer*)networkPacketAnalyzer)->ipv4.Versions & 0xF) * 4) + 14;
	}
	else
		contentLength = ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->header->len - ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint;

	int numberOfLines = (int)(contentLength) / 16;
	if ((int)(contentLength) % 16 != 0)
		numberOfLines++;

	formatTag->Output = (char *)malloc(15 + numberOfLines * 83);

	int currentIndex = 0;

	sprintf(&formatTag->Output[currentIndex], "|-Content:\n"); currentIndex += 11;

	for (int i = 0; i < (numberOfLines * 16); i++)
	{
		if (i % 16 == 0)
		{
			if ((i / 16) == (numberOfLines - 1))
			{	sprintf(&formatTag->Output[currentIndex], "| `-0x%08x  ", i + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint); currentIndex += 16;	}
			else
			{	sprintf(&formatTag->Output[currentIndex], "| |-0x%08x  ", i + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint); currentIndex += 16;	}
		}
		if ((i + 1) % 16 == 0)
		{
			if (i < (int)(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->header->len - ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint))
			{	sprintf(&formatTag->Output[currentIndex], "%02x  ", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[i + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint]); currentIndex += 4;	}
			else
			{	sprintf(&formatTag->Output[currentIndex], "    "); currentIndex += 4;	}
			for (int j = (i + 1) - 16; j < (i + 1); j++)
				if (j < (int)(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->header->len - ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint))
					if (((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[j + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint] > 32 && ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[j + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint] < 127)
						sprintf(&formatTag->Output[currentIndex++], "%c", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[j + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint]);
					else
						sprintf(&formatTag->Output[currentIndex++], ".");
				else
					sprintf(&formatTag->Output[currentIndex++], " ");
			sprintf(&formatTag->Output[currentIndex++], "\n");
		}
		else if ((i + 1) % 8 == 0)
			if (i < (int)(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->header->len - ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint))
			{	sprintf(&formatTag->Output[currentIndex], "%02x  ", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[i + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint]); currentIndex += 4;	}
			else
			{	sprintf(&formatTag->Output[currentIndex], "    "); currentIndex += 4;	}
		else if (i < (int)(((NetworkPacketAnalyzer*)networkPacketAnalyzer)->header->len - ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint))
		{	sprintf(&formatTag->Output[currentIndex], "%02x ", ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->packet[i + ((NetworkPacketAnalyzer*)networkPacketAnalyzer)->startingPoint]); currentIndex += 3;	}
		else
		{	sprintf(&formatTag->Output[currentIndex], "   "); currentIndex += 3;}
	}
	sprintf(&formatTag->Output[currentIndex], "`-\n");
}

#endif