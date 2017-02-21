#ifndef NETWORK_PACKET_ANALYZER_HEADER
#define NETWORK_PACKET_ANALYZER_HEADER

#define PCAP_WHOLE_PACKET 0x010000
#define NUMBER_OF_OPERATIONS 83

#include <time.h>
#include "OperationProcessor.h"
#include "Internet.h"
#include <pcap.h>

int IntegerLength(unsigned int input)
{
	unsigned int output = 1;
	unsigned int i = 1; unsigned long long j = 0;
	while (j = (unsigned long long)pow(10, i++))
		if (input >= j) output++;
		else return output;
}
unsigned int StringToInteger(char * input)
{
	int length = -1, counter = 0; unsigned int output = 0;
	while (input[++length] != '\0');
	while (--length >= 0 && ++counter)
		output += (input[length] - 48) * (unsigned int)pow(10, counter - 1);

	return output;
}

class NetworkPacketAnalyzer
{
public:
	NetworkPacketAnalyzer(char *, int);
	~NetworkPacketAnalyzer();
	void Run(int, char *, char *);
	tm * timeInfo;
	EthernetHeader ethernet;
	ARPHeader arp;
	IPV4Header ipv4;
	IPV6Header ipv6;
	TCPHeader tcp;
	UDPHeader udp;
	bool bETH, bARP, bIPv4, bIPv6, bTCP, bUDP;

private:
	char * deviceName;
	pcap_t * adapterHandle;
	pcap_pkthdr * header; 
	u_char * packet;
	int startingPoint;
	OperationProcessor * operationProcessor;
	static void GENERAL_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void IF_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void EQUALS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void NOT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void OR_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void AND_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ODD_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void XOR_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void LEADING_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TRAILING_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void HOUR_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void MINUTE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void SECOND_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void ETHERNET_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ETHERNET_DESTINATION_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ETHERNET_SOURCE_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ETHERNET_TYPE_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void ARP_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_HARDWARE_TYPE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_PROTOCOL_TYPE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_HARDWARE_ADDRESS_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_PROTOCOL_ADDRESS_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_OPERATION_CODE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_SENDER_MAC_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_SENDER_IPV4_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_TARGET_MAC_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void ARP_TARGET_IPV4_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void IPV4_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_VERSIONS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_VERSIONS_VERSION_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_VERSIONS_HEADER_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_TOTAL_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_IDENTIFICATION_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_FRAGMENT_FLAGS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_FRAGMENT_FLAGS_DF_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_FRAGMENT_FLAGS_MF_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_FRAGMENT_FLAGS_OFFSET_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_TIME_TO_LIVE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_NEXT_PROTOCOL_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_CHECKSUM_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_SOURCE_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV4_DESTINATION_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void IPV6_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERSIONS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERSIONS_VERSION_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERSIONS_DSCP_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERSIONS_ECT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERSIONS_CE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_VERISONS_FLOW_LABEL_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_PAYLOAD_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_NEXT_PROTOCOL_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_HOP_LIMIT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_SOURCE_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void IPV6_DESTINATION_ADDRESS_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void TCP_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_SOURCE_PORT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_DESTINATION_PORT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_PAYLOAD_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_SEQUENCE_NUMBER_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_ACKNOWLEDGEMENT_NUMBER_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_DATA_OFFSET_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_FIN_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_SYN_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_RST_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_PSH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_ACK_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_URG_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_ECE_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_FLAGS_CWR_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_WINDOW_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_CHECKSUM_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void TCP_URGENT_POINTER_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void UDP_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void UDP_SOURCE_PORT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void UDP_DESTINATION_PORT_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void UDP_LENGTH_OPERATION_ROUTINE(void *, OperationNode *, char *);
	static void UDP_CHECKSUM_OPERATION_ROUTINE(void *, OperationNode *, char *);

	static void CONTENT_OPERATION_ROUTINE(void *, OperationNode *, char *);
};

NetworkPacketAnalyzer::NetworkPacketAnalyzer(char * deviceName, int timeout)
{
	this->deviceName = deviceName;

	char ErrorBuffer[PCAP_ERRBUF_SIZE];

	this->adapterHandle = pcap_open_live(deviceName, PCAP_WHOLE_PACKET, true, timeout, ErrorBuffer);

	char ** operations = (char **)malloc(NUMBER_OF_OPERATIONS * sizeof(char *));
	void (**operationFunctions)(void *, OperationNode *, char *) = (void (**)(void *, OperationNode *, char *))malloc(NUMBER_OF_OPERATIONS * sizeof(void* (*)(void*, OperationNode*, char*)));
	
	operations[0] = "GENERAL";

	operations[1] = "IF";
	operations[2] = "EQUALS";
	operations[3] = "NOT";
	operations[4] = "OR";
	operations[5] = "AND";
	operations[6] = "ODD";
	operations[7] = "XOR";

	operations[8] = "LEADING";
	operations[9] = "TRAILING";

	operations[10] = "HOUR";
	operations[11] = "MINUTE";
	operations[12] = "SECOND";
		
	operations[13] = "ETHERNET";
	operations[14] = "ETHERNET_DESTINATION_ADDRESS";
	operations[15] = "ETHERNET_SOURCE_ADDRESS";
	operations[16] = "ETHERNET_TYPE";

	operations[17] = "ARP";
	operations[18] = "ARP_HARDWARE_TYPE";
	operations[19] = "ARP_PROTOCOL_TYPE";
	operations[20] = "ARP_HARDWARE_ADDRESS_LENGTH";
	operations[21] = "ARP_PROTOCOL_ADDRESS_LENGTH";
	operations[22] = "ARP_OPERATION_CODE";
	operations[23] = "ARP_SENDER_MAC_ADDRESS";
	operations[24] = "ARP_SENDER_IPV4_ADDRESS";
	operations[25] = "ARP_TARGET_MAC_ADDRESS";
	operations[26] = "ARP_TARGET_IPV4_ADDRESS";

	operations[27] = "IPV4";
	operations[28] = "IPV4_VERSIONS";
	operations[29] = "IPV4_VERSIONS_VERSION";
	operations[30] = "IPV4_VERSIONS_HEADER_LENGTH";
	operations[31] = "IPV4_DIFFERENTIATED_SERVICES_FIELD";
	operations[32] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP";
	operations[33] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT";
	operations[34] = "IPV4_DIFFERENTIATED_SERVICES_FIELD_CE";
	operations[35] = "IPV4_TOTAL_LENGTH";
	operations[36] = "IPV4_IDENTIFICATION";
	operations[37] = "IPV4_FRAGMENT_FLAGS";
	operations[38] = "IPV4_FRAGMENT_FLAGS_DF";
	operations[39] = "IPV4_FRAGMENT_FLAGS_MF";
	operations[40] = "IPV4_FRAGMENT_FLAGS_OFFSET";
	operations[41] = "IPV4_TIME_TO_LIVE";
	operations[42] = "IPV4_NEXT_PROTOCOL";
	operations[43] = "IPV4_CHECKSUM";
	operations[44] = "IPV4_SOURCE_ADDRESS";
	operations[45] = "IPV4_DESTINATION_ADDRESS";

	operations[46] = "IPV6";
	operations[47] = "IPV6_VERSIONS";
	operations[48] = "IPV6_VERSIONS_VERSION";
	operations[49] = "IPV6_VERSIONS_DSCP";
	operations[50] = "IPV6_VERSIONS_ECT";
	operations[51] = "IPV6_VERSIONS_CE";
	operations[52] = "IPV6_VERISONS_FLOW_LABEL";
	operations[53] = "IPV6_PAYLOAD_LENGTH";
	operations[54] = "IPV6_NEXT_PROTOCOL";
	operations[55] = "IPV6_HOP_LIMIT";
	operations[56] = "IPV6_SOURCE_ADDRESS";
	operations[57] = "IPV6_DESTINATION_ADDRESS";

	operations[58] = "TCP";
	operations[59] = "TCP_SOURCE_PORT";
	operations[60] = "TCP_DESTINATION_PORT";
	operations[61] = "TCP_PAYLOAD_LENGTH";
	operations[62] = "TCP_ACKNOWLEDGEMENT_NUMBER";
	operations[63] = "TCP_SEQUENCE_NUMBER";
	operations[64] = "TCP_DATA_OFFSET";
	operations[65] = "TCP_FLAGS";
	operations[66] = "TCP_FLAGS_FIN";
	operations[67] = "TCP_FLAGS_SYN";
	operations[68] = "TCP_FLAGS_RST";
	operations[69] = "TCP_FLAGS_PSH";
	operations[70] = "TCP_FLAGS_ACK";
	operations[71] = "TCP_FLAGS_URG";
	operations[72] = "TCP_FLAGS_ECE";
	operations[73] = "TCP_FLAGS_CWR";
	operations[74] = "TCP_WINDOW";
	operations[75] = "TCP_CHECKSUM";
	operations[76] = "TCP_URGENT_POINTER";

	operations[77] = "UDP";
	operations[78] = "UDP_SOURCE_PORT";
	operations[79] = "UDP_DESTINATION_PORT";
	operations[80] = "UDP_LENGTH";
	operations[81] = "UDP_CHECKSUM";
	operations[82] = "CONTENT";
	
	operationFunctions[0] = &this->GENERAL_OPERATION_ROUTINE;

	operationFunctions[1] = &this->IF_OPERATION_ROUTINE;
	operationFunctions[2] = &this->EQUALS_OPERATION_ROUTINE;
	operationFunctions[3] = &this->NOT_OPERATION_ROUTINE;
	operationFunctions[4] = &this->OR_OPERATION_ROUTINE;
	operationFunctions[5] = &this->AND_OPERATION_ROUTINE;
	operationFunctions[6] = &this->ODD_OPERATION_ROUTINE;
	operationFunctions[7] = &this->XOR_OPERATION_ROUTINE;

	operationFunctions[8] = &this->LEADING_OPERATION_ROUTINE;
	operationFunctions[9] = &this->TRAILING_OPERATION_ROUTINE;

	operationFunctions[10] = &this->HOUR_OPERATION_ROUTINE;
	operationFunctions[11] = &this->MINUTE_OPERATION_ROUTINE;
	operationFunctions[12] = &this->SECOND_OPERATION_ROUTINE;
	
	operationFunctions[13] = &this->ETHERNET_OPERATION_ROUTINE;
	operationFunctions[14] = &this->ETHERNET_DESTINATION_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[15] = &this->ETHERNET_SOURCE_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[16] = &this->ETHERNET_TYPE_OPERATION_ROUTINE;

	operationFunctions[17] = &this->ARP_OPERATION_ROUTINE;
	operationFunctions[18] = &this->ARP_HARDWARE_TYPE_OPERATION_ROUTINE;
	operationFunctions[19] = &this->ARP_PROTOCOL_TYPE_OPERATION_ROUTINE;
	operationFunctions[20] = &this->ARP_HARDWARE_ADDRESS_LENGTH_OPERATION_ROUTINE;
	operationFunctions[21] = &this->ARP_PROTOCOL_ADDRESS_LENGTH_OPERATION_ROUTINE;
	operationFunctions[22] = &this->ARP_OPERATION_CODE_OPERATION_ROUTINE;
	operationFunctions[23] = &this->ARP_SENDER_MAC_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[24] = &this->ARP_SENDER_IPV4_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[25] = &this->ARP_TARGET_MAC_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[26] = &this->ARP_TARGET_IPV4_ADDRESS_OPERATION_ROUTINE;

	operationFunctions[27] = &this->IPV4_OPERATION_ROUTINE;
	operationFunctions[28] = &this->IPV4_VERSIONS_OPERATION_ROUTINE;
	operationFunctions[29] = &this->IPV4_VERSIONS_VERSION_OPERATION_ROUTINE;
	operationFunctions[30] = &this->IPV4_VERSIONS_HEADER_LENGTH_OPERATION_ROUTINE;
	operationFunctions[31] = &this->IPV4_DIFFERENTIATED_SERVICES_FIELD_OPERATION_ROUTINE;
	operationFunctions[32] = &this->IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_OPERATION_ROUTINE;
	operationFunctions[33] = &this->IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_OPERATION_ROUTINE;
	operationFunctions[34] = &this->IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_OPERATION_ROUTINE;
	operationFunctions[35] = &this->IPV4_TOTAL_LENGTH_OPERATION_ROUTINE;
	operationFunctions[36] = &this->IPV4_IDENTIFICATION_OPERATION_ROUTINE;
	operationFunctions[37] = &this->IPV4_FRAGMENT_FLAGS_OPERATION_ROUTINE;
	operationFunctions[38] = &this->IPV4_FRAGMENT_FLAGS_DF_OPERATION_ROUTINE;
	operationFunctions[39] = &this->IPV4_FRAGMENT_FLAGS_MF_OPERATION_ROUTINE;
	operationFunctions[40] = &this->IPV4_FRAGMENT_FLAGS_OFFSET_OPERATION_ROUTINE;
	operationFunctions[41] = &this->IPV4_TIME_TO_LIVE_OPERATION_ROUTINE;
	operationFunctions[42] = &this->IPV4_NEXT_PROTOCOL_OPERATION_ROUTINE;
	operationFunctions[43] = &this->IPV4_CHECKSUM_OPERATION_ROUTINE;
	operationFunctions[44] = &this->IPV4_SOURCE_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[45] = &this->IPV4_DESTINATION_ADDRESS_OPERATION_ROUTINE;

	operationFunctions[46] = &this->IPV6_OPERATION_ROUTINE;
	operationFunctions[47] = &this->IPV6_VERSIONS_OPERATION_ROUTINE;
	operationFunctions[48] = &this->IPV6_VERSIONS_VERSION_OPERATION_ROUTINE;
	operationFunctions[49] = &this->IPV6_VERSIONS_DSCP_OPERATION_ROUTINE;
	operationFunctions[50] = &this->IPV6_VERSIONS_ECT_OPERATION_ROUTINE;
	operationFunctions[51] = &this->IPV6_VERSIONS_CE_OPERATION_ROUTINE;
	operationFunctions[52] = &this->IPV6_VERISONS_FLOW_LABEL_OPERATION_ROUTINE;
	operationFunctions[53] = &this->IPV6_PAYLOAD_LENGTH_OPERATION_ROUTINE;
	operationFunctions[54] = &this->IPV6_NEXT_PROTOCOL_OPERATION_ROUTINE;
	operationFunctions[55] = &this->IPV6_HOP_LIMIT_OPERATION_ROUTINE;
	operationFunctions[56] = &this->IPV6_SOURCE_ADDRESS_OPERATION_ROUTINE;
	operationFunctions[57] = &this->IPV6_DESTINATION_ADDRESS_OPERATION_ROUTINE;

	operationFunctions[58] = &this->TCP_OPERATION_ROUTINE;
	operationFunctions[59] = &this->TCP_SOURCE_PORT_OPERATION_ROUTINE;
	operationFunctions[60] = &this->TCP_DESTINATION_PORT_OPERATION_ROUTINE;
	operationFunctions[61] = &this->TCP_PAYLOAD_LENGTH_OPERATION_ROUTINE;
	operationFunctions[62] = &this->TCP_ACKNOWLEDGEMENT_NUMBER_OPERATION_ROUTINE;
	operationFunctions[63] = &this->TCP_SEQUENCE_NUMBER_OPERATION_ROUTINE;
	operationFunctions[64] = &this->TCP_DATA_OFFSET_OPERATION_ROUTINE;
	operationFunctions[65] = &this->TCP_FLAGS_OPERATION_ROUTINE;
	operationFunctions[66] = &this->TCP_FLAGS_FIN_OPERATION_ROUTINE;
	operationFunctions[67] = &this->TCP_FLAGS_SYN_OPERATION_ROUTINE;
	operationFunctions[68] = &this->TCP_FLAGS_RST_OPERATION_ROUTINE;
	operationFunctions[69] = &this->TCP_FLAGS_PSH_OPERATION_ROUTINE;
	operationFunctions[70] = &this->TCP_FLAGS_ACK_OPERATION_ROUTINE;
	operationFunctions[71] = &this->TCP_FLAGS_URG_OPERATION_ROUTINE;
	operationFunctions[72] = &this->TCP_FLAGS_ECE_OPERATION_ROUTINE;
	operationFunctions[73] = &this->TCP_FLAGS_CWR_OPERATION_ROUTINE;
	operationFunctions[74] = &this->TCP_WINDOW_OPERATION_ROUTINE;
	operationFunctions[75] = &this->TCP_CHECKSUM_OPERATION_ROUTINE;
	operationFunctions[76] = &this->TCP_URGENT_POINTER_OPERATION_ROUTINE;

	operationFunctions[77] = &this->UDP_OPERATION_ROUTINE;
	operationFunctions[78] = &this->UDP_SOURCE_PORT_OPERATION_ROUTINE;
	operationFunctions[79] = &this->UDP_DESTINATION_PORT_OPERATION_ROUTINE;
	operationFunctions[80] = &this->UDP_LENGTH_OPERATION_ROUTINE;
	operationFunctions[81] = &this->UDP_CHECKSUM_OPERATION_ROUTINE;
	operationFunctions[82] = &this->CONTENT_OPERATION_ROUTINE;

	this->operationProcessor = new OperationProcessor((void *)this, NUMBER_OF_OPERATIONS, operations, operationFunctions);
}
NetworkPacketAnalyzer::~NetworkPacketAnalyzer()
{
	pcap_close(this->adapterHandle);
}

void NetworkPacketAnalyzer::Run(int numberOfPackets, char * formatString, char * filterString)
{
	for (int i = 0; (numberOfPackets) ? i < numberOfPackets : true; i++)
	{
		this->packet = NULL;
		pcap_next_ex(this->adapterHandle, &this->header, (const u_char **)&this->packet);

		if (this->packet)
		{
			time_t rawtime;

			time(&rawtime);
			this->timeInfo = localtime(&rawtime);

			this->bETH = false; this->ethernet.Clear();
			this->bARP = false; this->arp.Clear();
			this->bIPv4 = false; this->ipv4.Clear();
			this->bIPv6 = false; this->ipv6.Clear();
			this->bTCP = false; this->tcp.Clear();
			this->bUDP = false; this->udp.Clear();

			this->startingPoint = 0;

			this->ethernet.Assign((void *)this->packet);
			this->bETH = true;
			this->startingPoint += sizeof(EthernetHeader);

			switch (this->ethernet.Type)
			{
			case ETHERNET_ARP:
				this->arp.Assign((void *)(this->packet + this->startingPoint));
				this->bARP = true;
				this->startingPoint += sizeof(ARPHeader);
				break;
			case ETHERNET_IPV4:
				this->ipv4.Assign((void *)(this->packet + this->startingPoint));
				this->bIPv4 = true;
				this->startingPoint += sizeof(IPV4Header);
				switch (this->ipv4.NextProtocol)
				{
				case IPV4_TCP:
					this->tcp.Assign((void *)(this->packet + this->startingPoint));
					this->bTCP = true;
					this->startingPoint += sizeof(TCPHeader);
					break;
				case IPV4_UDP:
					this->udp.Assign((void *)(this->packet + this->startingPoint));
					this->bUDP = true;
					this->startingPoint += sizeof(UDPHeader);
					break;
				}
				break;
			case ETHERNET_IPV6:
				this->ipv6.Assign((void *)(this->packet + this->startingPoint));
				this->bIPv6 = true;
				this->startingPoint += sizeof(IPV6Header);
				switch (this->ipv6.NextProtocol)
				{
				case IPV6_TCP:
					this->tcp.Assign((void *)(this->packet + this->startingPoint));
					this->bTCP = true;
					this->startingPoint += sizeof(TCPHeader);
					break;
				case IPV6_UDP:
					this->udp.Assign((void *)(this->packet + this->startingPoint));
					this->bUDP = true;
					this->startingPoint += sizeof(UDPHeader);
					break;
				}
				break;
			}
			char * filter = this->operationProcessor->Resolve(filterString);
			if (filter[0] == '1')
			{
				char * outputString = this->operationProcessor->Resolve(formatString);
				printf("%s", outputString);
				free(outputString);
			}
			free(filter);
		}
	}
}

void NetworkPacketAnalyzer::GENERAL_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = -1;
	while (operationNode->Operation[++length] != '\0');

	operationNode->Output = (char *)malloc(length + 1);

	for (int i = 0; i <= length; i++)
		operationNode->Output[i] = operationNode->Operation[i];
}

void NetworkPacketAnalyzer::IF_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (operationNode->Parameters[0][0] == '0')
	{
		operationNode->Output = (char *)malloc(1 * sizeof(char));
		operationNode->Output[0] = '\0';
		operationNode->NextOperation->Free();
		free(operationNode->NextOperation);
		operationNode->NextOperation = NULL;
	}
}
void NetworkPacketAnalyzer::EQUALS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 1; i < operationNode->NumberOfParameters; i++)
		if (strcmp(operationNode->Parameters[i], operationNode->Parameters[0]))
		{
			operationNode->Output[0] = '0';
			operationNode->Output[1] = '\0';
			return;
		}
	operationNode->Output[0] = '1';
	operationNode->Output[1] = '\0';
}
void NetworkPacketAnalyzer::NOT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	if (operationNode->Parameters[0][0] == '1')
		operationNode->Output[0] = '0';
	else
		operationNode->Output[0] = '1';
	operationNode->Output[1] = '\0';
}
void NetworkPacketAnalyzer::OR_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 0; i < operationNode->NumberOfParameters; i++)
		if (operationNode->Parameters[i][0] == '1')
		{
			operationNode->Output[0] = '1';
			operationNode->Output[1] = '\0';
			return;
		}
	operationNode->Output[0] = '0';
	operationNode->Output[1] = '\0';
}
void NetworkPacketAnalyzer::AND_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	for (int i = 0; i < operationNode->NumberOfParameters; i++)
		if (operationNode->Parameters[i][0] == '0')
		{
			operationNode->Output[0] = '0';
			operationNode->Output[1] = '\0';
			return;
		}
	operationNode->Output[0] = '1';
	operationNode->Output[1] = '\0';
}
void NetworkPacketAnalyzer::ODD_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	int count = 0;
	for (int i = 0; i < operationNode->NumberOfParameters; i++)
		if (operationNode->Parameters[i]) count++;

	if (count % 2)
		operationNode->Output[0] = '1';
	else
		operationNode->Output[0] = '0';
	operationNode->Output[1] = '\0';
}
void NetworkPacketAnalyzer::XOR_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(2 * sizeof(char));

	int count = 0;
	for (int i = 0; i < operationNode->NumberOfParameters; i++)
		if (operationNode->Parameters[i]) count++;

	if (count == 1)
		operationNode->Output[0] = '1';
	else
		operationNode->Output[0] = '0';
	operationNode->Output[1] = '\0';
}

void NetworkPacketAnalyzer::LEADING_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	unsigned int spaces = StringToInteger(operationNode->Parameters[1]);
	operationNode->Output = (char *)malloc(spaces + 1);

	int length = -1;
	while (input[++length] != '\0');

	unsigned int i = 0;
	for (i; i < spaces - length; i++)
		operationNode->Output[i] = operationNode->Parameters[0][0];
	for (i; i < spaces; i++)
		operationNode->Output[i] = input[i - (spaces - length)];

	operationNode->Output[i] = '\0';
}
void NetworkPacketAnalyzer::TRAILING_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	unsigned int spaces = StringToInteger(operationNode->Parameters[1]);
	operationNode->Output = (char *)malloc(spaces + 1);

	int length = -1;
	while (input[++length] != '\0');

	int i = 0;
	for (i; i < length; i++)
		operationNode->Output[i] = input[i];
	for (i; i < (int)spaces; i++)
		operationNode->Output[i] = operationNode->Parameters[0][0];

	operationNode->Output[i] = '\0';
}

void NetworkPacketAnalyzer::HOUR_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->timeInfo->tm_hour);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->timeInfo->tm_hour);
}
void NetworkPacketAnalyzer::MINUTE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->timeInfo->tm_min);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->timeInfo->tm_min);


}
void NetworkPacketAnalyzer::SECOND_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->timeInfo->tm_sec);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->timeInfo->tm_sec);


}

void NetworkPacketAnalyzer::ETHERNET_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bETH)
	{
		operationNode->Output = (char *)malloc(109);

		sprintf(operationNode->Output, "|-Ethernet:\n| |-DestinationAddress: %02x-%02x-%02x-%02x-%02x-%02x\n| |-SourceAddress: %02x-%02x-%02x-%02x-%02x-%02x\n| `-Type: 0x%04x\n", ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[3], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[4], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[5], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[3], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[4], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[5], ((NetworkPacketAnalyzer*)_this)->ethernet.Type);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::ETHERNET_DESTINATION_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(18);

	sprintf(operationNode->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[3], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[4], ((NetworkPacketAnalyzer*)_this)->ethernet.DestinationAddress[5]);
}
void NetworkPacketAnalyzer::ETHERNET_SOURCE_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(18);

	sprintf(operationNode->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[3], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[4], ((NetworkPacketAnalyzer*)_this)->ethernet.SourceAddress[5]);
}
void NetworkPacketAnalyzer::ETHERNET_TYPE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ethernet.Type);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ethernet.Type);

}

void NetworkPacketAnalyzer::ARP_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bARP)
	{
		operationNode->Output = (char *)malloc(297);

		sprintf(operationNode->Output, "|-ARP:\n| |-HardwareType: 0x%04x\n| |-ProtocolType: 0x%04x\n| |-HardwareAddressLength: 0x%02x\n| |-ProtocolAddressLength: 0x%02x\n| |-Opcode: 0x%04x\n| |-SenderMACAddress: %02x-%02x-%02x-%02x-%02x-%02x\n| |-SenderIPv4Addres: %03d.%03d.%03d.%03d\n| |-TargetMACAddress: %02x-%02x-%02x-%02x-%02x-%02x\n| `-TargetIPv4Addres: %03d.%03d.%03d.%03d\n", ((NetworkPacketAnalyzer*)_this)->arp.HardwareType, ((NetworkPacketAnalyzer*)_this)->arp.ProtocolType, ((NetworkPacketAnalyzer*)_this)->arp.HardwareAddressLen, ((NetworkPacketAnalyzer*)_this)->arp.ProtocolAddressLen, ((NetworkPacketAnalyzer*)_this)->arp.OpCode, ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[0], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[1], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[2], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[3], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[4], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[5], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[0], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[1], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[2], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[3], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[0], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[1], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[2], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[3], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[4], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[5], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[0], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[1], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[2], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[3]);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}

}
void NetworkPacketAnalyzer::ARP_HARDWARE_TYPE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->arp.HardwareType);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->arp.HardwareType);

}
void NetworkPacketAnalyzer::ARP_PROTOCOL_TYPE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->arp.ProtocolType);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->arp.ProtocolType);

}
void NetworkPacketAnalyzer::ARP_HARDWARE_ADDRESS_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->arp.HardwareAddressLen);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->arp.HardwareAddressLen);

}
void NetworkPacketAnalyzer::ARP_PROTOCOL_ADDRESS_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->arp.ProtocolAddressLen);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->arp.ProtocolAddressLen);

}
void NetworkPacketAnalyzer::ARP_OPERATION_CODE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->arp.OpCode);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->arp.OpCode);

}
void NetworkPacketAnalyzer::ARP_SENDER_MAC_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(18);

	sprintf(operationNode->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[0], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[1], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[2], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[3], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[4], ((NetworkPacketAnalyzer*)_this)->arp.SenderMACAddress[5]);

}
void NetworkPacketAnalyzer::ARP_SENDER_IPV4_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(16);

	sprintf(operationNode->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[0], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[1], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[2], ((NetworkPacketAnalyzer*)_this)->arp.SenderIPv4Address[3]);

}
void NetworkPacketAnalyzer::ARP_TARGET_MAC_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(18);

	sprintf(operationNode->Output, "%02x-%02x-%02x-%02x-%02x-%02x", ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[0], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[1], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[2], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[3], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[4], ((NetworkPacketAnalyzer*)_this)->arp.TargetMACAddress[5]);

}
void NetworkPacketAnalyzer::ARP_TARGET_IPV4_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(16);

	sprintf(operationNode->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[0], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[1], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[2], ((NetworkPacketAnalyzer*)_this)->arp.TargetIPv4Address[3]);

}

void NetworkPacketAnalyzer::IPV4_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bIPv4)
	{
		operationNode->Output = (char *)malloc(421);

		sprintf(operationNode->Output, "|-IPv4:\n| |-Versions: 0x%02x\n| | |-Version: 0x%01x\n| | `-HeaderLength: 0x%01x\n| |-DifferentiatedServicesField: 0x%02x\n| | |-DSCP: 0x%02x\n| | |-ECT: 0x%01x\n| | `-CE: 0x%01x\n| |-TotalLength: 0x%04x\n| |-Identification: 0x%04x\n| |-FragmentFlags: 0x%04x\n| | |-DF: 0x%01x\n| | |-MF: 0x%01x\n| | `-Offset: 0x%04x\n| |-TimeToLive: 0x%02x\n| |-NextProtocol: 0x%02x\n| |-Checksum: 0x%04x\n| |-SourceAddress: %03d.%03d.%03d.%03d\n| `-DestinationAddress: %03d.%03d.%03d.%03d\n", ((NetworkPacketAnalyzer*)_this)->ipv4.Versions, (((NetworkPacketAnalyzer*)_this)->ipv4.Versions >> 4) & 0xF, ((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0xF, ((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField, (((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 2) & 0x3F, (((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 1) & 0x1, ((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField & 0x1, ((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength, ((NetworkPacketAnalyzer*)_this)->ipv4.Identification, ((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags, (((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 14) & 0x1, (((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 13) & 0x1, ((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags & 0x1FFF, ((NetworkPacketAnalyzer*)_this)->ipv4.TimeToLive, ((NetworkPacketAnalyzer*)_this)->ipv4.NextProtocol, ((NetworkPacketAnalyzer*)_this)->ipv4.Checksum, ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[3], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[3]);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::IPV4_VERSIONS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.Versions);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.Versions);

}
void NetworkPacketAnalyzer::IPV4_VERSIONS_VERSION_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv4.Versions >> 4) & 0XF);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv4.Versions >> 4) & 0xF);

}
void NetworkPacketAnalyzer::IPV4_VERSIONS_HEADER_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0xF);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0xF);

}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField);

}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_DSCP_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 2) & 0x3F);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 2) & 0x3F);

}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_ECT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 1) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField >> 1) & 0x1);

}
void NetworkPacketAnalyzer::IPV4_DIFFERENTIATED_SERVICES_FIELD_CE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.DifferentiatedServicesField & 0x1);

}
void NetworkPacketAnalyzer::IPV4_TOTAL_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength);

}
void NetworkPacketAnalyzer::IPV4_IDENTIFICATION_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.Identification);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.Identification);

}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags);

}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_DF_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 14) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 14) & 0x1);

}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_MF_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 13) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags >> 13) & 0x1);

}
void NetworkPacketAnalyzer::IPV4_FRAGMENT_FLAGS_OFFSET_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags & 0x1FFF);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.FragmentFlags & 0x1FFF);

}
void NetworkPacketAnalyzer::IPV4_TIME_TO_LIVE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.TimeToLive);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.TimeToLive);

}
void NetworkPacketAnalyzer::IPV4_NEXT_PROTOCOL_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.NextProtocol);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.NextProtocol);

}
void NetworkPacketAnalyzer::IPV4_CHECKSUM_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.Checksum);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.Checksum);

}
void NetworkPacketAnalyzer::IPV4_SOURCE_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(16 * sizeof(char));

	sprintf(operationNode->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv4.SourceAddress[3]);


}
void NetworkPacketAnalyzer::IPV4_DESTINATION_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(16 * sizeof(char));

	sprintf(operationNode->Output, "%03d.%03d.%03d.%03d", ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv4.DestinationAddress[3]);


}

void NetworkPacketAnalyzer::IPV6_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bIPv6)
	{
		operationNode->Output = (char *)malloc(315);

		sprintf(operationNode->Output, "|-IPv6:\n| |-Versions: 0x%08x\n| | |-Version: 0x%01x\n| | |-DSCP: 0x%02x\n| | |-ECT: 0x%01x\n| | |-CE: 0x%01x\n| | `-FlowLabel: 0x%05x\n| |-PayloadLength: 0x%04x\n| |-NextProtocol: 0x%02x\n| |-HopLimit: 0x%02x\n| |-SourceAddress: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n| `-DestinationAddress: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", ((NetworkPacketAnalyzer*)_this)->ipv6.Versions, (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 28) & 0xF, (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 22) & 0x3F, (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 21) & 0x1, (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 20) & 0x1, ((NetworkPacketAnalyzer*)_this)->ipv6.Versions & 0xFFFFF, ((NetworkPacketAnalyzer*)_this)->ipv6.PayloadLength, ((NetworkPacketAnalyzer*)_this)->ipv6.NextProtocol, ((NetworkPacketAnalyzer*)_this)->ipv6.HopLimit, ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[3], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[4], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[5], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[6], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[7], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[3], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[4], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[5], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[6], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[7]);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::IPV6_VERSIONS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv6.Versions);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv6.Versions);

}
void NetworkPacketAnalyzer::IPV6_VERSIONS_VERSION_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 28) & 0xF);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 28) & 0xF);

}
void NetworkPacketAnalyzer::IPV6_VERSIONS_DSCP_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 22) & 0x3F);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 22) & 0x3F);

}
void NetworkPacketAnalyzer::IPV6_VERSIONS_ECT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 21) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 21) & 0x1);

}
void NetworkPacketAnalyzer::IPV6_VERSIONS_CE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 20) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->ipv6.Versions >> 20) & 0x1);

}
void NetworkPacketAnalyzer::IPV6_VERISONS_FLOW_LABEL_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv6.Versions & 0xFFFFF);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv6.Versions & 0xFFFFF);

}
void NetworkPacketAnalyzer::IPV6_PAYLOAD_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv6.PayloadLength);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv6.PayloadLength);

}
void NetworkPacketAnalyzer::IPV6_NEXT_PROTOCOL_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv6.NextProtocol);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv6.NextProtocol);

}
void NetworkPacketAnalyzer::IPV6_HOP_LIMIT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv6.HopLimit);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv6.HopLimit);

}
void NetworkPacketAnalyzer::IPV6_SOURCE_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(40);

	sprintf(operationNode->Output, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[3], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[4], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[5], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[6], ((NetworkPacketAnalyzer*)_this)->ipv6.SourceAddress[7]);

}
void NetworkPacketAnalyzer::IPV6_DESTINATION_ADDRESS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	operationNode->Output = (char *)malloc(40);

	sprintf(operationNode->Output, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[0], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[1], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[2], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[3], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[4], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[5], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[6], ((NetworkPacketAnalyzer*)_this)->ipv6.DestinationAddress[7]);

}

void NetworkPacketAnalyzer::TCP_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bTCP)
	{
		operationNode->Output = (char *)malloc(350);

		sprintf(operationNode->Output, "|-TCP:\n| |-SourcePort: 0x%02x\n| |-DestinationPort: 0x%02x\n| |-SeqeunceNumber: 0x%08x\n| |-AcknowledgementNumber: 0x%08x\n| |-DataOffset: 0x%02x\n| |-Flags: 0x%02x\n| | |-FIN: 0x%01x\n| | |-SYN: 0x%01x\n| | |-RST: 0x%01x\n| | |-PSH: 0x%01x\n| | |-ACK: 0x%01x\n| | |-URG: 0x%01x\n| | |-ECE: 0x%01x\n| | `-CWR: 0x%01x\n| |-Window: 0x%04x\n| |-Checksum: 0x%04x\n| `-UrgentPointer: 0x%04x\n", ((NetworkPacketAnalyzer*)_this)->tcp.SourcePort, ((NetworkPacketAnalyzer*)_this)->tcp.DestinationPort, ((NetworkPacketAnalyzer*)_this)->tcp.SequenceNumber, ((NetworkPacketAnalyzer*)_this)->tcp.AcknowledgementNumber, ((NetworkPacketAnalyzer*)_this)->tcp.DataOffset, ((NetworkPacketAnalyzer*)_this)->tcp.Flags, ((NetworkPacketAnalyzer*)_this)->tcp.Flags & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 1) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 2) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 3) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 4) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 5) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 6) & 0x1, (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 7) & 0x1, ((NetworkPacketAnalyzer*)_this)->tcp.Window, ((NetworkPacketAnalyzer*)_this)->tcp.Checksum, ((NetworkPacketAnalyzer*)_this)->tcp.UrgentPointer);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::TCP_SOURCE_PORT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.SourcePort);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->tcp.SourcePort);


}
void NetworkPacketAnalyzer::TCP_DESTINATION_PORT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.DestinationPort);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->tcp.DestinationPort);


}
void NetworkPacketAnalyzer::TCP_PAYLOAD_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength - ((((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0x0F) * 4) - (((((NetworkPacketAnalyzer*)_this)->tcp.DataOffset >> 4) & 0x0F) * 4));

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength - ((((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0x0F) * 4) - (((((NetworkPacketAnalyzer*)_this)->tcp.DataOffset >> 4) & 0x0F) * 4));


}
void NetworkPacketAnalyzer::TCP_ACKNOWLEDGEMENT_NUMBER_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.AcknowledgementNumber);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.AcknowledgementNumber);


}
void NetworkPacketAnalyzer::TCP_SEQUENCE_NUMBER_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.SequenceNumber);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.SequenceNumber);


}
void NetworkPacketAnalyzer::TCP_DATA_OFFSET_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.DataOffset);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.DataOffset);

}
void NetworkPacketAnalyzer::TCP_FLAGS_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.Flags);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.Flags);

}
void NetworkPacketAnalyzer::TCP_FLAGS_FIN_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.Flags & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", ((NetworkPacketAnalyzer*)_this)->tcp.Flags & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_SYN_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 1) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 1) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_RST_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 2) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 2) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_PSH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 3) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 3) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_ACK_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 4) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 4) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_URG_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 5) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 5) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_ECE_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 6) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 6) & 0x1);


}
void NetworkPacketAnalyzer::TCP_FLAGS_CWR_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength((((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 7) & 0x1);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%d", (((NetworkPacketAnalyzer*)_this)->tcp.Flags >> 7) & 0x1);


}
void NetworkPacketAnalyzer::TCP_WINDOW_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.Window);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.Window);

}
void NetworkPacketAnalyzer::TCP_CHECKSUM_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.Checksum);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.Checksum);

}
void NetworkPacketAnalyzer::TCP_URGENT_POINTER_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->tcp.UrgentPointer);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->tcp.UrgentPointer);

}

void NetworkPacketAnalyzer::UDP_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	if (((NetworkPacketAnalyzer*)_this)->bUDP)
	{
		operationNode->Output = (char *)malloc(98);

		sprintf(operationNode->Output, "|-UDP:\n| |-SourcePort: 0x%02x\n| |-DestinationPort: 0x%02x\n| |-Length: 0x%02x\n| `-Checksum: 0x%02x\n", ((NetworkPacketAnalyzer*)_this)->udp.SourcePort, ((NetworkPacketAnalyzer*)_this)->udp.DestinationPort, ((NetworkPacketAnalyzer*)_this)->udp.Length, ((NetworkPacketAnalyzer*)_this)->udp.Checksum);
	}
	else
	{
		operationNode->Output = (char *)malloc(2);
		operationNode->Output[0] = '0';
		operationNode->Output[1] = '\0';
	}
}
void NetworkPacketAnalyzer::UDP_SOURCE_PORT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->udp.SourcePort);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->udp.SourcePort);

}
void NetworkPacketAnalyzer::UDP_DESTINATION_PORT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->udp.DestinationPort);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->udp.DestinationPort);

}
void NetworkPacketAnalyzer::UDP_LENGTH_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->udp.Length);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->udp.Length);

}
void NetworkPacketAnalyzer::UDP_CHECKSUM_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int length = 1;
	length += IntegerLength(((NetworkPacketAnalyzer*)_this)->udp.Checksum);

	operationNode->Output = (char *)malloc(length);

	sprintf(operationNode->Output, "%u", ((NetworkPacketAnalyzer*)_this)->udp.Checksum);

}

void NetworkPacketAnalyzer::CONTENT_OPERATION_ROUTINE(void * _this, OperationNode * operationNode, char * input)
{
	int contentLength = 0;

	if (((NetworkPacketAnalyzer*)_this)->bTCP)
	{
		contentLength = ((NetworkPacketAnalyzer*)_this)->ipv4.TotalLength - (((((NetworkPacketAnalyzer*)_this)->tcp.DataOffset >> 4) & 0x0F) * 4) - ((((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0xF) * 4);
		((NetworkPacketAnalyzer*)_this)->startingPoint = (((((NetworkPacketAnalyzer*)_this)->tcp.DataOffset >> 4) & 0x0F) * 4) + ((((NetworkPacketAnalyzer*)_this)->ipv4.Versions & 0xF) * 4) + 14;
	}
	else
		contentLength = ((NetworkPacketAnalyzer*)_this)->header->len - ((NetworkPacketAnalyzer*)_this)->startingPoint;

	int numberOfLines = (int)(contentLength) / 16;
	if ((int)(contentLength) % 16 != 0)
		numberOfLines++;

	operationNode->Output = (char *)malloc(15 + numberOfLines * 83);

	int currentIndex = 0;

	sprintf(&operationNode->Output[currentIndex], "|-Content:\n"); currentIndex += 11;

	for (int i = 0; i < (numberOfLines * 16); i++)
	{
		if (i % 16 == 0)
		{
			if ((i / 16) == (numberOfLines - 1))
			{	sprintf(&operationNode->Output[currentIndex], "| `-0x%08x  ", i + ((NetworkPacketAnalyzer*)_this)->startingPoint); currentIndex += 16;	}
			else
			{	sprintf(&operationNode->Output[currentIndex], "| |-0x%08x  ", i + ((NetworkPacketAnalyzer*)_this)->startingPoint); currentIndex += 16;	}
		}
		if ((i + 1) % 16 == 0)
		{
			if (i < (int)(((NetworkPacketAnalyzer*)_this)->header->len - ((NetworkPacketAnalyzer*)_this)->startingPoint))
			{	sprintf(&operationNode->Output[currentIndex], "%02x  ", ((NetworkPacketAnalyzer*)_this)->packet[i + ((NetworkPacketAnalyzer*)_this)->startingPoint]); currentIndex += 4;	}
			else
			{	sprintf(&operationNode->Output[currentIndex], "    "); currentIndex += 4;	}
			for (int j = (i + 1) - 16; j < (i + 1); j++)
				if (j < (int)(((NetworkPacketAnalyzer*)_this)->header->len - ((NetworkPacketAnalyzer*)_this)->startingPoint))
					if (((NetworkPacketAnalyzer*)_this)->packet[j + ((NetworkPacketAnalyzer*)_this)->startingPoint] > 32 && ((NetworkPacketAnalyzer*)_this)->packet[j + ((NetworkPacketAnalyzer*)_this)->startingPoint] < 127)
						sprintf(&operationNode->Output[currentIndex++], "%c", ((NetworkPacketAnalyzer*)_this)->packet[j + ((NetworkPacketAnalyzer*)_this)->startingPoint]);
					else
						sprintf(&operationNode->Output[currentIndex++], ".");
				else
					sprintf(&operationNode->Output[currentIndex++], " ");
			sprintf(&operationNode->Output[currentIndex++], "\n");
		}
		else if ((i + 1) % 8 == 0)
			if (i < (int)(((NetworkPacketAnalyzer*)_this)->header->len - ((NetworkPacketAnalyzer*)_this)->startingPoint))
			{	sprintf(&operationNode->Output[currentIndex], "%02x  ", ((NetworkPacketAnalyzer*)_this)->packet[i + ((NetworkPacketAnalyzer*)_this)->startingPoint]); currentIndex += 4;	}
			else
			{	sprintf(&operationNode->Output[currentIndex], "    "); currentIndex += 4;	}
		else if (i < (int)(((NetworkPacketAnalyzer*)_this)->header->len - ((NetworkPacketAnalyzer*)_this)->startingPoint))
		{	sprintf(&operationNode->Output[currentIndex], "%02x ", ((NetworkPacketAnalyzer*)_this)->packet[i + ((NetworkPacketAnalyzer*)_this)->startingPoint]); currentIndex += 3;	}
		else
		{	sprintf(&operationNode->Output[currentIndex], "   "); currentIndex += 3;}
	}
	sprintf(&operationNode->Output[currentIndex], "`-\n");
}

#endif