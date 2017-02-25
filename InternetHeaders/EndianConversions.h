#ifndef ENDIAN_CONVERSIONS_HEADER
#define ENDIAN_CONVERSIONS_HEADER

#include "InternetTypes.h"

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

#endif