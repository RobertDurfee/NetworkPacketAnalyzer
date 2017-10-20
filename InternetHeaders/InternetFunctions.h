#ifndef INTERNET_FUNCTIONS_HEADER
#define INTERNET_FUNCTIONS_HEADER

#include <stdio.h> //vsprintf()
#include <stdarg.h> //va_list, va_start(), va_end();

template<typename T>
T Select(void * source, int * index)
{
	int i = *index;

	*index += sizeof(T);

	return *(T *)&((char *)source)[i];
}

int sprintfi(char * buffer, int * index, char * format, ...)
{
	va_list argumentList;
	va_start(argumentList, format);

	int result = vsprintf(&buffer[*index], format, argumentList);

	*index += result;

	va_end(argumentList);

	return result;
}

#endif
