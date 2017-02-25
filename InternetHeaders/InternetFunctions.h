#ifndef INTERNET_FUNCTIONS_HEADER
#define INTERNET_FUNCTIONS_HEADER

#include <stdio.h> //_vsprintf_l(), va_list, __crt_va_start(), __crt_va_end()

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
	__crt_va_start(argumentList, format);

	#pragma warning(push)
	#pragma warning(disable: 4996) // Deprecation
	int result = _vsprintf_l(&buffer[*index], format, NULL, argumentList);
	#pragma warning(pop)

	*index += result;

	__crt_va_end(argumentList);

	return result;
}

#endif