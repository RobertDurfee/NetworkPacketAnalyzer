#ifndef FORMAT_STRING_PROCESSOR_HEADER
#define FORMAT_STRING_PROCESSOR_HEADER

#include <string.h> //strcmp()
#include <stdlib.h> //malloc(), free()

class FormatTag
{
public:
	void Free()
	{
		if (this->Specifier)
			free(this->Specifier);
		if (this->NumberOfParameters)
		{
			for (int i = 0; i < this->NumberOfParameters; i++)
				free(this->Parameters[i]);
			free(this->Parameters);
		}
		if (this->NextFormatTag)
		{
			this->NextFormatTag->Free();
			free(this->NextFormatTag);
		}
		if (this->Output)
			free(this->Output);
	}
	char * Specifier;
	int SpecifierConstant;
	int NumberOfParameters;
	char ** Parameters;
	char * Output;
	FormatTag * NextFormatTag;
};

class FormatStringProcessor
{
public:
	FormatStringProcessor(void * definedTagFunctionsClass, int numberOfDefinedTags, char ** definedTags, void(**definedTagFunctions)(void * definedTagFunctionsClass, FormatTag * formatTag, char * tagFunctionInput));
	char * Resolve(char * formatString);

private:
	void * DefinedTagFunctionsClass;
	int NumberOfDefinedTags;
	char ** DefinedTags;
	void (**DefinedTagFunctions)(void *, FormatTag *, char *);

	int CountTags(char * formatString);
	char * GetTag(int tagIndex, char * formatString);
	void LocationOfTag(int tagIndex, char * formatString, int * begin, int * end);
	char * EvaluateTag(FormatTag * formatTag, char * tagFunctionInput);
	FormatTag * ParseTag(char ** tag);
	int LengthOfFormatStringWithoutTags(char * formatString);
	char * ReplaceTagsWithIndexes(char * formatString);
	void ReplaceTagIndexWithValue(int tagIndex, char ** formatString, char * valueString);
	char * CombineTags(char * firstTag, char * secondTag);
};

FormatStringProcessor::FormatStringProcessor(void * definedTagFunctionsClass, int numberOfDefinedTags, char ** definedTags, void(**definedTagFunctions)(void * definedTagFunctionsClass, FormatTag * formatTag, char * tagFunctionInput))
{
	DefinedTagFunctionsClass = definedTagFunctionsClass;
	NumberOfDefinedTags = numberOfDefinedTags;
	DefinedTags = definedTags;
	DefinedTagFunctions = definedTagFunctions;
}
char * FormatStringProcessor::Resolve(char * formatString)
{
	int numberOfTags = CountTags(formatString);

	FormatTag ** tags = (FormatTag **)malloc(numberOfTags * sizeof(FormatTag *));

	char * newFormatString = ReplaceTagsWithIndexes(formatString);

	for (int tagIndex = 1; tagIndex <= numberOfTags; tagIndex++)
	{
		char * tag = GetTag(tagIndex, formatString);
		tags[tagIndex - 1] = ParseTag(&tag);
		free(tag);
		ReplaceTagIndexWithValue(tagIndex, &newFormatString, EvaluateTag(tags[tagIndex - 1], NULL));
		tags[tagIndex - 1]->Free();
		free(tags[tagIndex - 1]);
	}

	free(tags);

	return newFormatString;
}
int FormatStringProcessor::CountTags(char * formatString)
{
	int brackets = 0, tags = 0, i = -1;
	while (formatString[++i] != '\0')
		if (formatString[i] == '{') brackets++;
		else if (formatString[i] == '}' && !--brackets) tags++;

	return tags;
}
char * FormatStringProcessor::GetTag(int tagIndex, char * formatString)
{
	int begin, end;

	this->LocationOfTag(tagIndex, formatString, &begin, &end);

	if (begin != -1 && end != -1)
	{
		char * tag = (char *)malloc(end - begin + 2);

		int i = 0;
		for (int j = begin; j <= end; j++)
			tag[i++] = formatString[j];

		tag[i] = '\0';

		return tag;
	}
	else
		return NULL;
}
void FormatStringProcessor::LocationOfTag(int tagIndex, char * formatString, int * begin, int * end)
{
	*begin = -1, *end = -1;

	int brackets = 0, parameters = 0, tags = 0, i = -1;
	while (formatString[++i] != '\0')
		if (formatString[i] == '{' && !parameters && !brackets++ && ++tags == tagIndex)
			*begin = i + 1;
		else if (formatString[i] == '}' && !parameters && !--brackets && tags == tagIndex)
		{
			*end = i - 1;
			return;
		}
		else if (formatString[i] == ':' && brackets)
			parameters++;
		else if (formatString[i] == ';' && brackets)
			parameters--;
}
FormatTag * FormatStringProcessor::ParseTag(char ** tag)
{
	FormatTag * formatTag = (FormatTag *)malloc(sizeof(FormatTag));

	int specifierLength = -1;
	while ((*tag)[++specifierLength] != '{' && (*tag)[specifierLength] != ':' && (*tag)[specifierLength] != ';' && (*tag)[specifierLength] != '\0');

	formatTag->Specifier = (char *)malloc(specifierLength + 1);
	int i = -1;
	while (++i < specifierLength)
		formatTag->Specifier[i] = (*tag)[i];

	formatTag->Specifier[specifierLength] = '\0';

	formatTag->SpecifierConstant = 0;
	for (int i = 1; i < NumberOfDefinedTags; i++)
		if (!strcmp(formatTag->Specifier, DefinedTags[i]))
		{
			formatTag->SpecifierConstant = i;
			break;
		}

	formatTag->Output = NULL;

	formatTag->NumberOfParameters = 0;

	if ((*tag)[specifierLength] == ':')
	{
		int i = specifierLength, brackets = 0;
		while ((*tag)[++i] != ';' || brackets)
			if ((*tag)[i] == ',' && !brackets) formatTag->NumberOfParameters++;
			else if ((*tag)[i] == '{') brackets++;
			else if ((*tag)[i] == '}') brackets--;
		formatTag->NumberOfParameters++;

		char oldCharater = (*tag)[i + 1];
		(*tag)[i + 1] = '\0';

		char * newTag = Resolve((*tag));

		(*tag)[i + 1] = oldCharater;
		char * oldTag = *tag;
		(*tag) = CombineTags(newTag, &(*tag)[i + 1]);
		free(newTag);
		free(oldTag);

		formatTag->Parameters = (char **)malloc(formatTag->NumberOfParameters * sizeof(char *));

		i = specifierLength;
		for (int j = 0; j < formatTag->NumberOfParameters; j++)
		{
			int parameterLength = 0;
			while ((*tag)[++i] != ',' && (*tag)[i] != ';') parameterLength++;
			formatTag->Parameters[j] = (char *)malloc(parameterLength + 1);
			int zero = i - parameterLength; i = i - parameterLength - 1;
			while ((*tag)[++i] != ',' && (*tag)[i] != ';')
				formatTag->Parameters[j][i - zero] = (*tag)[i];
			formatTag->Parameters[j][i - zero] = '\0';
		}
	}
	else
		formatTag->Parameters = NULL;

	char * newTag;
	if ((newTag = GetTag(1, (*tag))) != NULL)
	{
		formatTag->NextFormatTag = ParseTag(&newTag);
		free(newTag);
	}
	else
		formatTag->NextFormatTag = NULL;

	return formatTag;
}
char * FormatStringProcessor::EvaluateTag(FormatTag * formatTag, char * tagFunctionInput)
{
	(*DefinedTagFunctions[formatTag->SpecifierConstant])(DefinedTagFunctionsClass, formatTag, tagFunctionInput);
	if (formatTag->NextFormatTag)
		return EvaluateTag(formatTag->NextFormatTag, formatTag->Output);
	else
		return formatTag->Output;
}
int FormatStringProcessor::LengthOfFormatStringWithoutTags(char * formatString)
{
	int brackets = 0, i = -1, formatStringLength = 0;
	while (formatString[++i] != '\0')
	{
		if (formatString[i] == '{') brackets++;
		else if (formatString[i] == '}') brackets--;
		if (!brackets && formatString[i] != '}') formatStringLength++;
	}

	return formatStringLength + 1;
}
char * FormatStringProcessor::ReplaceTagsWithIndexes(char * formatString)
{
	int newFormatStringLength = LengthOfFormatStringWithoutTags(formatString) + CountTags(formatString) * 3;
	char * newFormatString = (char *)malloc(newFormatStringLength);

	int i = -1, begin, end, tagIndex = 0, j = 0;
	LocationOfTag(++tagIndex, formatString, &begin, &end);
	while (formatString[++i] != '\0')
	{
		if (i < begin - 1 || begin == -1)
			newFormatString[j++] = formatString[i];
		else if (i > end)
			LocationOfTag(++tagIndex, formatString, &begin, &end);
		else if (i == begin - 1)
		{
			newFormatString[j++] = '{';
			newFormatString[j++] = tagIndex;
			newFormatString[j++] = '}';
		}
	}

	newFormatString[j] = '\0';

	return newFormatString;
}
void FormatStringProcessor::ReplaceTagIndexWithValue(int tagIndex, char ** formatString, char * valueString)
{
	int lengthOfValueString = -1;
	while (valueString[++lengthOfValueString] != '\0');
	int lengthOfFormatString = -1;
	while ((*formatString)[++lengthOfFormatString] != '\0'); lengthOfFormatString++;

	char * newFormatString = (char *)malloc(lengthOfFormatString + lengthOfValueString - 3);

	int formatStringIndex = -1, newFormatStringIndex = -1;
	while (++formatStringIndex < lengthOfFormatString)
		if ((*formatString)[formatStringIndex] == '{' && (*formatString)[formatStringIndex + 1] == tagIndex && (*formatString)[formatStringIndex + 2] == '}')
		{
			formatStringIndex += 2;
			for (int valueStringIndex = 0; valueStringIndex < lengthOfValueString; valueStringIndex++)
				newFormatString[++newFormatStringIndex] = valueString[valueStringIndex];
		}
		else
			newFormatString[++newFormatStringIndex] = (*formatString)[formatStringIndex];

	free(*formatString);
	(*formatString) = newFormatString;
}
char * FormatStringProcessor::CombineTags(char * firstTag, char * lastTag)
{
	int firstTagLength = -1, lastTagLength = -1;
	while (firstTag[++firstTagLength] != '\0');
	while (lastTag[++lastTagLength] != '\0');

	char * newTag = (char *)malloc(firstTagLength + lastTagLength + 1);

	int i = -1, j = -1;
	while (firstTag[++j] != '\0')
		newTag[++i] = firstTag[j];
	j = -1;
	while (lastTag[++j] != '\0')
		newTag[++i] = lastTag[j];

	newTag[++i] = '\0';

	return newTag;
}

#endif