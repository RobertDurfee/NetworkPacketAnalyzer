#ifndef OPERATION_PROCESSOR_HEADER
#define OPERATION_PROCESSOR_HEADER

#include <string.h>
#include <stdlib.h>
#include <math.h>

struct OperationNode
{
	void Free()
	{
		if (this->Operation)
			free(this->Operation);
		if (this->NumberOfParameters)
		{
			for (int i = 0; i < this->NumberOfParameters; i++)
				free(this->Parameters[i]);
			free(this->Parameters);
		}
		if (this->NextOperation)
		{
			this->NextOperation->Free();
			free(this->NextOperation);
		}
		if (this->Output)
			free(this->Output);
	}
	char * Operation;
	int OperationConstant;
	int NumberOfParameters;
	char ** Parameters;
	char * Output;
	OperationNode * NextOperation;
};

class OperationProcessor
{
public:
	OperationProcessor(void *, int, char **, void(**operation_functions)(void *, OperationNode *, char *));
	char * Resolve(char *);

private:
	void * OperationFunctionsClass;
	int NumberOfOperations;
	char ** Operations;
	void (**OperationFunctions)(void *, OperationNode *, char *);

	int CountOperations(char *);
	char * GetOperation(int, char *);
	void IndexesOfOperation(int, char *, int *, int *);
	char * EvaluateOperation(OperationNode *, char *);
	OperationNode * ParseOperation(char **);
	int LengthOfFormatStringWithoutOperations(char *);
	char * ReplaceOperationKeywordsWithIndexes(char *);
	void ReplaceOperationIndexesWithValues(int, char **, char *);
	char * CombineOperators(char *, char *);
};

OperationProcessor::OperationProcessor(void * operationFunctionsClass, int number_of_operations, char ** operations, void(** operation_functions)(void *, OperationNode *, char *))
{
	this->NumberOfOperations = number_of_operations;
	this->OperationFunctionsClass = operationFunctionsClass;
	this->Operations = operations;
	this->OperationFunctions = operation_functions;
}
char * OperationProcessor::Resolve(char * formatString)
{
	int numberOfOperations = this->CountOperations(formatString);

	OperationNode ** operations = (OperationNode **)malloc(numberOfOperations * sizeof(OperationNode *));

	char * newFormatString = this->ReplaceOperationKeywordsWithIndexes(formatString);

	for (int i = 1; i <= numberOfOperations; i++)
	{
		char * operation = this->GetOperation(i, formatString);
		operations[i - 1] = this->ParseOperation(&operation);
		free(operation);
		this->ReplaceOperationIndexesWithValues(i, &newFormatString, this->EvaluateOperation(operations[i - 1], NULL));
		operations[i - 1]->Free();
		free(operations[i - 1]);
	}

	free(operations);

	return newFormatString;
}
int OperationProcessor::CountOperations(char * input)
{
	int brackets = 0, operations = 0, i = -1;
	while (input[++i] != '\0')
		if (input[i] == '{') brackets++;
		else if (input[i] == '}' && !--brackets) operations++;

		return operations;
}
char * OperationProcessor::GetOperation(int operation, char * input)
{
	int begin, end;

	this->IndexesOfOperation(operation, input, &begin, &end);

	if (begin != -1 && end != -1)
	{
		char * output = (char *)malloc(end - begin + 2);

		int i = 0;
		for (int j = begin; j <= end; j++)
			output[i++] = input[j];

		output[i] = '\0';

		return output;
	}
	else
		return NULL;
}
void OperationProcessor::IndexesOfOperation(int operation, char * input, int * begin, int * end)
{
	*begin = -1, *end = -1;

	int brackets = 0, parameters = 0, operations = 0, i = -1;
	while (input[++i] != '\0')
		if (input[i] == '{' && !parameters && !brackets++ && ++operations == operation)
			*begin = i + 1;
		else if (input[i] == '}' && !parameters && !--brackets && operations == operation)
		{
			*end = i - 1;
			return;
		}
		else if (input[i] == ':' && brackets)
			parameters++;
		else if (input[i] == ';' && brackets)
			parameters--;
}
OperationNode * OperationProcessor::ParseOperation(char ** operation)
{
	OperationNode * output = (OperationNode *)malloc(sizeof(OperationNode));

	int length = -1;
	while ((*operation)[++length] != '{' && (*operation)[length] != ':' && (*operation)[length] != ';' && (*operation)[length] != '\0');

	output->Operation = (char *)malloc(length + 1);
	int i = -1;
	while (++i < length)
		output->Operation[i] = (*operation)[i];

	output->Operation[length] = '\0';

	output->OperationConstant = 0;
	for (int i = 1; i < this->NumberOfOperations; i++)
		if (!strcmp(output->Operation, this->Operations[i]))
		{
			output->OperationConstant = i;
			break;
		}

	output->Output = NULL;

	output->NumberOfParameters = 0;

	if ((*operation)[length] == ':')
	{
		int i = length, brackets = 0;
		while ((*operation)[++i] != ';' || brackets)
			if ((*operation)[i] == ',' && !brackets) output->NumberOfParameters++;
			else if ((*operation)[i] == '{') brackets++;
			else if ((*operation)[i] == '}') brackets--;
		output->NumberOfParameters++;

		char oldCharater = (*operation)[i + 1];
		(*operation)[i + 1] = '\0';

		char * newOp = this->Resolve((*operation));

		(*operation)[i + 1] = oldCharater;
		char * oldOp = (*operation);
		(*operation) = CombineOperators(newOp, &(*operation)[i + 1]);
		free(newOp);
		free(oldOp);

		output->Parameters = (char **)malloc(output->NumberOfParameters * sizeof(char *));

		i = length;
		for (int j = 0; j < output->NumberOfParameters; j++)
		{
			int parameterLength = 0;
			while ((*operation)[++i] != ',' && (*operation)[i] != ';') parameterLength++;
			output->Parameters[j] = (char *)malloc(parameterLength + 1);
			int zero = i - parameterLength; i = i - parameterLength - 1;
			while ((*operation)[++i] != ',' && (*operation)[i] != ';')
				output->Parameters[j][i - zero] = (*operation)[i];
			output->Parameters[j][i - zero] = '\0';
		}
	}
	else
		output->Parameters = NULL;

	char * newOperation;
	if ((newOperation = this->GetOperation(1, (*operation))) != NULL)
	{
		output->NextOperation = this->ParseOperation(&newOperation);
		free(newOperation);
	}
	else
		output->NextOperation = NULL;

	return output;
}
char * OperationProcessor::EvaluateOperation(OperationNode * operation, char * input)
{
	(*this->OperationFunctions[operation->OperationConstant])(this->OperationFunctionsClass, operation, input);
	if (operation->NextOperation)
		return this->EvaluateOperation(operation->NextOperation, operation->Output);
	else
		return operation->Output;
}
int OperationProcessor::LengthOfFormatStringWithoutOperations(char * input)
{
	int brackets = 0, i = -1, length = 0;
	while (input[++i] != '\0')
	{
		if (input[i] == '{') brackets++;
		else if (input[i] == '}') brackets--;
		if (!brackets && input[i] != '}') length++;
	}

	return length + 1;
}
char * OperationProcessor::ReplaceOperationKeywordsWithIndexes(char * input)
{
	int newLength = this->LengthOfFormatStringWithoutOperations(input) + this->CountOperations(input) * 3;
	char * output = (char *)malloc(newLength);

	int i = -1, begin, end, operation = 0, j = 0;
	this->IndexesOfOperation(++operation, input, &begin, &end);
	while (input[++i] != '\0')
	{
		if (i < begin - 1 || begin == -1)
			output[j++] = input[i];
		else if (i > end)
			this->IndexesOfOperation(++operation, input, &begin, &end);
		else if (i == begin - 1)
		{
			output[j++] = '{';
			output[j++] = operation;
			output[j++] = '}';
		}
	}

	output[j] = '\0';

	return output;
}
void OperationProcessor::ReplaceOperationIndexesWithValues(int operation, char ** formatString, char * insert)
{
	int lengthOfInsert = -1;
	while (insert[++lengthOfInsert] != '\0');
	int lengthOfFormat = -1;
	while ((*formatString)[++lengthOfFormat] != '\0'); lengthOfFormat++;

	char * output = (char *)malloc(lengthOfFormat + lengthOfInsert - 3);

	int formatStringIndex = -1, outputIndex = -1;
	while (++formatStringIndex < lengthOfFormat)
		if ((*formatString)[formatStringIndex] == '{' && (*formatString)[formatStringIndex + 1] == operation && (*formatString)[formatStringIndex + 2] == '}')
		{
			formatStringIndex += 2;
			for (int insertIndex = 0; insertIndex < lengthOfInsert; insertIndex++)
				output[++outputIndex] = insert[insertIndex];
		}
		else
			output[++outputIndex] = (*formatString)[formatStringIndex];

	free(*formatString);
	(*formatString) = output;
}
char * OperationProcessor::CombineOperators(char * first, char * last)
{
	int firstLength = -1, lastLength = -1;
	while (first[++firstLength] != '\0');
	while (last[++lastLength] != '\0');

	char * output = (char *)malloc(firstLength + lastLength + 1);

	int i = -1, j = -1;
	while (first[++j] != '\0')
		output[++i] = first[j];
	j = -1;
	while (last[++j] != '\0')
		output[++i] = last[j];

	output[++i] = '\0';

	return output;
}

#endif