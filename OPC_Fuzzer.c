#include "Opc_Fuzzer.h"

HANDLE handshakeThread = NULL;
HANDLE fuzzingThread = NULL;
DWORD dwThreadId = NULL;
DWORD recvThreadId = NULL;				//for the receiving thread
int connectionSet = false;
int canStartFuzz = false;
int alreadyInitialStarted = false;
long currentLen;

OPC_FUZZER_API int APIENTRY dll_run(char* data, long size, int begin)
{
	static WSADATA wsa;
	DWORD initialFuzzingThread;
	currentLen = size;
		
	/*if (size < 46)								//try to avoid crashes
	{
		//printf("Coming from here...\n");
		//sendMessageToServer(MSGF, "C:\\Users\\gpsap\\Desktop\\OPC_Fuzzing_Corpus\\Corpus\\browse.bin");		
		//return 1;
	}*/

	if (begin == 0)							//if it is the beginning of fuzzing 
	{
		initFields();

		Sleep(SOCKET_INIT_DELAY);			//wait for the server to start listening

		handshakeThread = CreateThread(NULL, 0, handshakeThreadEntryPoint, data, 0, &dwThreadId);

		return 1;
	}
	else if (canStartFuzz)
	{
		sendFuzzedInput(data, size);	
	}
	else if (!alreadyInitialStarted)
	{
		alreadyInitialStarted = true;
		fuzzingThread = CreateThread(NULL, 0, initialFuzzing, data, 0, &initialFuzzingThread);
	}
	else if (connectionSet)
	{
		sendInitialFuzzedInput(data);
	}

	if (begin == 100000)
	{
		freeFields();
	}

	return 1;
}

OPC_FUZZER_API int APIENTRY dll_init()
{
	return 1;
}

DWORD WINAPI handshakeThreadEntryPoint(LPVOID lpParameter)
{
	setupConnection();					//setup the connection and do the handshake with the server
	doOpcHandshake();
	connectionSet = true;
	sendFuzzedInput(lpParameter, currentLen);

	return 0;
}

DWORD WINAPI initialFuzzing(LPVOID buffer)
{
	Sleep(4000);				//give time to do the handshake
	if (connectionSet)
		sendInitialFuzzedInput(buffer);
	else
	{
		printf("Connection not set yet, increase wait time...\n");
		exit(1);
	}
	canStartFuzz = true;
}

void initFields()
{
	channelId = NULL;
	mustSetSeq = false;
	authenticationTokenId = NULL;
	canStartFuzz = false;
	alreadyInitialStarted = false;
	connectionSet = false;
	sockLen = sizeof(server);
}

void freeFields()
{
	free(channelId);
	free(authenticationTokenId);

	channelId = NULL;
	authenticationTokenId = NULL;
}

void setupConnection()
{
	unsigned long ul = 1;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup failed. Error Code : %d", WSAGetLastError());
		exit(1);
	}
	

	//Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (socket_desc == -1)
	{
		printf("Could not create socket\n");
		exit(1);
	}

	memset((char*)&server, 0, sizeof(server));
	server.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(48010);

	//Connect to remote server
	if (connect(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		printf("connect error number %d, exiting...\n", WSAGetLastError());
		exit(1);
	}
}

void doOpcHandshake()
{
	printf("doing handshake...\n");
	sendMessageToServer(HELF, NULL);
	recvResponseFromServer(HELF, true);

	//printf("Sent HELF...\n");

	sendMessageToServer(OPNF, NULL);
	recvResponseFromServer(OPNF, false);
	retrieveChannelId(msgResponse);					//retrieve the channelId from the OPNF response

	free(msgResponse);
	msgResponse = 0;

	sendMessageToServer(MSGF, (unsigned char*)"C:\\Users\\gpsap\\Desktop\\OPC_Fuzzing_Corpus\\MSGF_1.bin");		//createSessionRequest
	recvResponseFromServer(MSGF, false);
	retrieveAuthenticationTokenId(msgResponse);			//retrieve the authentication token from the createSessionResponse

	free(msgResponse);
	msgResponse = 0;

	sendMessageToServer(MSGF, (unsigned char*)"C:\\Users\\gpsap\\Desktop\\OPC_Fuzzing_Corpus\\MSGF_2.bin");		//activateSessionRequest
	recvResponseFromServer(MSGF, true);

	printf("End of handshake...\n");
}

long readMSGF(enum messageType type, unsigned char* corpusFile)
{
	long fileSize = 0;
	size_t result;
	FILE* fp = 0;

	switch (type)
	{
		case HELF:
			fp = fopen("C:\\Users\\gpsap\\Desktop\\OPC_Fuzzing_Corpus\\HELF.bin", "rb");
			break;

		case OPNF:
			fp = fopen("C:\\Users\\gpsap\\Desktop\\OPC_Fuzzing_Corpus\\OPNF.bin", "rb");
			break;
		case MSGF:
			fp = fopen(corpusFile, "rb");
			break;
	}

	if (fp == NULL)
	{
		puts("Error while reading file, exiting...\n");
		//printf("%d\n", GetLastError());
		exit(1);
	}

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	rewind(fp);

	messageBuffer = (unsigned char*)malloc(fileSize);
	if (messageBuffer == NULL)
	{
		fprintf(stderr, "Memory allocation error.\n");
		fclose(fp);
		exit(1);
	}

	result = fread(messageBuffer, 1, fileSize, fp);
	if (result != fileSize)
	{
		("Reading error.\n", stderr);
		exit(1);
	}

	fclose(fp);

	return fileSize;
}

/*
	from the 8th to the 11th bytes of the server OPNF response
*/
void retrieveChannelId(unsigned char* serverOPNFResponse)
{
	channelId = (unsigned char*)malloc(4);

	for (size_t i = 0; i < 4; i++)
	{
		channelId[i] = serverOPNFResponse[i + 8];
	}
}

/*
	from the 50th to the 53th bytes of the server CreateSession response
*/
void retrieveAuthenticationTokenId(unsigned char* serverCreateSessionResponse)
{
	authenticationTokenId = (unsigned char*)malloc(4);

	for (size_t i = 0; i < 4; i++)
	{
		authenticationTokenId[i] = serverCreateSessionResponse[i + 74];
	}
}

/*
	takes a message from the corpus and set its channelId to be coherent with the currently used channel
	as for the channelId in the OPNF server response, also here the bytes are from the 8th to the 11th
*/
void setChannelId(unsigned char* buf)
{
	for (size_t i = 0; i < 4; i++)
	{
		buf[i + 8] = channelId[i];
	}
}

/*
	takes a message from the corpus and set its authenticationToken to be coherent with the currently used channel
	as for the channelId in the OPNF server response, also here the bytes are from the 50th to the 53th
*/
void setAuthenticationToken(unsigned char* buf)
{
	buf[28] = 0x02;								//the encoding: the fuzzer may break it
	buf[29] = 0x00;
	buf[30] = 0x00;

	for (size_t i = 0; i < 4; i++)
	{
		buf[i + 31] = authenticationTokenId[i];
	}
}

/*
	I don't know whether it does change something
*/
void setTimestamp(unsigned char* buf)
{
	buf[35] = 0x70;
	buf[36] = 0x97;
	buf[37] = 0xa1;
	buf[38] = 0x08;
	buf[39] = 0xf2;
	buf[40] = 0xf5;
	buf[41] = 0xd7;
	buf[42] = 0x01;
}

/*
	I don't know whether it does change something
*/
void setRequestHandle(unsigned char* buf)
{
	buf[43] = 0x2f;
	buf[44] = 0x00;
	buf[45] = 0x00;
	buf[46] = 0x00;
}

void setSequenceNumber(unsigned char* buf)
{
	for (size_t i = 0; i < 4; i++)
	{
		buf[i + 16] = (currentSequenceNumber << (8 * i)) & 0xff;
	}

	currentSequenceNumber++;
}

int fuzzerFuckedTheTypeId(unsigned char* messageBuffer)
{
	if (messageBuffer[24] != 0x1 || messageBuffer[25] != 0x00)				//a bit weak because it doesn't consider the ID itself, but it's a start
		return 1;
	return 0;
}

/*
	To call only if the fuzzer fucked up the typeId
	I set it to a simple browse request
*/
void setTypeId(unsigned char* messageBuffer)
{
	messageBuffer[24] = 0x1;				//encoding mask
	messageBuffer[25] = 0x00;				//node namespace index
	messageBuffer[26] = 0x0f;				//browse identifier
	messageBuffer[27] = 0x02;				//browse identifier
}

void setMSFG(unsigned char* messageBuffer)
{
	messageBuffer[0] = 0x4d;
	messageBuffer[1] = 0x53;
	messageBuffer[2] = 0x47;
	messageBuffer[3] = 0x46;
}

void sendFuzzedInput(unsigned char* messageBuffer, long size)
{
	if (size > 12)
		setChannelId(messageBuffer);
	if (size > 34)
		setAuthenticationToken(messageBuffer);
	if (size > 19)
		setSequenceNumber(messageBuffer);
	if (size > 7)
		setMessageLength(messageBuffer);
	if (size > 42)
		setTimestamp(messageBuffer);
	if (size > 46)
		setRequestHandle(messageBuffer);
	if (size > 5)
		setMSFG(messageBuffer);

	if (size > 27 && fuzzerFuckedTheTypeId(messageBuffer))
	{
		setTypeId(messageBuffer);
	}

	if (send(socket_desc, (char*)messageBuffer, currentLen, 0) < 0)			//Be careful to the conversion to char*
	{
		//puts("Send failed, exiting...\n");
		//I try to remake connection
		initFields();
		handshakeThread = CreateThread(NULL, 0, handshakeThreadEntryPoint, 0, 0, &dwThreadId);
		canStartFuzz = true;
		//exit(1);
	}
	else
	{
		//printf("fuzzed message sent of length %ld...\n", currentLen);
	}
}

void setMessageLength(unsigned char* messageBuffer)
{
	for (size_t i = 0; i < 4; i++)
	{
		messageBuffer[i + 4] = (currentLen << (8 * i)) & 0xff;
	}
}

void sendInitialFuzzedInput(unsigned char* buf)
{
	if (currentLen > 12)
		setChannelId(buf);
	if (currentLen > 34)
		setAuthenticationToken(buf);
	if (currentLen > 19)
		setSequenceNumber(buf);
	if (currentLen > 7)
		setMessageLength(buf);
	if (currentLen > 42)
		setTimestamp(buf);
	if (currentLen > 46)
		setRequestHandle(buf);
	if (currentLen > 5)
		setMSFG(buf);

	if (currentLen > 27 && fuzzerFuckedTheTypeId(buf))
	{
		setTypeId(buf);
	}

	if (send(socket_desc, (char*)buf, currentLen, 0) < 0)
	{
		puts("Send initial fuzzing failed, exiting...\n");
		exit(1);
	}
}
/*
	channelId should be 0 for "OPNF" and "HELF" messages
	corpusFile should be 0 for "OPNF" and "HELF" messages, since they are always the same
*/
void sendMessageToServer(enum messageType type, unsigned char* corpusFile)
{
	int canFreeBuffer = true;

	switch (type)
	{
		case HELF:
			bytesToSend = readMSGF(HELF, NULL);
			channelId = NULL;
			break;

		case OPNF:
			bytesToSend = readMSGF(OPNF, NULL);
			channelId = NULL;
			break;
		case MSGF:
			if (corpusFile != NULL)								//only for handshake related messages, otherwise take the input from the fuzzer
				bytesToSend = readMSGF(MSGF, corpusFile);
			else
			{
				canFreeBuffer = false;							//if it is an input given by the fuzzer, don't free the buffer since WinAFL will do it
				bytesToSend = currentLen;
			}
			break;
	}

	if (channelId != NULL)
		setChannelId(messageBuffer);

	if (authenticationTokenId != NULL)
	{
		setAuthenticationToken(messageBuffer);
	}

	if (mustSetSeq)
	{
		setSequenceNumber(messageBuffer);
	}

	if (send(socket_desc, (char*)messageBuffer, bytesToSend, 0) < 0)			//Be careful to the conversion to char*
	{
		puts("Send failed 2, exiting...\n");
		initFields();
		handshakeThread = CreateThread(NULL, 0, handshakeThreadEntryPoint, 0, 0, &dwThreadId);					//handling the connection closed by the server upon errors
		canStartFuzz = true;
		//exit(1);
	}

	if (canFreeBuffer)													//if it is not an input given by the fuzzer
	{
		free(messageBuffer);
		messageBuffer = 0;
	}
}

size_t recvResponseFromServer(enum messageType type, size_t canFree)
{

	size_t bytesReceived = 0;
	msgResponse = (unsigned char*)malloc(60000);

	if ((bytesReceived = recv(socket_desc, (char*)msgResponse, 30000, 0)) < 0)				//should I increase size? Be careful to the conversion to char*
	{
		puts("recv failed, exiting...");
		exit(1);
	}

	switch (type)
	{
	case HELF:
		puts("Reply to HELF received\n");
		break;
	case OPNF:
		puts("Reply to OPNF received\n");
		break;
	case MSGF:
		puts("Reply to MSGF received\n");
		break;
	}

	if (canFree)
	{
		free(msgResponse);
		msgResponse = 0;
	}

	return bytesReceived;
}