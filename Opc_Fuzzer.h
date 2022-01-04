#pragma once

#define WIN32_LEAN_AND_MEAN

#define OPC_FUZZER_API __declspec(dllexport)
#define SOCKET_INIT_DELAY 15000

#define true 1
#define false 0

#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <malloc.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library
#pragma comment( lib, "wininet")

OPC_FUZZER_API int APIENTRY dll_init();
OPC_FUZZER_API int APIENTRY dll_run(char* data, long size, int fuzz_iterations);

unsigned char* messageBuffer;
unsigned char* msgResponse;
unsigned char* channelId;					//it identifies the channel, i.e. the lower level communication "pipe"
unsigned char* authenticationTokenId;		//it identifies the session, i.e. the higher level communication "pipe"
unsigned int currentSequenceNumber = 4;			//we start fuzzing after the OPC handshake

SOCKET socket_desc;
struct sockaddr_in server;
WSADATA wsa;
int sockLen;

long bytesToSend;

u_short mustSetSeq = 0;

enum messageType {
    HELF = 0,
    OPNF = 1,
    MSGF = 2
};

extern void setupConnection();
extern void initFields();
extern void doOpcHandshake();
extern void freeFields();
extern void sendMessageToServer(enum messageType type, unsigned char* corpusFile);               //this should be called with channelId=NULL for "OPNF" and "HELF"
extern size_t recvResponseFromServer(enum messageType type, size_t canFree);
extern long readMSGF(enum messageType type, unsigned char* corpusFile);
extern void retrieveChannelId(unsigned char* serverOPNFResponse);
extern void retrieveAuthenticationTokenId(unsigned char* serverCreateSessionResponse);
extern void setChannelId(unsigned char* buf);
extern DWORD WINAPI handshakeThreadEntryPoint(LPVOID lpParameter);
extern DWORD WINAPI initialFuzzing(LPVOID buffer);
extern void setAuthenticationToken(unsigned char* buf);
extern void setSequenceNumber(unsigned char* buf);
extern void setMessageLength(unsigned char* buf);
extern void setTypeId(unsigned char* buf);
extern void printServerResponse(unsigned char* response, size_t length);
int fuzzerFuckedTheTypeId(unsigned char* buf);

extern void sendFuzzedInput(unsigned char* buf, long size);
extern void sendInitialFuzzedInput(unsigned char* data);