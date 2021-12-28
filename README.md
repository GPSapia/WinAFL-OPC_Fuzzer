# WinAFL-OPC_Fuzzer
custom "run_target" for WinAFL to fuzz a OPC server.
It sets the connection towards the server, perform the handshake and send the fuzzed input received by WinAFL, setting for each new message the channelId, authenticationId and sequence Number.
