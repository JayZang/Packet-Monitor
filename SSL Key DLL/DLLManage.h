#pragma once

#define CLASS_EXPORT

#include "SSLAnalyze.h"

using namespace System;

namespace SSL
{
	public  ref class SSLHandShakeContent
	{
	public:
		SSLHandShakeContent()
		{
			UserIP = new Byte  *;
			ServerIP  = new Byte  *;
			UserPort = new unsigned short();
			ServerPort = new unsigned short();
			Version = new unsigned short();
			CipherSuite = new unsigned short();
			PubKeyLen = new int();
			Pubkey = new Byte  *;
			SessionKeyLen = new int;
			SessionKey = new Byte  *;
			NewSessionTicketLen = new int();
			NewSessionTicket = new Byte  *;
		}

		Byte *GetUserIP() { return *UserIP; }
		Byte  *GetServerIP(){ return *ServerIP; }
		unsigned short GetUserPort() { return *UserPort; }
		unsigned short GetServerPort() { return *ServerPort; }
		unsigned short GetVersion() { return *Version; }
		unsigned short GetCipherSuite() { return *CipherSuite; }
		int GetPubKeyLen() { return *PubKeyLen;}
		Byte *GetPubkey() { return *Pubkey; }
		int GetSessionKeyLen() { return *SessionKeyLen; }
		Byte *GetSessionKey() { return *SessionKey; }
		int GetNewSessionTicketLen() { return *NewSessionTicketLen; }
		Byte *GetNewSessionTicket() { return *NewSessionTicket; }

	protected:
		Byte  **UserIP;
		Byte  **ServerIP;
		unsigned short *UserPort;
		unsigned short *ServerPort;
		unsigned short *Version;
		unsigned short *CipherSuite;
		int *PubKeyLen;
		Byte **Pubkey;
		int *SessionKeyLen;
		Byte **SessionKey;
		int *NewSessionTicketLen;
		Byte **NewSessionTicket;
	};

	public ref class SSLAnalyzer : public SSLHandShakeContent
	{
	public:
		SSLAnalyzer();

		void InsertPacketData(Byte*);
		/*bool GetHandShakeMainContent(Byte **, Byte **, unsigned short *, unsigned short *, unsigned short *, unsigned short *, unsigned int *, Byte **, unsigned int *, Byte **, unsigned int *, Byte **);*/
		bool GetHandShakeMainContent();
		bool IsSSLRecordLayer();

	private:
		SSLAnalyze  *mySSL;		
	};
}