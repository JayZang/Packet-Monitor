#include "stdafx.h"
#include "DLLManage.h"



namespace SSL
{
	SSLAnalyzer::SSLAnalyzer()
	{
		mySSL = new SSLAnalyze();
	}

	void SSLAnalyzer::InsertPacketData(Byte* param)
	{
		mySSL->InsertPacketData(param);
	}

	bool SSLAnalyzer::IsSSLRecordLayer()
	{
		return mySSL->IsSSLRecordLayer;
	}

	/*bool SSLAnalyzer::GetHandShakeMainContent(Byte **UserIP, Byte **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, unsigned int *PubKeyLen, Byte **Pubkey, unsigned int *SessionKeyLen, Byte **SessionKey, unsigned int *NewSessionTicketLen, Byte **NewSessionTicket)
	{		
		return mySSL->GetHandShakeMainContent(UserIP, ServerIP, UserPort, ServerPort, Version, CipherSuite, (int *)PubKeyLen, Pubkey, (int *)SessionKeyLen, SessionKey, (int *)NewSessionTicketLen, NewSessionTicket);
	}*/

	bool SSLAnalyzer::GetHandShakeMainContent( )
	{
		bool _bool;
		_bool =  mySSL->GetHandShakeMainContent(UserIP, ServerIP, UserPort, ServerPort, Version, CipherSuite, (int *)PubKeyLen, Pubkey, (int *)SessionKeyLen, SessionKey, (int *)NewSessionTicketLen, NewSessionTicket);

		if (_bool == true && (*PubKeyLen > 500 || *SessionKeyLen > 500 || *NewSessionTicketLen > 500) )
		{
			return false;
		}		
		else if (_bool == true)
		{
			return true;
		}

		return _bool;
	}
}

