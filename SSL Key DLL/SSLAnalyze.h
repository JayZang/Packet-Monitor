#pragma once
#include "SSLCommon.h"
#include "PacketHeader.h"

#ifndef CLASS_EXPORT
    #define DLL_CLASS __declspec(dllexport)
#else
    #define DLL_CLASS __declspec(dllimport)
#endif

#define MAX_ReassemblyPacketTable_BUFFER 100
#define MAX_HandShakeMainContent_BUFFER  50
#define MAX_ReassemblePubkey_BUFFER      20

	struct ReassemblyPacketContent
	{
		bool isCanUse;
		int  type;
		unsigned int   ip_srcaddr;
		unsigned int   ip_destaddr;
		unsigned short SrcPort;
		unsigned short DstPort;
		unsigned int   Sequence;
		unsigned int   NextSequence;
		unsigned short RemainingLen;
		int            LiveTime;
		bool           isAppLayer;    //  is Application Layer;
	};

    struct HandShakeMainContent
	{
		unsigned char  UserIP[4];
		unsigned char  ServerIP[4];
		unsigned short UserPort;
		unsigned short ServerPort;
		unsigned short Versiom;
		unsigned short CipherSuite;
		int PubKeyLen;
		unsigned char *Pubkey;
		int SessionKeyLen;
		unsigned char *SessionKey;
		int NewSessionTicketLen;
		unsigned char *NewSessionTicket;
	};

	struct HandShakeMainContentBuffer
	{
		bool isCanUse;
		bool isContentOK;
		int  TTL;                       //  Time to live.
		unsigned int   UserIP;
		unsigned int   ServerIP;
		unsigned short UserPort;
		unsigned short ServerPort;
		unsigned short Versiom;
		unsigned short CipherSuite;
		int PubKeyLen;
		unsigned char *Pubkey;
		int SessionKeyLen;
		unsigned char *SessionKey;
		int NewSessionTicketLen;
		unsigned char *NewSessionTicket;
	};

	struct ReassemblePubkey
	{
		bool isCanUse;
		int  TTL;                    // Time to live
		unsigned int   UserIP;
		unsigned int   ServerIP;
		unsigned short UserPort;
		unsigned short ServerPort;
		int ReaminPubkeyLen;
		unsigned char *Pubkey;
	};

	class  HandShakeLayerAndChangeCipherSpecLayer
	{
	public:
		HandShakeLayerAndChangeCipherSpecLayer();

		bool GetMainContent(unsigned char **UserIP, unsigned char **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, int *PubKeyLen, unsigned char **Pubkey, int *SessionKeyLen, unsigned char **SessionKey, int *NewSessionTicketLen, unsigned char **NewSessionTicket);

		void SetHandShakeMainContent(ssl_tls_record_layer*, unsigned int srcip, unsigned int dstip, unsigned short srcport, unsigned short dstport, int TcpRemainingLen, int type, ssl_tls_handshake_layer *);

		void GetRemainPubkey(unsigned int SrcIP, unsigned int DstIP, unsigned short SrcPort, unsigned short DstPort, unsigned char * Byte);

	private:
		HandShakeMainContentBuffer HandShakeMainContentBuffer[MAX_HandShakeMainContent_BUFFER];
		HandShakeMainContent       HandShakeMainContent[MAX_HandShakeMainContent_BUFFER];
		ReassemblePubkey           ReassemblePubkey[MAX_ReassemblePubkey_BUFFER];

		bool isCorrespondingHandShakeContent(unsigned int userip, unsigned int serverip, unsigned short userport, unsigned short serverport);
		int  CorrespondingHandShakeContentIndex;
		void HandShakeMainContentBufferToHandShakeMainContent(int i);
		void InitialHandShakeMainContentBuffer();
		void InitialReassemblePubkeyTable();
		void SetReassemblePubkeyTable(unsigned int ServerIP, unsigned int UserIP, unsigned short ServerPort, unsigned short UserPort, int KeyRemainingLen, unsigned char * Key);

		ssl_tls_handshake_layer *SSLHandShakeLayer;
		SSLHandshakeType SSLHandshakeType;
	};

	class DLL_CLASS SSLAnalyze
	{
	public:
		SSLAnalyze();
		//~SSLAnalyze();

		void InsertPacketData(unsigned char *);
		bool GetHandShakeMainContent(unsigned char **UserIP, unsigned char **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, int *PubKeyLen, unsigned char **Pubkey, int *SessionKeyLen, unsigned char **SessionKey, int *NewSessionTicketLen, unsigned char **NewSessionTicket);

		bool IsSSLRecordLayer;

	private:
		
		HandShakeLayerAndChangeCipherSpecLayer HandShakeLayer;

		bool isSSLRecordLayer();
		bool isRemainingPacket(int &index);
		void AnalyzeIfNeedReassemble(unsigned int);         // Analyze a packet if need to be reassembled and create table.
		void AnalyzeIfNeedReassemble_2(unsigned int);
		void SetReassemblyPacketTable(unsigned short, int m_type);
		void clearReassemblyPacketTable();
		bool isNextSSLRecordLayer(ssl_tls_record_layer *);	
		bool isHandShakeLayerOrChangeCipherSpecLayer(ssl_tls_record_layer *);

		unsigned char *pkt_data;
		unsigned char *TcpSegment;
		unsigned int  TcpSegmentLen;
		unsigned int  RemainingTcpSegmentLen;

		ETHER_HDR *ethhdr;
		IPV4_HDR *iphdr;
		TCP_HDR *tcpheader;

		ReassemblyPacketContent ReassemblyPacketTable[MAX_ReassemblyPacketTable_BUFFER];

		ssl_tls_record_layer *RecordLayer;
		ssl_tls_handshake_layer *StructHandShakeLayer;
	};


