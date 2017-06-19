#include "stdafx.h"
#include "winsock2.h"
#include "SSLAnalyze.h"


	////////////////////////////////////////////////////////////////// Class SSLAnalyze //////////////////////////////////////////////////////////////////
	SSLAnalyze::SSLAnalyze()
	{
		pkt_data = NULL;
		this->clearReassemblyPacketTable();
	}

	// ��J Row Packet
	void SSLAnalyze::InsertPacketData(unsigned char *packet_data)
	{
		pkt_data = packet_data;
		ethhdr = (ETHER_HDR *)pkt_data;
		if (ntohs(ethhdr->type) == 0x0800 || ntohs(ethhdr->type) == 0x8864)
		{
			if(ntohs(ethhdr->type) == 0x0800)
				iphdr = (IPV4_HDR *)(pkt_data + sizeof(ETHER_HDR));
			else if (ntohs(ethhdr->type) == 0x8864)
				iphdr = (IPV4_HDR *)(pkt_data + sizeof(ETHER_HDR) + 8);
			tcpheader = (TCP_HDR*)((unsigned char*)iphdr + iphdr->ip_header_len * 4);
			TcpSegment = (unsigned char *)((unsigned char*)tcpheader + tcpheader->data_offset * 4);
			TcpSegmentLen = ntohs(iphdr->ip_total_length) - iphdr->ip_header_len * 4 - tcpheader->data_offset * 4;
			RecordLayer = (ssl_tls_record_layer*)(TcpSegment);

			int index = -1;

			// �P�_���OSSL���ʥ](�Ĥ@�]���Q����)
			if (this->isSSLRecordLayer() && TcpSegmentLen != 0)
			{
				// �Y�O Application Data Layer �n��������ƫᤣ���~���L���R
				if (RecordLayer->recordType == SSL_APPLICATION_DATA)
				{
					SetReassemblyPacketTable(0, 0);
					return;
				}

				StructHandShakeLayer = (ssl_tls_handshake_layer *)((unsigned char *)RecordLayer + sizeof(ssl_tls_record_layer));
				// all SSL content just has one SSL Record Layer at the first of reassembled packet. type = 2
				if (ntohs(RecordLayer->length) != ntohs(StructHandShakeLayer->length2) + sizeof(ssl_tls_handshake_layer) && StructHandShakeLayer->handshakeType == SSL_SERVER_HELLO)
				{
					RemainingTcpSegmentLen = TcpSegmentLen - sizeof(ssl_tls_record_layer) - sizeof(ssl_tls_handshake_layer);
					this->AnalyzeIfNeedReassemble_2(RemainingTcpSegmentLen);
				}
				// Each SSL content have their own Record Layer. type = 1
				else
				{
					this->AnalyzeIfNeedReassemble(TcpSegmentLen);
				}
			}
			// �P�_���O�Q���Ϊ�SSL�ʥ]
			else if (this->isRemainingPacket(index) && TcpSegmentLen != 0)
			{			
				// �Y�O Application Data Layer �Y�i���ΰ��i�@�B���R�C
				if (ReassemblyPacketTable[index].isAppLayer == true)
				{
					return;
				}

				// ���ɭ�HandShake Layer��Pubkey�|�Q�ʥ]�Ҥ����A�o�̬O�n�ӴM���ѤU���_�ͤ��e
				HandShakeLayer.GetRemainPubkey(iphdr->ip_srcaddr, iphdr->ip_destaddr,ntohs(tcpheader->source_port),ntohs(tcpheader->dest_port), TcpSegment);

				if (ReassemblyPacketTable[index].type == 1)
				{
					if (ReassemblyPacketTable[index].RemainingLen < TcpSegmentLen)
					{
						RecordLayer = (ssl_tls_record_layer *)(TcpSegment + ReassemblyPacketTable[index].RemainingLen);
						RemainingTcpSegmentLen = TcpSegmentLen - ReassemblyPacketTable[index].RemainingLen;
						this->AnalyzeIfNeedReassemble(RemainingTcpSegmentLen);
					}
					else if (ReassemblyPacketTable[index].RemainingLen > TcpSegmentLen)
					{
						unsigned int RemainingLen = ReassemblyPacketTable[index].RemainingLen - TcpSegmentLen;
						this->SetReassemblyPacketTable(RemainingLen, 1);
					}
				}
				else if (ReassemblyPacketTable[index].type == 2)
				{
					if (ReassemblyPacketTable[index].RemainingLen < TcpSegmentLen)
					{
						StructHandShakeLayer = (ssl_tls_handshake_layer *)(TcpSegment + ReassemblyPacketTable[index].RemainingLen);
						RemainingTcpSegmentLen = TcpSegmentLen - ReassemblyPacketTable[index].RemainingLen - sizeof(ssl_tls_handshake_layer);
						this->AnalyzeIfNeedReassemble_2(RemainingTcpSegmentLen);
					}
					else if (ReassemblyPacketTable[index].RemainingLen > TcpSegmentLen)
					{
						unsigned int RemainingLen = ReassemblyPacketTable[index].RemainingLen - TcpSegmentLen;
						this->SetReassemblyPacketTable(RemainingLen, 2);
					}
				}
			}	
			// ���O SSL�ʥ]
			else
			{
				IsSSLRecordLayer = FALSE;
			}
		}
	}

	// ���o HandShake �洫�_�͸�T
	 bool SSLAnalyze::GetHandShakeMainContent(unsigned char **UserIP, unsigned char **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, int *PubKeyLen, unsigned char **Pubkey, int *SessionKeyLen, unsigned char **SessionKey, int *NewSessionTicketLen, unsigned char **NewSessionTicket)
	{
		return HandShakeLayer.GetMainContent(UserIP, ServerIP, UserPort, ServerPort, Version, CipherSuite, PubKeyLen, Pubkey, SessionKeyLen, SessionKey, NewSessionTicketLen, NewSessionTicket);	
	}

	///////////////////////////////  Private  ///////////////////////////////

	 // �P�_�O�_�� SSL Record Layer�A�]��(IsSSLRecordLayer) 
	bool SSLAnalyze::isSSLRecordLayer()
	{
		if (ntohs(ethhdr->type) == 0x0800 || ntohs(ethhdr->type) == 0x8864)
		{
			if ((RecordLayer->recordType == 0x14) ||
				(RecordLayer->recordType == 0x15) ||
				(RecordLayer->recordType == 0x16) ||
				(RecordLayer->recordType == 0x17))
			{
				if ((ntohs(RecordLayer->recordVersion) == 0x0200) ||
					(ntohs(RecordLayer->recordVersion) == 0x0300) ||
					(ntohs(RecordLayer->recordVersion) == 0x0301) ||
					(ntohs(RecordLayer->recordVersion) == 0x0302) ||
					(ntohs(RecordLayer->recordVersion) == 0x0303))
				{
					IsSSLRecordLayer = TRUE;
					return TRUE;
				}
				else
				{
					IsSSLRecordLayer = FALSE;
					return FALSE;
				}
			}
			else
			{
				IsSSLRecordLayer = FALSE;
				return FALSE;
			}
		}
		else
		{
			IsSSLRecordLayer = FALSE;
			return FALSE;
		}
	}

	// �P�_���ʥ]�O�_���Q���Ϊ�SSL�ʥ]
	bool SSLAnalyze::isRemainingPacket(int &index)
	{		
		for (int i = 0; i < MAX_ReassemblyPacketTable_BUFFER ; i++)
		{
			if ((ReassemblyPacketTable[i].isCanUse == false ) &&                         // Table �O�w�n�����A
				(iphdr->ip_srcaddr == ReassemblyPacketTable[i].ip_srcaddr) &&
				(iphdr->ip_destaddr == ReassemblyPacketTable[i].ip_destaddr) &&
				(ntohs(tcpheader->source_port) == ReassemblyPacketTable[i].SrcPort) &&
				(ntohs(tcpheader->dest_port) == ReassemblyPacketTable[i].DstPort) )
			{
				// ���O Application Data Layer ���ܭn�P�_�O�_������ sequence �A�O�Y�i�����q table ������(�Y�i�H�ϥγo�� Table)
				if (ReassemblyPacketTable[i].isAppLayer == false &&  ntohl(tcpheader->sequence) == ReassemblyPacketTable[i].NextSequence)
				{
					index = i;					
					ReassemblyPacketTable[i].isCanUse = TRUE;

					IsSSLRecordLayer = TRUE;
					return TRUE;
				}
				// �� Application Data Layer �����~��n���b table ���A�H�K�P�_�U�]�O�_�� Application Data
				else if (ReassemblyPacketTable[i].isAppLayer == true)
				{
					index = i;
					ReassemblyPacketTable[i].LiveTime = 0;

					IsSSLRecordLayer = TRUE;
					return TRUE;
				}	
			}
		}
		index = -1;
		IsSSLRecordLayer = FALSE;
		return FALSE;
	}

	// ��l ReassemblyPacketTable
	void SSLAnalyze::clearReassemblyPacketTable()
	{
		for (int i = 0; i<MAX_ReassemblyPacketTable_BUFFER; i++)
		{
			ReassemblyPacketTable[i].isCanUse = TRUE;
			ReassemblyPacketTable[i].LiveTime = 0;
			ReassemblyPacketTable[i].isAppLayer = false;
		}
	}

	// For type = 1�A�C�� HandShakeLayer �e�����U�۪� RecordLayer 
	void SSLAnalyze::AnalyzeIfNeedReassemble(unsigned int m_TcpSegmentLen)
	{
		RemainingTcpSegmentLen = m_TcpSegmentLen;

		if ((ntohs(RecordLayer->length) + 5) > RemainingTcpSegmentLen)
		{
			unsigned short RemainingLen = ntohs(RecordLayer->length) - (RemainingTcpSegmentLen - 5);
			this->SetReassemblyPacketTable(RemainingLen, 1);

			if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
			{
				HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), RemainingTcpSegmentLen, 1, NULL);
			}
		}
		else if ((ntohs(RecordLayer->length) + 5) < RemainingTcpSegmentLen)
		{
			if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
			{
				HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 1, NULL);
			}

			while ((ntohs(RecordLayer->length) + 5) < RemainingTcpSegmentLen)
			{
				RemainingTcpSegmentLen = RemainingTcpSegmentLen - (ntohs(RecordLayer->length) + 5);
				RecordLayer = (ssl_tls_record_layer *)((unsigned char *)RecordLayer + (5 + ntohs(RecordLayer->length)));
				if (this->isNextSSLRecordLayer(RecordLayer))
				{
					if ((ntohs(RecordLayer->length) + 5) < RemainingTcpSegmentLen)
					{
						if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
						{
							HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 1, NULL);
						}
						continue;
					}
					else if ((ntohs(RecordLayer->length) + 5) > RemainingTcpSegmentLen)
					{
						if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
						{
							HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), RemainingTcpSegmentLen, 1, NULL);
						}

						unsigned short RemainingLen = ntohs(RecordLayer->length) - (RemainingTcpSegmentLen - 5);
						this->SetReassemblyPacketTable(RemainingLen, 1);
						RemainingTcpSegmentLen = NULL;
						break;
					}
					else
					{
						if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
						{
							HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 1, NULL);
						}

						RemainingTcpSegmentLen = NULL;
					}
				}
			}
		}
		else
		{
			if (this->isHandShakeLayerOrChangeCipherSpecLayer(RecordLayer))
			{
				HandShakeLayer.SetHandShakeMainContent(RecordLayer, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 1, NULL);
			}
		}
	}

	// For type = 2�A�Ҧ� HandShakeLayer �Q�]�b�@�� Record Layer
	void SSLAnalyze::AnalyzeIfNeedReassemble_2(unsigned int m_TcpSegmentLen)
	{
		RemainingTcpSegmentLen = m_TcpSegmentLen;

		if (ntohs(StructHandShakeLayer->length2) > RemainingTcpSegmentLen)
		{
			unsigned short RemainingLen = ntohs(StructHandShakeLayer->length2) - RemainingTcpSegmentLen;
			this->SetReassemblyPacketTable(RemainingLen, 2);

			HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), RemainingTcpSegmentLen, 2, StructHandShakeLayer);
		}
		else if (ntohs(StructHandShakeLayer->length2) < RemainingTcpSegmentLen)
		{
			HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 2, StructHandShakeLayer);

			while (ntohs(StructHandShakeLayer->length2) < RemainingTcpSegmentLen)
			{
				RemainingTcpSegmentLen = RemainingTcpSegmentLen - ntohs(StructHandShakeLayer->length2) - sizeof(ssl_tls_handshake_layer);
				StructHandShakeLayer = (ssl_tls_handshake_layer *)((unsigned char *)StructHandShakeLayer + sizeof(ssl_tls_handshake_layer) + ntohs(StructHandShakeLayer->length2));
				if (ntohs(StructHandShakeLayer->length2) < RemainingTcpSegmentLen)
				{
					HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 2, StructHandShakeLayer);

					continue;
				}
				else if (ntohs(StructHandShakeLayer->length2) > RemainingTcpSegmentLen)
				{
					HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), RemainingTcpSegmentLen, 2, StructHandShakeLayer);

					unsigned short RemainingLen = ntohs(StructHandShakeLayer->length2) - RemainingTcpSegmentLen;
					this->SetReassemblyPacketTable(RemainingLen, 2);
					RemainingTcpSegmentLen = NULL;
					break;
				}
				else
				{
					HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 2, StructHandShakeLayer);

					RemainingTcpSegmentLen = NULL;
				}
			}
		}
		else
		{
			HandShakeLayer.SetHandShakeMainContent(NULL, iphdr->ip_srcaddr, iphdr->ip_destaddr, ntohs(tcpheader->source_port), ntohs(tcpheader->dest_port), 0, 2, StructHandShakeLayer);
		}
	}

	// �n���Q���Ϋʥ]��������ơA�H���ѤU�@�]�ʥ]�O�_��SSL�ʥ]
	void SSLAnalyze::SetReassemblyPacketTable(unsigned short len, int m_type)
	{
		int i;
		bool NeedFindTableSpace = true;

		// �w�n������ƥi��]���������U�@�ʥ]�S�ӡA�ӵL�k����������ƾɭP�@���Ȧs�b ReassemblyPacketTable �̡A�]���]�m��s�����ƤӤ[�N�R��
		for (i = 0; i < MAX_ReassemblyPacketTable_BUFFER; i++)
		{
			if (ReassemblyPacketTable[i].isCanUse == FALSE)
			{
				ReassemblyPacketTable[i].LiveTime += 1;

				// �P�_�O�_�� APPLICATION DATA Layer �åB�P�_�O�_�w�g�n���L�A�O�h��l LiveTime�A���ΦA�n���@�����
				if (RecordLayer->recordType == SSL_APPLICATION_DATA && ReassemblyPacketTable[i].isAppLayer && m_type != 2)
				{
					if (ReassemblyPacketTable[i].ip_srcaddr == iphdr->ip_srcaddr &&
						ReassemblyPacketTable[i].ip_destaddr == iphdr->ip_destaddr &&
						ReassemblyPacketTable[i].SrcPort == ntohs(tcpheader->source_port) &&
						ReassemblyPacketTable[i].DstPort == ntohs(tcpheader->dest_port))
					{
						ReassemblyPacketTable[i].LiveTime = 0;
						NeedFindTableSpace = false;
					}
				}

			}
			if (ReassemblyPacketTable[i].LiveTime == MAX_ReassemblyPacketTable_BUFFER)
			{
				ReassemblyPacketTable[i].LiveTime = 0;
				ReassemblyPacketTable[i].isCanUse = TRUE;
			}
		}

		// �n���Q���쪺SSL�ʥ]���U�@�ʥ]����T
		for (i = 0; i < MAX_ReassemblyPacketTable_BUFFER, NeedFindTableSpace == true ; i++)
		{
			if (ReassemblyPacketTable[i].isCanUse)
			{
				ReassemblyPacketTable[i].isCanUse = FALSE;
				ReassemblyPacketTable[i].type = m_type;
				ReassemblyPacketTable[i].ip_srcaddr = iphdr->ip_srcaddr;
				ReassemblyPacketTable[i].ip_destaddr = iphdr->ip_destaddr;
				ReassemblyPacketTable[i].SrcPort = ntohs(tcpheader->source_port);
				ReassemblyPacketTable[i].DstPort = ntohs(tcpheader->dest_port);

				// �P�_�O�_�� Application Data Layer , �Y�O���ܨä��ݭn�Ҽ{�U�@�] Sequence �O�h�֡A�u�ݭn�P�_�� PORT
				if (RecordLayer->recordType != SSL_APPLICATION_DATA || m_type == 2 ) //m_type == 2�ɤ@�w�OHandShake Layer���OAPPLICATION_DATA
				{
					ReassemblyPacketTable[i].isAppLayer = false;
					ReassemblyPacketTable[i].Sequence = ntohl(tcpheader->sequence);
					ReassemblyPacketTable[i].NextSequence = ntohl(tcpheader->sequence) + TcpSegmentLen;
					ReassemblyPacketTable[i].RemainingLen = len;  // �ʥ]��ƳQ�����ҳѪ�����
					break;
				}
				else
				{
					ReassemblyPacketTable[i].isAppLayer = true;
					ReassemblyPacketTable[i].Sequence = 0;
					ReassemblyPacketTable[i].NextSequence = 0;
					ReassemblyPacketTable[i].RemainingLen = 0;  
					break;
				}
			}
		}
		if (i == MAX_ReassemblyPacketTable_BUFFER)
		{
			bool error = TRUE;
		}

	}

	// �P�_�O�_�� SSL Record Layer�A���]��(IsSSLRecordLayer)
	bool SSLAnalyze::isNextSSLRecordLayer(ssl_tls_record_layer *NextRecordLayer)
	{
		if ((NextRecordLayer->recordType == 0x14) ||
			(NextRecordLayer->recordType == 0x15) ||
			(NextRecordLayer->recordType == 0x16) ||
			(NextRecordLayer->recordType == 0x17))
		{
			if ((ntohs(NextRecordLayer->recordVersion) == 0x0200) ||
				(ntohs(NextRecordLayer->recordVersion) == 0x0300) ||
				(ntohs(NextRecordLayer->recordVersion) == 0x0301) ||
				(ntohs(NextRecordLayer->recordVersion) == 0x0302) ||
				(ntohs(NextRecordLayer->recordVersion) == 0x0303))
			{
				return TRUE;
			}
			else return FALSE;
		}
		else return FALSE;
	}

	// �P�_ Record Layer Type �O�_�� HandShakeLayer || ChangeCipherSpecLayer
	bool SSLAnalyze::isHandShakeLayerOrChangeCipherSpecLayer(ssl_tls_record_layer *m_RecordLayet)
	{
		if ((m_RecordLayet->recordType == SSL_HANDSHAKE) || (m_RecordLayet->recordType == SSL_CHANGE_CIPHER_SPEC))
		{
			return TRUE;
		}
		return FALSE;
	}





	//////////////////////////////////////////////////////////////// Class HandShakeLayer ////////////////////////////////////////////////////////////////

	// ��l HandShakeMainContentBuffer
	HandShakeLayerAndChangeCipherSpecLayer::HandShakeLayerAndChangeCipherSpecLayer()
	{
		CorrespondingHandShakeContentIndex = 0;
		InitialReassemblePubkeyTable();
		InitialHandShakeMainContentBuffer();
	}

	// �x�s�洫�_�ͪ�������ơA�q SSL Record Type == SSL_HANDSHAKE || SSL_CHANGE_CIPHER_SPEC �����o�������
	void HandShakeLayerAndChangeCipherSpecLayer::SetHandShakeMainContent(ssl_tls_record_layer *m_RecordLayer, unsigned int srcip, unsigned int dstip, unsigned short srcport, unsigned short dstport, int TcpRemainingLen, int type, ssl_tls_handshake_layer *m_HandShakeLayer)
	{
		int /*i = 0 ,*/ index = 0;
		bool needSearch;

		// �Ҧ��� HandShakeLayer ���]�b�P�@��RecordLayer : type = 2 , 
		if (type == 2 && m_HandShakeLayer != NULL && m_RecordLayer == NULL)
		{
			SSLHandShakeLayer = m_HandShakeLayer;
			SSLHandshakeType = (enum SSLHandshakeType)SSLHandShakeLayer->handshakeType;
			if (TcpRemainingLen != 0) 
			{
				// ���]�p�W���~�A�Ϩ���׬O�qRecordLayer�e�p��A���᪺�p��~�i�H�M type 1 �ۦP�p��覡
				TcpRemainingLen = TcpRemainingLen + sizeof(ssl_tls_record_layer) + sizeof(ssl_tls_handshake_layer);
			}
			goto HasHandShakeLayer;
		}
		// �C�@�� HandShakeLayer ���֦��ۤv�� ReacodLayer : type = 1
		else if (type == 1 && m_RecordLayer->recordType == SSL_HANDSHAKE && m_HandShakeLayer == NULL)
		{
			SSLHandShakeLayer = (ssl_tls_handshake_layer *)((unsigned char *)m_RecordLayer + sizeof(ssl_tls_record_layer));
			SSLHandshakeType = (enum SSLHandshakeType)SSLHandShakeLayer->handshakeType;

		    HasHandShakeLayer:
			switch (SSLHandshakeType)
			{
			case SSL_CLIENT_HELLO:
			
				needSearch = true;   //�]���b�n���ɥ������ˬd�w�n������Ʀs��h�[�F�A�ݭnTable�j��@��;�ӷ���n�n���s�񪺦a�I���� needSearch �N�� false ��ܤw�n�����ݭn�A�~��n���F
				// �N������Ƶn����HandShakeMainContentBuffer
				for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
				{		
					if ( HandShakeMainContentBuffer[i].isCanUse == false )  // �w�n�������
					{
						HandShakeMainContentBuffer[i].TTL += 1;             // �s�����ƥ[1
						if (HandShakeMainContentBuffer[i].TTL >= MAX_HandShakeMainContent_BUFFER) // �w�s�bTable��>=MAX_HandShakeMainContent_BUFFER��
						{
							HandShakeMainContentBuffer[i].isCanUse = true;
							HandShakeMainContentBuffer[i].isContentOK = false;
							HandShakeMainContentBuffer[i].TTL = 0;
							HandShakeMainContentBuffer[i].UserIP = 0;
							HandShakeMainContentBuffer[i].ServerIP = 0;
							HandShakeMainContentBuffer[i].UserPort = 0;
							HandShakeMainContentBuffer[i].ServerPort = 0;
							HandShakeMainContentBuffer[i].Versiom = 0;
							HandShakeMainContentBuffer[i].CipherSuite = 0;
							HandShakeMainContentBuffer[i].PubKeyLen = 0;
							HandShakeMainContentBuffer[i].Pubkey = 0;
							HandShakeMainContentBuffer[i].SessionKeyLen = 0;
							HandShakeMainContentBuffer[i].SessionKey = 0;
							HandShakeMainContentBuffer[i].NewSessionTicketLen = 0;
							HandShakeMainContentBuffer[i].NewSessionTicket = 0;
						}
					}
					if (HandShakeMainContentBuffer[i].isCanUse && needSearch == true)
					{
						needSearch = false;
						index = i;

						HandShakeMainContentBuffer[i].isCanUse = FALSE;
						HandShakeMainContentBuffer[i].isContentOK = FALSE;
						HandShakeMainContentBuffer[i].UserIP = srcip;
						HandShakeMainContentBuffer[i].ServerIP = dstip;
						HandShakeMainContentBuffer[i].UserPort = srcport;
						HandShakeMainContentBuffer[i].ServerPort = dstport;						
					}
				}
				//if (i == MAX_HandShakeMainContent_BUFFER)
				//{
				//	bool error = true;    // Buffer�w��
				//}
				break;

			case  SSL_SERVER_HELLO:

				// ��X�b HandShakeMainContentBuffer �̹�����index�æb�n���������
				if (this->isCorrespondingHandShakeContent(dstip, srcip, dstport, srcport))
				{
					HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Versiom = *(unsigned short *)((unsigned char *)SSLHandShakeLayer + 4);
					HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].CipherSuite = *(unsigned short *)((unsigned char *)SSLHandShakeLayer + 39 + *((unsigned char *)SSLHandShakeLayer + 38));
				}
				break;

			case SSL_SERVER_KEY_EXCHANGE:

				if (this->isCorrespondingHandShakeContent(dstip, srcip, dstport, srcport))
				{
					HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen = *((unsigned char *)SSLHandShakeLayer + 7);

					// �M����l�ҥe�O���骺�Ŷ�
					if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey != NULL)
					{
						delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey;
					}

					// �ᤩPubkey �O����Ŷ����j�p�� PubkeyLen + 1
					HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen + 1];

					//  Pubkey �b�ӫʥ]���èS������
					if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen + 13 <= TcpRemainingLen)
					{
						for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen; i++)
						{
							*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey + i) = *((unsigned char *)SSLHandShakeLayer + 8 + i);
						}
					}
					//  Pubkey �b�ӫʥ]�����Q����A�]���L�k���o���㪺Pubkey�A�ݭn�b�������U�@�ӫʥ]���X�ѤU���_�ͤ��e
					else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen > (TcpRemainingLen - 13) )
					{
						// �ݭn�A�]�p Code ���o�Q�������_�ͤ��e�A�o�̥��]����׬�0�A�קK�� key ���ȿ��~
						/*HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen = 0; break;*/
						int x;
						for (x = 0; x < (TcpRemainingLen - 13) ; x++)
						{
							*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey + x) = *((unsigned char *)SSLHandShakeLayer + 8 + x);
						}
						SetReassemblePubkeyTable(srcip,dstip,srcport,dstport, HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen - (TcpRemainingLen - 13), HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey + x);
					}
				}
				break;

			case SSL_CLIENT_KEY_EXCHANGE:
				if (this->isCorrespondingHandShakeContent(srcip, dstip, srcport, dstport))
				{
					// memory size of the key length over 1 Byte 
					if (ntohs(SSLHandShakeLayer->length2) >= 258)   
					{
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = ntohs(*((unsigned short*)((unsigned char *)SSLHandShakeLayer + 4)));

						// �M����l�ҥe�O���骺�Ŷ�
						if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey != NULL)
						{
							delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey;
						}

						// �ᤩSessionKey �O����Ŷ����j�p�� SessionKeyLen + 1
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen + 1];

						//  SessionKey �b�ӫʥ]���èS������
						if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen <= TcpRemainingLen - 11)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen; i++)
							{
								*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 6 + i);
							}
						}
						//  SessionKey �b�ӫʥ]�����Q����A�]���L�k���o���㪺SessionKey�A�ݭn�b�������U�@�ӫʥ]���X�ѤU���_�ͤ��e
						else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen > TcpRemainingLen - 11)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen - (TcpRemainingLen - 11); i++)
							{
								// �ݭn�A�]�p Code ���o�Q�������_�ͤ��e�A�o�̥��]����׬�0�A�קK�� key ���ȿ��~
								HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = 0; break;
								/**(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 6 + i);*/

							}
						}

					}
					// memory size of the key length just have 1 Byte
					else
					{
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = *((unsigned char *)SSLHandShakeLayer + 4);
						// �M����l�ҥe�O���骺�Ŷ�
						if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey != NULL)
						{
							delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey;
						}

						// �ᤩSessionKey �O����Ŷ����j�p�� SessionKeyLen + 1
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen + 1];

						//  SessionKey �b�ӫʥ]���èS������
						if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen <= TcpRemainingLen - 10)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen; i++)
							{
								*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 5 + i);
							}
						}
						//  SessionKey �b�ӫʥ]�����Q����A�]���L�k���o���㪺SessionKey�A�ݭn�b�������U�@�ӫʥ]���X�ѤU���_�ͤ��e
						else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen > TcpRemainingLen - 10)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen - (TcpRemainingLen - 10); i++)
							{
								//  SessionKey �b�ӫʥ]�����Q����A�]���L�k���o���㪺SessionKey�A�ݭn�b�������U�@�ӫʥ]���X�ѤU���_�ͤ��e
								HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = 0; break;
								/**(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 5 + i);*/
							}
						}

					}
				}
				break;

			case SSL_NEW_SESSION_TICKET:

				needSearch = true;   //�]���b�n���ɥ������ˬd�w�n������Ʀs��h�[�F�A�ݭnTable�j��@��;�ӷ���n�n���s�񪺦a�I���� needSearch �N�� false ��ܤw�n�����ݭn�A�~��n���F
				// �N������Ƶn���� HandShakeMainContentBuffer
				for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
				{
					if (HandShakeMainContentBuffer[i].isCanUse == false)  // �w�n�������
					{
						HandShakeMainContentBuffer[i].TTL += 1;             // �s�����ƥ[1
						if (HandShakeMainContentBuffer[i].TTL >= MAX_HandShakeMainContent_BUFFER) // �w�s�bTable��>=MAX_HandShakeMainContent_BUFFER��
						{
							HandShakeMainContentBuffer[i].isCanUse = true;
							HandShakeMainContentBuffer[i].isContentOK = false;
							HandShakeMainContentBuffer[i].TTL = 0;
							HandShakeMainContentBuffer[i].UserIP = 0;
							HandShakeMainContentBuffer[i].ServerIP = 0;
							HandShakeMainContentBuffer[i].UserPort = 0;
							HandShakeMainContentBuffer[i].ServerPort = 0;
							HandShakeMainContentBuffer[i].Versiom = 0;
							HandShakeMainContentBuffer[i].CipherSuite = 0;
							HandShakeMainContentBuffer[i].PubKeyLen = 0;
							HandShakeMainContentBuffer[i].Pubkey = 0;
							HandShakeMainContentBuffer[i].SessionKeyLen = 0;
							HandShakeMainContentBuffer[i].SessionKey = 0;
							HandShakeMainContentBuffer[i].NewSessionTicketLen = 0;
							HandShakeMainContentBuffer[i].NewSessionTicket = 0;
						}
					}
					if (HandShakeMainContentBuffer[i].isCanUse && needSearch == true)
					{
						needSearch = false;
						index = i;

						HandShakeMainContentBuffer[i].isCanUse = FALSE;
						HandShakeMainContentBuffer[i].isContentOK = FALSE;
						HandShakeMainContentBuffer[i].UserIP = dstip;
						HandShakeMainContentBuffer[i].ServerIP = srcip;
						HandShakeMainContentBuffer[i].UserPort = dstport;
						HandShakeMainContentBuffer[i].ServerPort = srcport;
					}
				}

				HandShakeMainContentBuffer[index].Versiom = m_RecordLayer->recordVersion;
				HandShakeMainContentBuffer[index].NewSessionTicketLen = ntohs(*(unsigned short*)((unsigned char *)SSLHandShakeLayer + sizeof(ssl_tls_handshake_layer) + 4));

				// �R����l�Ҧ����O����Ŷ�
				if (HandShakeMainContentBuffer[index].NewSessionTicket != NULL)
				{
					delete[] HandShakeMainContentBuffer[index].NewSessionTicket;
				}

				// �ᤩ NewSessionTicket �O����Ŷ����j�p�� NewSessionTicketLen + 1
				HandShakeMainContentBuffer[index].NewSessionTicket = new unsigned char[HandShakeMainContentBuffer[index].NewSessionTicketLen + 1];

				// NewSessionTicket ���|�Q�ʥ]�����]���i�H�������
				for (int x = 0; x < HandShakeMainContentBuffer[index].NewSessionTicketLen; x++)
				{
					*(HandShakeMainContentBuffer[index].NewSessionTicket + x) = *((unsigned char *)SSLHandShakeLayer + sizeof(ssl_tls_handshake_layer) + 6 + x);
				}
			
				this->HandShakeMainContentBufferToHandShakeMainContent(index);
				// �N�� HandShakeMainContent �O�i�Q���Ȫ����A
				HandShakeMainContentBuffer[index].isContentOK = TRUE;

				break;
			}
		}
		// �� RecordLayer �� Type �� SSL CHANGE CIPHER SPEC �N��F���ϥέ�跾�q�洫���_�͡A�]���i�N���ҵn�J����ƪ����A�]���i�H����������e
		else if (type == 1 && m_RecordLayer->recordType == SSL_CHANGE_CIPHER_SPEC && m_HandShakeLayer == NULL)
		{
			if (this->isCorrespondingHandShakeContent(srcip, dstip, srcport, dstport))
			{			
				this->HandShakeMainContentBufferToHandShakeMainContent(CorrespondingHandShakeContentIndex);
				HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].isContentOK = TRUE;
			}
		}
	}

	// ���o HandShakeMainContentBuffer[i].isContentOK == TRUE �ɹ��� HandShakeMainContent �����
	bool HandShakeLayerAndChangeCipherSpecLayer::GetMainContent(unsigned char **UserIP, unsigned char **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, int *PubKeyLen, unsigned char **Pubkey, int *SessionKeyLen, unsigned char **SessionKey, int *NewSessionTicketLen, unsigned char **NewSessionTicket)
	{
		for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
		{
			if (HandShakeMainContentBuffer[i].isContentOK == TRUE)
			{
				*UserIP = HandShakeMainContent[i].UserIP;
				*ServerIP = HandShakeMainContent[i].ServerIP;
				*UserPort = HandShakeMainContent[i].UserPort;
				*ServerPort = HandShakeMainContent[i].ServerPort;
				*Version = HandShakeMainContent[i].Versiom;
				*CipherSuite = HandShakeMainContent[i].CipherSuite;
				*PubKeyLen = HandShakeMainContent[i].PubKeyLen;
				*Pubkey = HandShakeMainContent[i].Pubkey;
				*SessionKeyLen = HandShakeMainContent[i].SessionKeyLen;
				*SessionKey = HandShakeMainContent[i].SessionKey;
				*NewSessionTicketLen = HandShakeMainContent[i].NewSessionTicketLen;
				*NewSessionTicket = HandShakeMainContent[i].NewSessionTicket;

				HandShakeMainContentBuffer[i].isContentOK = FALSE;
				HandShakeMainContentBuffer[i].isCanUse = TRUE;			
				HandShakeMainContent[i].UserPort = 0;
				HandShakeMainContent[i].ServerPort = 0;
				HandShakeMainContent[i].Versiom = 0;
				HandShakeMainContent[i].CipherSuite = 0;
				HandShakeMainContent[i].PubKeyLen = 0;
				HandShakeMainContent[i].SessionKeyLen = 0;
				HandShakeMainContent[i].NewSessionTicketLen = 0;

				return true;
			}
		}
		return false;
	}

	// ���o�ҳѤUPubkey���e
	void  HandShakeLayerAndChangeCipherSpecLayer::GetRemainPubkey(unsigned int SrcIP, unsigned int DstIP, unsigned short SrcPort, unsigned short DstPort, unsigned char * Byte)
	{
		for (int i = 0; i < MAX_ReassemblePubkey_BUFFER; i++)
		{
			if (ReassemblePubkey[i].isCanUse == false &&
				ReassemblePubkey[i].ServerIP == SrcIP &&
				ReassemblePubkey[i].UserIP == DstIP &&
				ReassemblePubkey[i].ServerPort == SrcPort &&
				ReassemblePubkey[i].UserPort == DstPort)
			{
				for (int x = 0; x < ReassemblePubkey[i].ReaminPubkeyLen; x++)
				{
					*(ReassemblePubkey[i].Pubkey + x) = *(Byte + x);
				}

				ReassemblePubkey[i].isCanUse = true;
				ReassemblePubkey[i].TTL = 0;
				ReassemblePubkey[i].ServerIP = 0;
				ReassemblePubkey[i].UserIP = 0;
				ReassemblePubkey[i].ServerPort = 0;
				ReassemblePubkey[i].UserPort = 0;
				ReassemblePubkey[i].ReaminPubkeyLen = 0;
				ReassemblePubkey[i].Pubkey = 0;

				return;
			}
		}
	}

	///////////////////////////////  Private  ///////////////////////////////

	// ��X HandShakeMainContentBuffer �̹�����index
	bool HandShakeLayerAndChangeCipherSpecLayer::isCorrespondingHandShakeContent(unsigned int userip, unsigned int serverip, unsigned short userport, unsigned short serverport)
	{
		for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
		{
			if ((HandShakeMainContentBuffer[i].UserIP == userip) &&
				(HandShakeMainContentBuffer[i].ServerIP == serverip) &&
				(HandShakeMainContentBuffer[i].UserPort == userport) &&
				(HandShakeMainContentBuffer[i].ServerPort == serverport))
			{
				CorrespondingHandShakeContentIndex = i;
				return TRUE;
			}
		}
		return FALSE;
	}

	// �N HandShakeMainContentBuffer ����Ƶn���� HandShakeMainContent
	void HandShakeLayerAndChangeCipherSpecLayer::HandShakeMainContentBufferToHandShakeMainContent(int i)
	{
		HandShakeMainContent[i].UserIP[3] = ntohl(HandShakeMainContentBuffer[i].UserIP) / 0x1000000;
		HandShakeMainContent[i].UserIP[2] = ntohl(HandShakeMainContentBuffer[i].UserIP) / 0x10000 - HandShakeMainContent[i].UserIP[3] * 0x100;
		HandShakeMainContent[i].UserIP[1] = ntohl(HandShakeMainContentBuffer[i].UserIP) / 0x100 - HandShakeMainContent[i].UserIP[3] * 0x10000 - HandShakeMainContent[i].UserIP[2] * 0x100;
		HandShakeMainContent[i].UserIP[0] = ntohl(HandShakeMainContentBuffer[i].UserIP) - HandShakeMainContent[i].UserIP[3] * 0x1000000 - HandShakeMainContent[i].UserIP[2] * 0x10000 - HandShakeMainContent[i].UserIP[1] * 0x100;

		HandShakeMainContent[i].ServerIP[3] = ntohl(HandShakeMainContentBuffer[i].ServerIP) / 0x1000000;
		HandShakeMainContent[i].ServerIP[2] = ntohl(HandShakeMainContentBuffer[i].ServerIP) / 0x10000 - HandShakeMainContent[i].ServerIP[3] * 0x100;
		HandShakeMainContent[i].ServerIP[1] = ntohl(HandShakeMainContentBuffer[i].ServerIP) / 0x100 - HandShakeMainContent[i].ServerIP[3] * 0x10000 - HandShakeMainContent[i].ServerIP[2] * 0x100;
		HandShakeMainContent[i].ServerIP[0] = ntohl(HandShakeMainContentBuffer[i].ServerIP) - HandShakeMainContent[i].ServerIP[3] * 0x1000000 - HandShakeMainContent[i].ServerIP[2] * 0x10000 - HandShakeMainContent[i].ServerIP[1] * 0x100;

		// HandShakeMainContentBuffer ��Ʋ��ܹ����� HandShakeMainContent
		HandShakeMainContent[i].UserPort = HandShakeMainContentBuffer[i].UserPort;
		HandShakeMainContent[i].ServerPort = HandShakeMainContentBuffer[i].ServerPort;
		HandShakeMainContent[i].Versiom = ntohs(HandShakeMainContentBuffer[i].Versiom);
		HandShakeMainContent[i].CipherSuite = ntohs(HandShakeMainContentBuffer[i].CipherSuite);
		HandShakeMainContent[i].PubKeyLen = HandShakeMainContentBuffer[i].PubKeyLen;
		HandShakeMainContent[i].Pubkey = HandShakeMainContentBuffer[i].Pubkey;
		HandShakeMainContent[i].SessionKeyLen = HandShakeMainContentBuffer[i].SessionKeyLen;
		HandShakeMainContent[i].SessionKey = HandShakeMainContentBuffer[i].SessionKey;
		HandShakeMainContent[i].NewSessionTicketLen = HandShakeMainContentBuffer[i].NewSessionTicketLen;
		HandShakeMainContent[i].NewSessionTicket = HandShakeMainContentBuffer[i].NewSessionTicket;

		// ��l HandShakeMainContentBuffer ����ơA���F���A�ݩ�(isCanUse�BisContentOK)
		HandShakeMainContentBuffer[i].UserIP = NULL;
		HandShakeMainContentBuffer[i].ServerIP = NULL;
		HandShakeMainContentBuffer[i].UserPort = NULL;
		HandShakeMainContentBuffer[i].ServerPort = NULL;
		HandShakeMainContentBuffer[i].Versiom = NULL;
		HandShakeMainContentBuffer[i].CipherSuite = NULL;
		HandShakeMainContentBuffer[i].PubKeyLen = NULL;
		HandShakeMainContentBuffer[i].Pubkey = NULL;
		HandShakeMainContentBuffer[i].SessionKeyLen = NULL;
		HandShakeMainContentBuffer[i].SessionKey = NULL;
		HandShakeMainContentBuffer[i].NewSessionTicketLen = NULL;
		HandShakeMainContentBuffer[i].NewSessionTicket = NULL;
	}

	// ��l HandShakeMainContentBuffer Table
	void HandShakeLayerAndChangeCipherSpecLayer::InitialHandShakeMainContentBuffer()
	{
		for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
		{
			HandShakeMainContentBuffer[i].isCanUse = TRUE;
			HandShakeMainContentBuffer[i].isContentOK = FALSE;
			HandShakeMainContentBuffer[i].TTL = 0;
			HandShakeMainContentBuffer[i].UserIP = NULL;
			HandShakeMainContentBuffer[i].ServerIP = NULL;
			HandShakeMainContentBuffer[i].UserPort = 0;
			HandShakeMainContentBuffer[i].ServerPort = 0;
			HandShakeMainContentBuffer[i].Versiom = 0;
			HandShakeMainContentBuffer[i].CipherSuite = 0;
			HandShakeMainContentBuffer[i].PubKeyLen = 0;
			HandShakeMainContentBuffer[i].Pubkey = NULL;
			HandShakeMainContentBuffer[i].SessionKeyLen = 0;
			HandShakeMainContentBuffer[i].SessionKey = NULL;
			HandShakeMainContentBuffer[i].NewSessionTicketLen = 0;
			HandShakeMainContentBuffer[i].NewSessionTicket = NULL;
		}
	}

	// ��l ReassemblePubkey table
	void HandShakeLayerAndChangeCipherSpecLayer::InitialReassemblePubkeyTable()
	{
		for (int i = 0; i < MAX_ReassemblePubkey_BUFFER; i++)
		{
			ReassemblePubkey[i].isCanUse = true;
			ReassemblePubkey[i].TTL = 0;
			ReassemblePubkey[i].ServerIP = 0;
			ReassemblePubkey[i].UserIP = 0 ;
			ReassemblePubkey[i].ServerPort = 0;
			ReassemblePubkey[i].UserPort = 0;
			ReassemblePubkey[i].ReaminPubkeyLen = 0;
			ReassemblePubkey[i].Pubkey = 0;
		}
	}

	// �]�m ReassemblePubkey Table ���
	void HandShakeLayerAndChangeCipherSpecLayer::SetReassemblePubkeyTable(unsigned int ServerIP, unsigned int UserIP, unsigned short ServerPort, unsigned short UserPort, int KeyRemainingLen, unsigned char * Key)
	{
		bool needFind = true;

		for (int i = 0; i < MAX_ReassemblePubkey_BUFFER; i++)
		{
			if (ReassemblePubkey[i].isCanUse == false)
			{
				ReassemblePubkey[i].TTL += 1;
				if (ReassemblePubkey[i].TTL == MAX_ReassemblePubkey_BUFFER)
				{
					ReassemblePubkey[i].isCanUse = true;
					ReassemblePubkey[i].TTL = 0;
					ReassemblePubkey[i].ServerIP = 0;
					ReassemblePubkey[i].UserIP = 0;
					ReassemblePubkey[i].ServerPort = 0;
					ReassemblePubkey[i].UserPort = 0;
					ReassemblePubkey[i].ReaminPubkeyLen = 0;
					ReassemblePubkey[i].Pubkey = 0;
				}
			}
			if (ReassemblePubkey[i].isCanUse == true && needFind == true)
			{
				needFind = false;
				ReassemblePubkey[i].isCanUse = false;
				ReassemblePubkey[i].TTL = 0;
				ReassemblePubkey[i].ServerIP = ServerIP;
				ReassemblePubkey[i].UserIP = UserIP;
				ReassemblePubkey[i].ServerPort = ServerPort;
				ReassemblePubkey[i].UserPort = UserPort;
				ReassemblePubkey[i].ReaminPubkeyLen = KeyRemainingLen;
				ReassemblePubkey[i].Pubkey = Key;
			}
		}
	}
