#include "stdafx.h"
#include "winsock2.h"
#include "SSLAnalyze.h"


	////////////////////////////////////////////////////////////////// Class SSLAnalyze //////////////////////////////////////////////////////////////////
	SSLAnalyze::SSLAnalyze()
	{
		pkt_data = NULL;
		this->clearReassemblyPacketTable();
	}

	// 輸入 Row Packet
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

			// 判斷為是SSL的封包(第一包未被切割)
			if (this->isSSLRecordLayer() && TcpSegmentLen != 0)
			{
				// 若是 Application Data Layer 登錄相關資料後不用繼續其他分析
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
			// 判斷為是被切割的SSL封包
			else if (this->isRemainingPacket(index) && TcpSegmentLen != 0)
			{			
				// 若是 Application Data Layer 即可不用做進一步分析。
				if (ReassemblyPacketTable[index].isAppLayer == true)
				{
					return;
				}

				// 有時候HandShake Layer的Pubkey會被封包所切掉，這裡是要來尋找其剩下的鑰匙內容
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
			// 不是 SSL封包
			else
			{
				IsSSLRecordLayer = FALSE;
			}
		}
	}

	// 取得 HandShake 交換鑰匙資訊
	 bool SSLAnalyze::GetHandShakeMainContent(unsigned char **UserIP, unsigned char **ServerIP, unsigned short *UserPort, unsigned short *ServerPort, unsigned short *Version, unsigned short *CipherSuite, int *PubKeyLen, unsigned char **Pubkey, int *SessionKeyLen, unsigned char **SessionKey, int *NewSessionTicketLen, unsigned char **NewSessionTicket)
	{
		return HandShakeLayer.GetMainContent(UserIP, ServerIP, UserPort, ServerPort, Version, CipherSuite, PubKeyLen, Pubkey, SessionKeyLen, SessionKey, NewSessionTicketLen, NewSessionTicket);	
	}

	///////////////////////////////  Private  ///////////////////////////////

	 // 判斷是否為 SSL Record Layer，設值(IsSSLRecordLayer) 
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

	// 判斷此封包是否為被切割的SSL封包
	bool SSLAnalyze::isRemainingPacket(int &index)
	{		
		for (int i = 0; i < MAX_ReassemblyPacketTable_BUFFER ; i++)
		{
			if ((ReassemblyPacketTable[i].isCanUse == false ) &&                         // Table 是已登錄狀態
				(iphdr->ip_srcaddr == ReassemblyPacketTable[i].ip_srcaddr) &&
				(iphdr->ip_destaddr == ReassemblyPacketTable[i].ip_destaddr) &&
				(ntohs(tcpheader->source_port) == ReassemblyPacketTable[i].SrcPort) &&
				(ntohs(tcpheader->dest_port) == ReassemblyPacketTable[i].DstPort) )
			{
				// 不是 Application Data Layer 的話要判斷是否為對應 sequence ，是即可直接從 table 中消除(即可以使用這個 Table)
				if (ReassemblyPacketTable[i].isAppLayer == false &&  ntohl(tcpheader->sequence) == ReassemblyPacketTable[i].NextSequence)
				{
					index = i;					
					ReassemblyPacketTable[i].isCanUse = TRUE;

					IsSSLRecordLayer = TRUE;
					return TRUE;
				}
				// 為 Application Data Layer 的話繼續登錄在 table 中，以便判斷下包是否為 Application Data
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

	// 初始 ReassemblyPacketTable
	void SSLAnalyze::clearReassemblyPacketTable()
	{
		for (int i = 0; i<MAX_ReassemblyPacketTable_BUFFER; i++)
		{
			ReassemblyPacketTable[i].isCanUse = TRUE;
			ReassemblyPacketTable[i].LiveTime = 0;
			ReassemblyPacketTable[i].isAppLayer = false;
		}
	}

	// For type = 1，每個 HandShakeLayer 前都有各自的 RecordLayer 
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

	// For type = 2，所有 HandShakeLayer 被包在一個 Record Layer
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

	// 登錄被切割封包的相關資料，以辨識下一包封包是否為SSL封包
	void SSLAnalyze::SetReassemblyPacketTable(unsigned short len, int m_type)
	{
		int i;
		bool NeedFindTableSpace = true;

		// 已登錄的資料可能因為對應的下一封包沒來，而無法消除此筆資料導致一直暫存在 ReassemblyPacketTable 裡，因此設置當存活次數太久就刪除
		for (i = 0; i < MAX_ReassemblyPacketTable_BUFFER; i++)
		{
			if (ReassemblyPacketTable[i].isCanUse == FALSE)
			{
				ReassemblyPacketTable[i].LiveTime += 1;

				// 判斷是否為 APPLICATION DATA Layer 並且判斷是否已經登錄過，是則初始 LiveTime，不用再登錄一次資料
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

		// 登錄被切到的SSL封包的下一封包的資訊
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

				// 判斷是否為 Application Data Layer , 若是的話並不需要考慮下一包 Sequence 是多少，只需要判斷其 PORT
				if (RecordLayer->recordType != SSL_APPLICATION_DATA || m_type == 2 ) //m_type == 2時一定是HandShake Layer不是APPLICATION_DATA
				{
					ReassemblyPacketTable[i].isAppLayer = false;
					ReassemblyPacketTable[i].Sequence = ntohl(tcpheader->sequence);
					ReassemblyPacketTable[i].NextSequence = ntohl(tcpheader->sequence) + TcpSegmentLen;
					ReassemblyPacketTable[i].RemainingLen = len;  // 封包資料被切掉所剩的長度
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

	// 判斷是否為 SSL Record Layer，不設值(IsSSLRecordLayer)
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

	// 判斷 Record Layer Type 是否為 HandShakeLayer || ChangeCipherSpecLayer
	bool SSLAnalyze::isHandShakeLayerOrChangeCipherSpecLayer(ssl_tls_record_layer *m_RecordLayet)
	{
		if ((m_RecordLayet->recordType == SSL_HANDSHAKE) || (m_RecordLayet->recordType == SSL_CHANGE_CIPHER_SPEC))
		{
			return TRUE;
		}
		return FALSE;
	}





	//////////////////////////////////////////////////////////////// Class HandShakeLayer ////////////////////////////////////////////////////////////////

	// 初始 HandShakeMainContentBuffer
	HandShakeLayerAndChangeCipherSpecLayer::HandShakeLayerAndChangeCipherSpecLayer()
	{
		CorrespondingHandShakeContentIndex = 0;
		InitialReassemblePubkeyTable();
		InitialHandShakeMainContentBuffer();
	}

	// 儲存交換鑰匙的相關資料，從 SSL Record Type == SSL_HANDSHAKE || SSL_CHANGE_CIPHER_SPEC 中取得相關資料
	void HandShakeLayerAndChangeCipherSpecLayer::SetHandShakeMainContent(ssl_tls_record_layer *m_RecordLayer, unsigned int srcip, unsigned int dstip, unsigned short srcport, unsigned short dstport, int TcpRemainingLen, int type, ssl_tls_handshake_layer *m_HandShakeLayer)
	{
		int /*i = 0 ,*/ index = 0;
		bool needSearch;

		// 所有的 HandShakeLayer 都包在同一個RecordLayer : type = 2 , 
		if (type == 2 && m_HandShakeLayer != NULL && m_RecordLayer == NULL)
		{
			SSLHandShakeLayer = m_HandShakeLayer;
			SSLHandshakeType = (enum SSLHandshakeType)SSLHandShakeLayer->handshakeType;
			if (TcpRemainingLen != 0) 
			{
				// 當初設計上錯誤，使其長度是從RecordLayer前計算，之後的計算才可以和 type 1 相同計算方式
				TcpRemainingLen = TcpRemainingLen + sizeof(ssl_tls_record_layer) + sizeof(ssl_tls_handshake_layer);
			}
			goto HasHandShakeLayer;
		}
		// 每一個 HandShakeLayer 都擁有自己的 ReacodLayer : type = 1
		else if (type == 1 && m_RecordLayer->recordType == SSL_HANDSHAKE && m_HandShakeLayer == NULL)
		{
			SSLHandShakeLayer = (ssl_tls_handshake_layer *)((unsigned char *)m_RecordLayer + sizeof(ssl_tls_record_layer));
			SSLHandshakeType = (enum SSLHandshakeType)SSLHandShakeLayer->handshakeType;

		    HasHandShakeLayer:
			switch (SSLHandshakeType)
			{
			case SSL_CLIENT_HELLO:
			
				needSearch = true;   //因為在登錄時必須先檢查已登錄的資料存放多久了，需要Table迴圈一次;而當找到要登錄存放的地點的話 needSearch 就為 false 表示已登錄不需要再繼續登錄了
				// 將相關資料登錄至HandShakeMainContentBuffer
				for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
				{		
					if ( HandShakeMainContentBuffer[i].isCanUse == false )  // 已登錄中資料
					{
						HandShakeMainContentBuffer[i].TTL += 1;             // 存活次數加1
						if (HandShakeMainContentBuffer[i].TTL >= MAX_HandShakeMainContent_BUFFER) // 已存在Table中>=MAX_HandShakeMainContent_BUFFER次
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
				//	bool error = true;    // Buffer已滿
				//}
				break;

			case  SSL_SERVER_HELLO:

				// 找出在 HandShakeMainContentBuffer 裡對應的index並在登錄相關資料
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

					// 清除原始所占記憶體的空間
					if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey != NULL)
					{
						delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey;
					}

					// 賦予Pubkey 記憶體空間的大小為 PubkeyLen + 1
					HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen + 1];

					//  Pubkey 在該封包中並沒有切掉
					if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen + 13 <= TcpRemainingLen)
					{
						for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen; i++)
						{
							*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].Pubkey + i) = *((unsigned char *)SSLHandShakeLayer + 8 + i);
						}
					}
					//  Pubkey 在該封包中有被切到，因此無法取得完整的Pubkey，需要在對應的下一個封包取出剩下的鑰匙內容
					else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].PubKeyLen > (TcpRemainingLen - 13) )
					{
						// 需要再設計 Code 取得被切掉的鑰匙內容，這裡先設其長度為0，避免取 key 的值錯誤
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

						// 清除原始所占記憶體的空間
						if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey != NULL)
						{
							delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey;
						}

						// 賦予SessionKey 記憶體空間的大小為 SessionKeyLen + 1
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen + 1];

						//  SessionKey 在該封包中並沒有切掉
						if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen <= TcpRemainingLen - 11)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen; i++)
							{
								*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 6 + i);
							}
						}
						//  SessionKey 在該封包中有被切到，因此無法取得完整的SessionKey，需要在對應的下一個封包取出剩下的鑰匙內容
						else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen > TcpRemainingLen - 11)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen - (TcpRemainingLen - 11); i++)
							{
								// 需要再設計 Code 取得被切掉的鑰匙內容，這裡先設其長度為0，避免取 key 的值錯誤
								HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = 0; break;
								/**(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 6 + i);*/

							}
						}

					}
					// memory size of the key length just have 1 Byte
					else
					{
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = *((unsigned char *)SSLHandShakeLayer + 4);
						// 清除原始所占記憶體的空間
						if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey != NULL)
						{
							delete[] HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey;
						}

						// 賦予SessionKey 記憶體空間的大小為 SessionKeyLen + 1
						HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey = new unsigned char[HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen + 1];

						//  SessionKey 在該封包中並沒有切掉
						if (TcpRemainingLen == 0 || HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen <= TcpRemainingLen - 10)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen; i++)
							{
								*(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 5 + i);
							}
						}
						//  SessionKey 在該封包中有被切到，因此無法取得完整的SessionKey，需要在對應的下一個封包取出剩下的鑰匙內容
						else if (HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen > TcpRemainingLen - 10)
						{
							for (int i = 0; i < HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen - (TcpRemainingLen - 10); i++)
							{
								//  SessionKey 在該封包中有被切到，因此無法取得完整的SessionKey，需要在對應的下一個封包取出剩下的鑰匙內容
								HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKeyLen = 0; break;
								/**(HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].SessionKey + i) = *((unsigned char *)SSLHandShakeLayer + 5 + i);*/
							}
						}

					}
				}
				break;

			case SSL_NEW_SESSION_TICKET:

				needSearch = true;   //因為在登錄時必須先檢查已登錄的資料存放多久了，需要Table迴圈一次;而當找到要登錄存放的地點的話 needSearch 就為 false 表示已登錄不需要再繼續登錄了
				// 將相關資料登錄至 HandShakeMainContentBuffer
				for (int i = 0; i < MAX_HandShakeMainContent_BUFFER; i++)
				{
					if (HandShakeMainContentBuffer[i].isCanUse == false)  // 已登錄中資料
					{
						HandShakeMainContentBuffer[i].TTL += 1;             // 存活次數加1
						if (HandShakeMainContentBuffer[i].TTL >= MAX_HandShakeMainContent_BUFFER) // 已存在Table中>=MAX_HandShakeMainContent_BUFFER次
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

				// 刪除原始所佔的記憶體空間
				if (HandShakeMainContentBuffer[index].NewSessionTicket != NULL)
				{
					delete[] HandShakeMainContentBuffer[index].NewSessionTicket;
				}

				// 賦予 NewSessionTicket 記憶體空間的大小為 NewSessionTicketLen + 1
				HandShakeMainContentBuffer[index].NewSessionTicket = new unsigned char[HandShakeMainContentBuffer[index].NewSessionTicketLen + 1];

				// NewSessionTicket 不會被封包切掉因此可以直接賦值
				for (int x = 0; x < HandShakeMainContentBuffer[index].NewSessionTicketLen; x++)
				{
					*(HandShakeMainContentBuffer[index].NewSessionTicket + x) = *((unsigned char *)SSLHandShakeLayer + sizeof(ssl_tls_handshake_layer) + 6 + x);
				}
			
				this->HandShakeMainContentBufferToHandShakeMainContent(index);
				// 代表 HandShakeMainContent 是可被取值的狀態
				HandShakeMainContentBuffer[index].isContentOK = TRUE;

				break;
			}
		}
		// 當 RecordLayer 的 Type 為 SSL CHANGE CIPHER SPEC 代表達成使用剛剛溝通交換的鑰匙，因此可將剛剛所登入的資料的狀態設為可以取其相關內容
		else if (type == 1 && m_RecordLayer->recordType == SSL_CHANGE_CIPHER_SPEC && m_HandShakeLayer == NULL)
		{
			if (this->isCorrespondingHandShakeContent(srcip, dstip, srcport, dstport))
			{			
				this->HandShakeMainContentBufferToHandShakeMainContent(CorrespondingHandShakeContentIndex);
				HandShakeMainContentBuffer[CorrespondingHandShakeContentIndex].isContentOK = TRUE;
			}
		}
	}

	// 取得 HandShakeMainContentBuffer[i].isContentOK == TRUE 時對應 HandShakeMainContent 的資料
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

	// 取得所剩下Pubkey內容
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

	// 找出 HandShakeMainContentBuffer 裡對應的index
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

	// 將 HandShakeMainContentBuffer 的資料登錄至 HandShakeMainContent
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

		// HandShakeMainContentBuffer 資料移至對應的 HandShakeMainContent
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

		// 初始 HandShakeMainContentBuffer 的資料，除了狀態屬性(isCanUse、isContentOK)
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

	// 初始 HandShakeMainContentBuffer Table
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

	// 初始 ReassemblePubkey table
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

	// 設置 ReassemblePubkey Table 資料
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
