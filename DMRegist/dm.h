#ifndef _DM_H
#define _DM_H

#include <stdio.h>
typedef int bool;
#define false 0
#define true  1

#pragma pack(1)
struct _CommPkt
{
	uint8_t bKey[8];
	uint32_t dwHeadCrc;
	uint32_t dwPktCrc;
	uint32_t dwFlag;
	uint32_t dwSize;
	uint32_t dwOp;
	uint32_t dwType;
	uint32_t dwWhat;
	uint32_t dwEquType;
	uint64_t dwEquID;
	uint64_t dwCorpID;
	uint64_t dwTransID;
	uint64_t dwTransLen;
	uint64_t dwSequence;
	uint32_t dwCellLen;
	bool     IsEncrypt;
	bool     IsRemoteRes;
}__attribute__ ((aligned (1)));
typedef struct _CommPkt CommPkt, *pCommPkt;
#pragma pack()

#define PKT_FLAG				183356126
#define HEAD_SIZE				sizeof(CommPkt)
#define KEY_SIZE				8
#define PKT_OFFSET				(KEY_SIZE+sizeof(DWORD))

#define REQ_PKT					0
#define RES_PKT					1

#define	CMD_TYPE_COMMON_LINK						3200
#define	CMD_WHAT_COMMON_SINGLE						3201

#endif
