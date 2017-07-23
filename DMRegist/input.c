 /**********************************
 created: 2014/05/12
 filename: CreateXmlFile.c
 auther: wang kai
 depend: libxml2.lib
 purpose: ???????xml???
 **********************************/

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <errno.h>
#include <ctype.h>
#include <linux/hdreg.h>
#include <stdlib.h>
#include <netinet/in.h>       /* for sockaddr_in */
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/statvfs.h>

#include "dm.h"
#include "crc32.h"

#define BUFFSIZE (64*1024)
typedef unsigned long long jiff;

typedef struct _CONFIG_INFOR{
	char chServiceIpAddr[32];
	char chOrganId[32];
	char chDeviceId[32];
	char chDeviceNum[32];
	char chDeviceType[32];
	char chUserName[32];
}CONFIG_INFOR;

typedef struct _ITEM_NODE{
	unsigned char chName[32];
	unsigned char chFild[32];
	unsigned char chType[32];
	unsigned char chMust[8];
	unsigned char chTable[32];
	unsigned char chDesc[128];
	unsigned char chValue[32];
	unsigned char chIndex[32];
}ITEM_NODE;

typedef struct _LIST_VALUE{
	unsigned char chValue[32];
	unsigned char chIndex[32];
}LIST_VALUE;

ITEM_NODE* gItemArray=NULL;

ITEM_NODE* gReportItemArray=NULL;

CONFIG_INFOR gConfigInfor={0};

/* hardwar info struct */
typedef struct _DEVICE_INFOR {
	char product_name[128];
	char cpu_model[128];
	char os_type[128];
	char os_rel[128];
	char cpu_hz[128];
	int  cpu_cores;
	char cpu_serial[128];
}DEVICE_INFOR;

/* memery usage stat struct */
struct mem_stat_t {
	unsigned long tot;
	unsigned long free;
};
typedef struct  mem_stat_t *pmem_stat_t;


/* disk stat struct */
struct disk_stat_t {
	jiff tot;
	jiff free;
};
typedef struct  disk_stat_t *pdisk_stat_t;

void ReadConfig(char* ipaddr,char* organid,char* deviceid)
{
	char *p = NULL;
	FILE *devid_fp;
	FILE *fp = fopen("/usr/local/sinopec/cfg","r");
	if(fp==NULL)
	{
		perror("fopen error\n");
		exit(-1);
	}

	if(fgets(ipaddr,32,fp)==NULL)
	{
		fclose(fp);
		perror("fgets error");
		exit(-1);
	}

	p = strchr(ipaddr,'\n');
	if(p != NULL)
	{
		*p = '\0';
	}
	else
	{
		fclose(fp);
		exit(-1);
	}
	if(fgets(organid,32,fp) == NULL)
	{
		fclose(fp);
		perror("get organid error");
		exit(-1);
	}

	p = strchr(organid,'\n');
	if(p != NULL)
	{
		*p = '\0';
	}
	else
	{
		fclose(fp);
		exit(-1);
	}

	fclose(fp);

	devid_fp = fopen("/usr/local/sinopec_cfg/cfg_devid","r");
	if(devid_fp==NULL)
	{
		perror("fopen devid_fp error\n");
		exit(-1);
	}
	if(fgets(deviceid,32,devid_fp) == NULL)
	{
		fclose(devid_fp);
		perror("get deviceid error");
		exit(-1);
	}

	p = strchr(deviceid,'\n');
	if(p != NULL)
	{
		*p = '\0';
	}
	fclose(devid_fp);
}

void GetIpAndMac(char* pIpArray,char *pMacArray)
{

#ifndef MAX_INTERFACE
# define MAX_INTERFACE    16
#endif

	struct ifreq buf[MAX_INTERFACE];
	struct ifconf ifc;
	int ret = 0;
	int if_num = 0;
	int fd;
	int i = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		printf("Create socket failed");
		return;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_req = buf;
	ret = ioctl(fd, SIOCGIFCONF, (char*)&ifc);
	if(ret<0)
	{
		printf("Get a list of interface addresses failed");
		return;
	}

	if_num = ifc.ifc_len/sizeof(struct ifreq);
	printf("interface num is interface = %d\n", if_num);
	while(if_num--)
	{
		char* pIp;
		char mac[32] = { 0 };
		printf("net device: %s\n", buf[if_num].ifr_name);
		ret = ioctl(fd, SIOCGIFFLAGS, (char*)&buf[if_num]);
		if(ret<0)
		{
			printf("Get the active flag word of the device");
			continue;
		}

		if(buf[if_num].ifr_flags & IFF_PROMISC)
			printf("Interface is in promiscuous mode\n");
		else if(buf[if_num].ifr_flags & IFF_LOOPBACK)
		{
			printf("Interface is a loopback net\n");
			continue;
		}

		if(buf[if_num].ifr_flags & IFF_UP)
			printf("Interface is running\n");
		else
			printf("Interface is not running\n");

		 if(ioctl(fd, SIOCGIFADDR, (char *)&buf[if_num]) < 0)
		 {
		    printf("Get interface address failed");
		    continue;
		 }
		 pIp = inet_ntoa(((struct sockaddr_in*)(&buf[if_num].ifr_addr))->sin_addr);
		 printf("IP address is %s\n", pIp);

		ret = ioctl(fd, SIOCGIFHWADDR, (char*)&buf[if_num]);
		if(ret<0)
		{
			printf("Get the hardware address of a device failed");
			continue;
		}

		sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[0],
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[1],
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[2],
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[3],
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[4],
				(unsigned char)buf[if_num].ifr_hwaddr.sa_data[5]);

		printf("%s\n",mac);

		if(i>0)
		{
			strcat(pIpArray,";");
			strcat(pMacArray,";");
		}
		i++;
		strcat(pIpArray,pIp);
		strcat(pMacArray,mac);
	}

	if(fd > 0)
		close(fd);
}

void get_mem_sta(struct mem_stat_t *pmem_stat)
{
	int fd;
	char *b;
	char *pbuf;
	int ret;


	pbuf = malloc(BUFFSIZE);
	if (pbuf == NULL)
	{
		printf("malloc error\n");
	}
	*(pbuf+BUFFSIZE-1) = 0;

	fd = open("/proc/meminfo", O_RDONLY, 0);
	if(fd < 0)
	{
		printf("open error\n");
		free(pbuf);
		exit(-1);
	}
	ret = read(fd,pbuf,BUFFSIZE-1);
	if (ret < 0)
	{
		printf("read error\n");

		free(pbuf);
		close(fd);
		exit(-1);
	}

	b = strstr(pbuf, "MemTotal");
	if(b != NULL)
	{
		sscanf(b, "MemTotal: %u\n", &pmem_stat->tot);
	}

	free(pbuf);
	close(fd);
}

void get_disk_stat(struct disk_stat_t *pdisk_stat)
{
	struct statvfs buf;

	memset(&buf, 0, sizeof(struct statvfs));
	statvfs("/", &buf);
	pdisk_stat->tot = (jiff)buf.f_bsize * buf.f_blocks;
	pdisk_stat->free= (jiff)buf.f_bsize * buf.f_bfree;

}

void GetCurrentTime(char *timestr)
{
    char time[10];
    char tmp[128];
    struct timeval tv;
	struct tm tm_tmp;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;

	localtime_r(&curtime, &tm_tmp);
	sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d",
		tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
		tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec);

	printf("GetCurrentTime: timestr:%s\n", timestr);
}

static void native_cpuid(unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
            : "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

void ReadDeviceInfor(DEVICE_INFOR* pDeviceInfor )
{
	char *pBuffer = NULL;
	int file_fd;
	int ret;

	pBuffer = malloc(BUFFSIZE);
	if(pBuffer==NULL)
	{
		printf("ReadDeviceInfor: malloc error\n");
		exit(-1);
	}

	do
	{
		//
		memset(pBuffer,0,BUFFSIZE);
		file_fd = open("/proc/sys/kernel/ostype", O_RDONLY, 0);
		if(file_fd < 0)
		{
			printf("ReadDeviceInfor: open error\n");
			break;
		}

		ret = read(file_fd,pBuffer,BUFFSIZE-1);
		if (ret < 0)
		{
			printf("ReadDeviceInfor: read error\n");
		    break;
		}
		close(file_fd);
		file_fd = -1;
		sscanf(pBuffer, "%s\n", pDeviceInfor->os_type);
		printf("ReadDeviceInfor:  os_type: %s\n", pDeviceInfor->os_type);

		//
		memset(pBuffer,0,BUFFSIZE);
		file_fd = open("/proc/sys/kernel/osrelease", O_RDONLY, 0);
		if(file_fd < 0)
		{
			printf("ReadDeviceInfor: open error\n");
			break;
		}

		ret = read(file_fd,pBuffer,BUFFSIZE-1);
		if (ret < 0)
		{
			printf("ReadDeviceInfor: read error\n");
		    break;
		}
		close(file_fd);
		file_fd = -1;
		sscanf(pBuffer, "%s\n", pDeviceInfor->os_rel);
		printf("ReadDeviceInfor:  os_rel: %s\n", pDeviceInfor->os_rel);

		//
		memset(pBuffer,0,BUFFSIZE);
		file_fd = open("/proc/cpuinfo", O_RDONLY, 0);
		if(file_fd < 0)
		{
			printf("ReadDeviceInfor: open error\n");
			break;
		}

		ret = read(file_fd,pBuffer,BUFFSIZE-1);
		if (ret < 0)
		{
			printf("ReadDeviceInfor: read error\n");
		    break;
		}
		close(file_fd);
		file_fd = -1;

		{
			char *p, *pp;
			p = strstr(pBuffer, "model name");
			p = strstr(p, ":");
			p += 1;
			pp = strstr(p, "\n");


			memset(pDeviceInfor->cpu_model, 0, 128);
			memcpy(pDeviceInfor->cpu_model, p, pp - p);
			printf("ReadDeviceInfor:  cpu_model: %s\n", pDeviceInfor->cpu_model);

			p = strstr(pBuffer, "cpu MHz");
			p = strstr(p, ":");
			p += 1;
			pp = strstr(p, "\n");
			memset(pDeviceInfor->cpu_hz, 0, 128);
			memcpy(pDeviceInfor->cpu_hz, p, pp - p);
			printf("ReadDeviceInfor:  cpu_hz: %s\n", pDeviceInfor->cpu_hz);
		}

	}while(0);

	if(pBuffer)
		free(pBuffer);

	if(file_fd >= 0)
		close(file_fd);
}

void mk_info_head(CommPkt *pkt,char* pDataBuffer,int datalen)
{
	memset((char *)pkt,0, sizeof(CommPkt));

	pkt->dwFlag      = PKT_FLAG;
	pkt->dwEquType   = 0;
	pkt->dwEquID     = 0;
	pkt->dwCorpID    = 0;
	pkt->dwSize      = HEAD_SIZE;
	pkt->dwType      = CMD_TYPE_COMMON_LINK;
	pkt->dwWhat      = CMD_WHAT_COMMON_SINGLE;
	pkt->dwOp        = REQ_PKT;
	pkt->dwPktCrc    = crc32(0,pDataBuffer,datalen);
	pkt->dwTransLen  = datalen;
	pkt->dwCellLen   = datalen;
	pkt->IsEncrypt   = false;
	pkt->dwTransID   = 100;
	pkt->IsRemoteRes = true;
	pkt->dwHeadCrc   = crc32(0, ((char *)pkt) + 12, HEAD_SIZE - 12);
}

void ReportAgentInfor(char* pInforData,int intDatalen)
{
	int sd, rc;
	CommPkt pkt;
	struct sockaddr_in serveraddr;

	mk_info_head(&pkt,pInforData,intDatalen);

	sd = socket(AF_INET,SOCK_STREAM,0);
	if(sd < 0)
	{
		perror("ReportAgentInfor: socket error\n");
		return;
	}

	memset(&serveraddr,0x00,sizeof(struct sockaddr_in));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(2289);//688
	serveraddr.sin_addr.s_addr=inet_addr(gConfigInfor.chServiceIpAddr);
	rc = connect(sd,(struct sockaddr *)&serveraddr,sizeof(serveraddr));
	if(rc < 0)
	{
		perror("ReportAgentInfor: connect error");
		return;
	}

	rc = write(sd,(char*)&pkt,sizeof(CommPkt));
	rc = write(sd,pInforData,intDatalen);
	memset(&pkt,0,sizeof(CommPkt));
	memset(pInforData,0,intDatalen);
	rc = read(sd,(char*)&pkt,sizeof(CommPkt));
	if(rc >0 &&
	   pkt.dwType != 2 &&
	   pkt.dwTransLen>0)
	{
		memset(pInforData,0,1024);
		if(pkt.dwTransLen<1024)
		{
			read(sd,pInforData,pkt.dwTransLen);
		}

		printf("ReportAgentInfor: ??????!!!ger respon error: %s!!pkt.dwType != 2\n",pInforData);
	}
	else
	{
		printf("?????!!!\n");
	}

	close(sd);
}

void BuildAgentInfor(char* pAgentInfor,int intlen)
{
	char disktol[128];
	struct disk_stat_t diskstat;
	char memtol[128];
	struct mem_stat_t memstat;
	char cpu_cores[16];
	char cpu_id[128];
	unsigned int eax, ebx, ecx, edx;
	char chCurrentTime[128];
	DEVICE_INFOR DeviceInfor;
	char pIpArray[128]={0};
	char pMacArray[128]={0};

	GetIpAndMac(pIpArray,pMacArray);
	if(pMacArray[0]==0 || pIpArray[0]==0)
	{
		printf("GetIpAndMac get ip and mac fail,please again!!\n");
		GetIpAndMac(pIpArray,pMacArray);
	}
	printf("Ip Address: %s\n",pIpArray);
	printf("mac Address: %s\n",pMacArray);

	memset(&DeviceInfor,0,sizeof(DEVICE_INFOR));
	ReadDeviceInfor(&DeviceInfor);

	memset(pAgentInfor, 0, intlen);

	strcat(pAgentInfor, "REQ=DM_LINUX_DEVICE_REG^\n");

	strcat(pAgentInfor, "CORPID=");
	strcat(pAgentInfor, "906241001");
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.DeviceIndex=");
	//char devIndex[16]={0};
	//sprintf(devIndex, "%u", crc32(0,pMacArray,strlen(pMacArray)));
	strcat(pAgentInfor, gConfigInfor.chDeviceId);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.OrganID=");   /* xxx */
	strcat(pAgentInfor, gConfigInfor.chOrganId);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.AgentVersion=12.04.07.1336^\n");   /* xxx */

	strcat(pAgentInfor, "Device.RegisterTime=");
	memset(chCurrentTime, 0, 128);
	GetCurrentTime(chCurrentTime);
	strcat(pAgentInfor, chCurrentTime);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.DeviceName="); /*  xxx */
	strcat(pAgentInfor, DeviceInfor.os_type);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.OSType="); /*  xxx */
	strcat(pAgentInfor, DeviceInfor.os_type);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.LanguageID=2052^\n"); /*  xxx */

	strcat(pAgentInfor, "Device.CpuType=");
	strcat(pAgentInfor,  DeviceInfor.cpu_model);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.CpuSerial=");
	native_cpuid(&eax,&ebx,&ecx,&edx);
	sprintf(cpu_id, "%x", edx);
	strcat(pAgentInfor, cpu_id); /*  xxx */
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.CoreCount=");
	sprintf(cpu_cores, "%d", sysconf(_SC_NPROCESSORS_ONLN));
	strcat(pAgentInfor,  cpu_cores);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.RealCpuSize=");
	strcat(pAgentInfor, DeviceInfor.cpu_hz);
	strcat(pAgentInfor, "^\n");

	get_mem_sta(&memstat);
	strcat(pAgentInfor, "Device.RealMemorySize=");
	sprintf(memtol, "%u", memstat.tot);
	strcat(pAgentInfor,  memtol);
	strcat(pAgentInfor, "^\n");

	get_disk_stat(&diskstat);
	strcat(pAgentInfor, "Device.RealDiskSize=");
	sprintf(disktol, "%llu", diskstat.tot);
	strcat(pAgentInfor, disktol);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.DiskSerial=");
	strcat(pAgentInfor, "0000");
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.IPAddress=");
	strcat(pAgentInfor, pIpArray);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.MacAddress=");
	strcat(pAgentInfor, pMacArray);
	strcat(pAgentInfor, "^\n");


	{
		int Index = 0;

		while(true)
		{
			if(gItemArray[Index].chName[0]==0)
				break;

			if(strcmp(gItemArray[Index].chFild,"OrganID")==0)
			{
				Index++;
				continue;
			}

			strcat(pAgentInfor,gItemArray[Index].chTable);
			strcat(pAgentInfor,".");
			strcat(pAgentInfor,gItemArray[Index].chFild);
			strcat(pAgentInfor,"=");
			if(strcmp(gItemArray[Index].chType,"List")==0)
				strcat(pAgentInfor,gItemArray[Index].chIndex);
			else
				strcat(pAgentInfor,gItemArray[Index].chValue);
			strcat(pAgentInfor, "^\n");
			Index++;
		}
	}

	/*
	strcat(pAgentInfor, "Device.UserName=");
	strcat(pAgentInfor, DeviceInfor.os_type);
	strcat(pAgentInfor, pMacArray);
	strcat(pAgentInfor, "^\n");

	strcat(pAgentInfor, "Device.DeviceType=3^\n");

	strcat(pAgentInfor, "DeviceExpand.Expand0=");
	strcat(pAgentInfor, gConfigInfor.chUserName);
	strcat(pAgentInfor, "^\n");


	strcat(pAgentInfor, "DeviceExpand.Expand1=");
	strcat(pAgentInfor, gConfigInfor.chDeviceNum);
	strcat(pAgentInfor, "^\n");


	strcat(pAgentInfor, "DeviceExpand.Expand2=");
	strcat(pAgentInfor, gConfigInfor.chDeviceType);
	strcat(pAgentInfor, "^\n");


	*/
	printf("BuildAgentInfor: \n%s\n", pAgentInfor);

}

int ParseConfigXml()
{
	xmlDocPtr doc;
	xmlNodePtr RootNode;
	xmlNodePtr ItemNode;
	int Index = 0;

	xmlKeepBlanksDefault(0);
	doc = xmlParseFile("Register.xml");
	RootNode = xmlDocGetRootElement(doc);
	if(RootNode == NULL)
	{
		fprintf(stderr,"Register.xml is empty document\n");
		xmlFreeDoc(doc);
		return 0;
	}

	ItemNode = RootNode->children;
	while(ItemNode)
	{
		strcpy(gItemArray[Index].chName,xmlGetProp(ItemNode,BAD_CAST "NAME"));
		strcpy(gItemArray[Index].chFild, xmlGetProp(ItemNode,BAD_CAST "FIELD"));
		strcpy(gItemArray[Index].chType,xmlGetProp(ItemNode,BAD_CAST "TYPE"));
		strcpy(gItemArray[Index].chMust,xmlGetProp(ItemNode,BAD_CAST "MUST"));
		strcpy(gItemArray[Index].chTable,xmlGetProp(ItemNode,BAD_CAST "TABLE"));
		strcpy(gItemArray[Index].chDesc ,xmlGetProp(ItemNode,BAD_CAST "DESC"));

		ItemNode = ItemNode->next;
		Index++;
	}

	return Index;
}

void GetGroupValue(int iGroupId,int* iarray)
{
	int index = 0;
	char organstr[64]={0};
	char cmd[128]={0};
	char ipaddr[64]={0};
	xmlDocPtr doc;
	xmlNodePtr RootNode;
	xmlNodePtr ItemNode;

	xmlKeepBlanksDefault(0);
	doc = xmlParseFile("Register.xml");
	RootNode = xmlDocGetRootElement(doc);
	if(RootNode == NULL)
	{
		fprintf(stderr,"Register.xml is empty document\n");
		xmlFreeDoc(doc);
		return;
	}

	ItemNode = RootNode->children;
	while(ItemNode)
	{
		xmlChar *ValueContent;
		xmlChar *ValueIndex;
		xmlNodePtr ValueNode;

		xmlChar *GroupIndex;
		xmlNodePtr GroupNode=ItemNode->children;

		while(GroupNode)
		{
			GroupIndex = xmlGetProp(GroupNode,BAD_CAST "INDEX");

			if(iGroupId != atoi(GroupIndex))
			{
				GroupNode= GroupNode->next;
				continue;
			}
			else
			{
				break;
			}
		}

		if(GroupNode == NULL)
		{
			ItemNode = ItemNode->next;
			continue;
		}



		ValueNode = GroupNode->children;
		while(ValueNode)
		{
			ValueContent = xmlNodeGetContent(ValueNode);
			ValueIndex = xmlGetProp(ValueNode,BAD_CAST "INDEX");
			iarray[index] = atoi(ValueIndex);
			printf("%d:%s\n",index+1,ValueContent);
			index++;

			ValueNode = ValueNode->next;
		}

		break;
	}
}

void GetDeviceType()
{
	int index = 0;
	char organstr[64]={0};
	char cmd[128]={0};
	char ipaddr[64]={0};
	xmlDocPtr doc;
	xmlNodePtr RootNode;
	xmlNodePtr ItemNode;

	xmlKeepBlanksDefault(0);
	doc = xmlParseFile("Register.xml");
	RootNode = xmlDocGetRootElement(doc);
	if(RootNode == NULL)
	{
		fprintf(stderr,"Register.xml is empty document\n");
		xmlFreeDoc(doc);
		return;
	}

	ItemNode = RootNode->children;
	while(ItemNode)
	{
		xmlChar *ValueContent;
		xmlChar *ValueIndex;
		xmlNodePtr ValueNode;

		xmlChar *GroupIndex;
		xmlNodePtr GroupNode;

		xmlChar *ItemField;

		ItemField = xmlGetProp(ItemNode,BAD_CAST "FIELD");
		if(strcmp(ItemField, "DeviceType") != 0)
		{
			ItemNode = ItemNode->next;
			continue;
		}

		printf("??????豸???????￡?????????д??: \n");
		GroupNode = ItemNode->children;
		ValueNode = GroupNode->children;

		while(ValueNode)
		{
			ValueContent = xmlNodeGetContent(ValueNode);
			printf("%d:%s\n",index+1,ValueContent);
			index++;

			ValueNode = ValueNode->next;
		}

		break;
	}
}

void SelectOrganId(ITEM_NODE* ItemNode)
{
	int iGroupId = 0;
	int iOrganIdArray[100];
	int iOrganId = 0;
	int iArrayIndex=0;
	char chIndex[32]={0};
	char cmd[128]={0};

	iGroupId = 0;
	memset(iOrganIdArray,0,sizeof(iOrganIdArray));
	GetGroupValue(iGroupId,iOrganIdArray);
	printf("请选择一级部门 Id(选择所属部门): ");
	scanf("%s",chIndex);
	iArrayIndex = atoi(chIndex);
	iOrganId = iOrganIdArray[iArrayIndex-1];
	if(iArrayIndex<100&& iArrayIndex>0)
	{
		iGroupId = iOrganIdArray[iArrayIndex-1];
		memset(iOrganIdArray,0,sizeof(iOrganIdArray));
		GetGroupValue(iGroupId,iOrganIdArray);
		if(iOrganIdArray[0]!=0)
		{
			printf("请选择二级部门 Id(选择所属部门): ");
			scanf("%s",chIndex);
			iArrayIndex = atoi(chIndex);
			iOrganId = iOrganIdArray[iArrayIndex-1];
			if(iArrayIndex<100 && iArrayIndex>0)
			{
				iGroupId = iOrganIdArray[iArrayIndex-1];
				memset(iOrganIdArray,0,sizeof(iOrganIdArray));
				printf("选择二级部门id=%d\n ",iGroupId);
				GetGroupValue(iGroupId,iOrganIdArray);
				if(iOrganIdArray[0]!=0)
				{
					printf("请选择三级部门 Id(选择所属部门): ");
					scanf("%s",chIndex);
					iArrayIndex = atoi(chIndex);
					iOrganId = iOrganIdArray[iArrayIndex-1];
				}
			}
		}
	}

	sprintf(cmd, "echo %d >> /usr/local/sinopec/cfg", iOrganId);
	system(cmd);
}

void InputTextTypeInfor(ITEM_NODE* ItemNode)
{
	printf("%s(%s): ",ItemNode->chName,ItemNode->chDesc);
	scanf("%15s",ItemNode->chValue);
}
int GetListTypeValue(unsigned char* chField,LIST_VALUE* pList)
{
	int index = 0;
	char organstr[64]={0};
	char cmd[128]={0};
	char ipaddr[64]={0};
	xmlDocPtr doc;
	xmlNodePtr RootNode;
	xmlNodePtr ItemNode;

	xmlKeepBlanksDefault(0);
	doc = xmlParseFile("Register.xml");
	RootNode = xmlDocGetRootElement(doc);
	if(RootNode == NULL)
	{
		fprintf(stderr,"Register.xml is empty document\n");
		xmlFreeDoc(doc);
		return index;
	}

	ItemNode = RootNode->children;
	while(ItemNode)
	{
		xmlChar *ValueContent;
		xmlChar *ValueIndex;
		xmlNodePtr ValueNode;

		xmlChar *GroupIndex;
		xmlNodePtr GroupNode;

		xmlChar *ItemField;

		ItemField = xmlGetProp(ItemNode,BAD_CAST "FIELD");
		if(strcmp(ItemField, chField) != 0)
		{
			ItemNode = ItemNode->next;
			continue;
		}

		//printf("??????豸???????￡?????????д??: \n");
		GroupNode = ItemNode->children;
		ValueNode = GroupNode->children;

		while(ValueNode)
		{
			ValueContent = xmlNodeGetContent(ValueNode);
			ValueIndex = xmlGetProp(ValueNode,BAD_CAST "INDEX");
			strcpy(pList[index].chValue,ValueContent);
			strcpy(pList[index].chIndex,ValueIndex);

			index++;

			ValueNode = ValueNode->next;
		}

		break;
	}

	return index;
}
void InputListTypeInfor(ITEM_NODE* ItemNode)
{
	char chId[8];
	int Id = 0;
	int i;
	LIST_VALUE ValueArray[50]={0};
	int index = GetListTypeValue(ItemNode->chFild,ValueArray);
	if(index==0)
	{
		printf("InputListTypeInfor Error!!(%s)\n",ItemNode->chFild);
		return;
	}

	for( i=0; i<index; i++)
	{
		printf("%d: %s\n",i+1,ValueArray[i].chValue);
	}

	printf("请选择%s Id(%s): ",ItemNode->chName,ItemNode->chDesc);
	scanf("%15s",chId);
	Id = atoi(chId);
	if(Id>0 && Id<index)
	{
		strcpy(ItemNode->chValue,ValueArray[Id-1].chValue);
		strcpy(ItemNode->chIndex,ValueArray[Id-1].chIndex);
	}
	else
	{
		printf("Id Error!!!\n");
	}
}

void GetUserRegistInfor()
{
	int Index = 0;
	int bSelect=1;
	int Count = ParseConfigXml();
	while(true)
	{
		if(gItemArray[Index].chName[0]==0)
			break;

		if(strcmp(gItemArray[Index].chFild,"OrganID")==0)
		{
			if(bSelect)
			{
				SelectOrganId(&gItemArray[Index]);
				bSelect = 0;
			}
		}
		else if(strcmp(gItemArray[Index].chType,"Text")==0)
		{
			InputTextTypeInfor(&gItemArray[Index]);
		}
		else if(strcmp(gItemArray[Index].chType,"List")==0)
		{
			InputListTypeInfor(&gItemArray[Index]);
		}

		Index++;
	}
}

void Regist()
{

	char cmd[128]={0};
	char ipaddr[64]={0};
	FILE *file_fp;
	char* AgentInfor = malloc(1024 * 4);
	FILE *fp = fopen("/usr/local/sinopec/cfg", "w+");

	if (fp == NULL)
	{
		perror("fopen error\n");
		exit(-1);
	}
	close(fp);

	printf("请输入DeskMaster服务器IP(例如 10.178.1.147):");
	scanf("%15s", ipaddr);
	sprintf(cmd, "echo %s >> /usr/local/sinopec/cfg", ipaddr);
	system(cmd);

	file_fp = fopen("/usr/local/sinopec_cfg/cfg_devid", "r");
	if (file_fp == NULL)
	{
		struct timeval tv;
		char DeviceId[4] = { 0 };
		FILE *fp = fopen("/usr/local/sinopec_cfg/cfg_devid", "w+");
		if (fp == NULL)
		{
			perror("fopen error\n");
			exit(-1);
		}
		close(fp);

		gettimeofday(&tv, NULL);
		sprintf(DeviceId, "%u", tv.tv_sec);
		sprintf(cmd, "echo %s >> /usr/local/sinopec_cfg/cfg_devid", DeviceId);
		system(cmd);
	}
	close(file_fp);

	memset(&gConfigInfor, 0, sizeof(CONFIG_INFOR));
	{
		GetUserRegistInfor();
	}

	ReadConfig(gConfigInfor.chServiceIpAddr, gConfigInfor.chOrganId, gConfigInfor.chDeviceId);
	if (AgentInfor)
	{
		memset(AgentInfor, 0, 1024 * 4);
		BuildAgentInfor(AgentInfor, 1024 * 4);
		ReportAgentInfor(AgentInfor, strlen(AgentInfor));
		free(AgentInfor);
	}
}

int main(int argc, char **argv)
{

	gItemArray = malloc(1024 * 4);
	if(gItemArray)
	{
		memset(gItemArray,0,1024*4);
	}
	else
	{
		printf("gItemArray memory malloc faild,Regist unsucess!!!!\n");
		return 0;
	}

	gReportItemArray = malloc(1024 * 4);
	if(gReportItemArray)
	{
		memset(gReportItemArray,0,1024*4);
	}
	else
	{
		printf("gReportItemArray memory malloc faild,Regist unsucess!!!!\n");
		return 0;
	}

	Regist();

	if(gReportItemArray)
		free(gReportItemArray);

	if(gItemArray)
		free(gItemArray);

    return 0;
  }
