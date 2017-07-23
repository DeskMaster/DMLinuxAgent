 /**********************************
 created: 2014/05/12
 filename: CreateXmlFile.c
 auther: wang kai
 depend: libxml2.lib
 purpose: 创建一个xml文件
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

typedef struct _CONFIG_INFOR{
	char chServiceIpAddr[32];
	char chOrganId[32];
	char chDeviceId[32];
}CONFIG_INFOR;

CONFIG_INFOR gConfigInfor={0};
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
		char mac[32] = { 0 };
		char* pIp;
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
	pkt->dwTransID   = 100;   /* ??????????????????   */
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

		printf("ReportAgentInfor: HeartBeat Error: %s!\n",pInforData);
	}

	close(sd);
}

void HeartBeat()
{
	char pIpArray[128] = { 0 };
	char pMacArray[128] = { 0 };
	char AgentInfor[1024] = { 0 };

	memset(&gConfigInfor,0,sizeof(CONFIG_INFOR));
	ReadConfig(gConfigInfor.chServiceIpAddr,gConfigInfor.chOrganId,gConfigInfor.chDeviceId);

	strcat(AgentInfor, "REQ=DM_LINUX_DEVICE_HEARTBEAT^\n");

	strcat(AgentInfor, "DeviceIndex=");
	strcat(AgentInfor, gConfigInfor.chDeviceId);
	strcat(AgentInfor, "^\n");

	GetIpAndMac(pIpArray,pMacArray);
	printf("Ip Address: %s\n",pIpArray);
	printf("mac Address: %s\n",pMacArray);

	strcat(AgentInfor, "IPAddress=");
	strcat(AgentInfor, pIpArray);
	strcat(AgentInfor, "^\n");

	strcat(AgentInfor, "MacAddress=");
	strcat(AgentInfor, pMacArray);
	strcat(AgentInfor, "^\n");

	ReportAgentInfor(AgentInfor,strlen(AgentInfor));
}
int main(int argc, char **argv)
{
	int i = 0;
	int pid;
	if ((pid = fork()) < 0)
	{
		perror("fork error");
		exit(-1);
	}

	else if (pid > 0)
	{ 	 /* parrent */

		//printf("###xxx pid :%d\n", pid);

		exit(0);

	}

	while(1)
	{
		printf("HeartBeat: %d ##################################\n",i++);
		HeartBeat();
		sleep(10);
	}

    return 0;
}
