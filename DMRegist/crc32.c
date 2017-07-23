
#include <stdio.h>
#include <string.h>
#include "crc32.h"

uint32_t POLYNOMIAL = 0xEDB88320 ;
int have_table = 0 ;
uint32_t table[256] ;

#if 0
void make_table()
{
    int i, j, crc ;
	
    have_table = 1 ;
    for (i = 0 ; i < 256 ; i++)
        for (j = 0, table[i] = i ; j < 8 ; j++)
            table[i] = (table[i]>>1)^((table[i]&1)?POLYNOMIAL:0) ;
}


uint crc32(uint crc, char *buff, int len)
{
	int i;
	
    if (!have_table) make_table() ;
    crc = ~crc;
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ table[(crc ^ buff[i]) & 0xff];
    return ~crc;
}
#endif
void make_table()
{
    int i, j, crc ;
	
    have_table = 1 ;
    for (i = 0 ; i < 256 ; i++)
        for (j = 0, table[i] = i ; j < 8 ; j++)
            table[i] = (table[i]>>1)^((table[i]&1)?POLYNOMIAL:0) ;
}


uint32_t crc32(uint32_t crc, char *buff, int len)
{
	int i;
	
    if (!have_table) make_table() ;
    crc = ~crc;
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ table[(crc ^ buff[i]) & 0xff];
    return ~crc;
}

/* 
uint32_t crc32cal(uint32_t crc, char *buf,  int len)
{
	int i;
	
	for (i = 0; i < len; i++)
	{
		crc = ((crc) >> 8) ^ lppdwCrc32Table[(buf[i]) ^ ((crc) & 0x000000FF)];
	}
	
	return crc;
}



uint32_t lppdwCrc32Table[256];


void crc32init()
{
	//crc Ëã·¨
		uint32_t dwPolynomial = 0xEDB88320;
		uint32_t dwCrc;
		int   m;
		int   n;
		
		for (m = 0; m < 256; m++)
		{
			dwCrc = m;
			for (n = 8; n > 0; n--)
			{
				if (dwCrc & 1)
				{
					dwCrc = (dwCrc >> 1) ^ dwPolynomial;
				}
				else
				{
					dwCrc >>= 1;
				}
			}
			lppdwCrc32Table[m] = dwCrc;
		}
	return lppdwCrc32Table;
}
*/
