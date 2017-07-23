#ifndef _CRC32_H
#define _CRC32_H

/* typedef int size_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
*/
typedef unsigned int uint32_t;

uint32_t crc32(uint32_t crc, char *buff, int len);
void make_table();



#endif
