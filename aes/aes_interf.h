#ifndef __AES_INTERF_H
#define __AES_INTERF_H

//#include "debug.h"
//#include "config.h"

//#define AES_DEBUG

#ifdef AES_DEBUG
#define AES_DEBUG_PRINTF	DEBUG_PRINTF
#define aes_debug_printf 	debug_printf 
#else
#define AES_DEBUG_PRINTF	
#define aes_debug_printf 	
#endif



int AES_ECB_encrypt(unsigned char *insrc,unsigned short srcLen,unsigned char *outdest,unsigned short *outLen);
int AES_ECB_decrypt(unsigned char *insrc,unsigned short srcLen,unsigned char *outdest,unsigned short *outLen,uint8_t endFlag);
#endif

