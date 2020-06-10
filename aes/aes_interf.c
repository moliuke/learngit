#include<stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include "mbedtls/aes.h"
#include "mbedtls/config.h"
//#include "debug.h"
//#include "config.h"
//#include "PTC_common.h"
#include "aes_interf.h"

#include "mbedtls/compat-1.3.h"
//#include "aes.c"
 
#define AES_ECB 0
#define AES_CBC 1
#define AES_CFB 2
#define AES_CTR 3
#define MODE AES_ECB

#define FLAG_RECV		0
#define FLAG_SEND		1
 
unsigned char key[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
unsigned char input[138] = {
	0x5b, 0x70, 0x6c, 0x61, 0x79, 0x6c, 0x69, 0x73, 0x74, 0x5d,
	0xd, 0xa, 0x69, 0x74, 0x65, 0x6d, 0x5f, 0x6e, 0x6f, 0x20,
	0x3d, 0x20, 0x33, 0xd, 0xa, 0x69, 0x74, 0x65, 0x6d, 0x30,
	0x20, 0x3d, 0x20, 0x31, 0x30, 0x30, 0x2c, 0x20, 0x31, 0x2c,
	0x20, 0x31, 0x30, 0x2c, 0x20, 0x5c, 0x43, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x5c, 0x42, 0x35, 0x35, 0x35, 0x62, 0x6d,
	0x70, 0xd, 0xa, 0x69, 0x74, 0x65, 0x6d, 0x31, 0x20, 0x3d,
	0x20, 0x31, 0x30, 0x30, 0x2c, 0x20, 0x31, 0x2c, 0x20, 0x31,
	0x30, 0x2c, 0x5c, 0x43, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x5c, 0x4a, 0x36, 0x36, 0x36, 0x6a, 0x70, 0x67, 0xd, 0xa,
	0x69, 0x74, 0x65, 0x6d, 0x32, 0x20, 0x3d, 0x20, 0x31, 0x30,
	0x30, 0x2c, 0x20, 0x31, 0x2c, 0x20, 0x31, 0x30, 0x2c, 0x20,
	0x5c, 0x43, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x50,
	0x37, 0x37, 0x37, 0x70, 0x6e, 0x67, 0xd, 0xa
	};
unsigned char plain_decrypt[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char IV[16];
unsigned char mid_input[16];
unsigned char mid_input2[16] = {0}; 
unsigned char inv_output[1024] = {0}; 
unsigned char inv_output2[1024] = {0}; 
unsigned char cypher[16];
unsigned char * phd_input=NULL;
int i = 0;
mbedtls_aes_context aes;
 
 
 
void SetIV()
{
	int i;
	for (i = 0; i < 16; i++)
	{ 
		IV[i] = 0x55;
	}
	
}



int AES_ECB_encrypt(unsigned char *insrc,unsigned short srcLen,unsigned char *outdest,unsigned short *outLen)
{
	int i = 0;
	int wgr;//�ܵļ��ܴ���
	unsigned char mid_input[16];
	unsigned char cypher[16];
	
	if(srcLen < 16)
		wgr=1;
	else
		wgr = srcLen/16+1;
	int j;
	
	for(i=0;i<wgr;i++)
	{
		mbedtls_aes_setkey_enc(&aes, key, 128);//  set encrypt key	
		int k = 0;
		for(j=0; j<16; ++j)
		{
			if((16*i+j)<srcLen)
			{
				mid_input[j] = insrc[16*i+j];
			}
			else
			{
				mid_input[j] = 16 - srcLen % 16;
			}
		}
		mbedtls_aes_crypt_ecb(&aes, 1, mid_input, cypher);
		for(j=0; j<16; ++j)
		outdest[16*i+j] = cypher[j];
	} 
	printf("wgr * 16 = %d\n",wgr * 16);
	*outLen = wgr * 16;
	return 0;
		
}



/**
������:AES_ECB_decrypt
����1--insrc:�����ܵ�����
����2--srcLen:���������ݳ���
����3--outdest:���ܺ������
����4--outLen:���ܺ����ݳ���
����5--endFlag:����Ƿ���ܵ����һ֡����,0��ʾ�����һ�ڣ�1��ʾ���һ��
*/
int AES_ECB_decrypt(unsigned char *insrc,unsigned short srcLen,unsigned char *outdest,unsigned short *outLen,uint8_t endFlag)
{
	int size = 0;
	int i = 0,j = 0;
	int wgr;//�ܵļ��ܴ���
	unsigned char mid_input[16];
	unsigned char mid_input2[16] = {0}; 
	unsigned char cypher[16];
	printf("srcLen = %d\n",srcLen);
	
	if(srcLen < 16)
		wgr=1;
	else
		wgr = srcLen/16;

	printf("wgr = %d\n",wgr);

	mbedtls_aes_setkey_dec(&aes, key, 128);//  set decrypt key
	for(i=0;i<wgr;i++)
	{
		for(j=0; j<16; ++j)
			mid_input[j] = insrc[16*i+j];
		//		   memcpy(mid_input,output+16*i,16);
	#if 0
		mbedtls_aes_crypt_ecb(&aes, 0, mid_input, mid_input2);
		for(j=0; j<16; ++j)
		{
			outdest[16*i+j] = mid_input2[j];
		}
	#else
		mbedtls_aes_crypt_ecb(&aes, 0, mid_input, (outdest + 16 * i));
	#endif

	} 
	

	size = (endFlag) ? (wgr*16-outdest[wgr*16-1]) : (wgr*16);
	printf("size = %d\n",size);
	*outLen = size;
	return 0;
}



static unsigned short XKCalculateCRC(uint8_t *TempString,uint32_t nDataLengh)
{
	uint8_t c,treat,bcrc;
	uint16_t warc =0;
	uint16_t ii,jj;
	uint32_t n = 0;
	for(ii=0; ii < nDataLengh; ii++)
	{
		c= TempString[ii];
		for(jj=0; jj<8; jj++)
		{
			treat = c & 0x80;
			c <<= 1;
			bcrc = (warc >>8) & 0x80;
			warc <<=1;
			if(treat != bcrc)
			{
				warc ^= 0x1021;
			}
		}
	}
	return warc;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

int check_0x02and0x03(uint8_t flag,uint8_t *input,uint32_t inputlen,uint8_t *output,uint32_t *outputlen)
{
	int i = 0,j;
	int m = 0;		
	int IsEscOK = 0;

	printf("######################################## inputlen = %d\n",inputlen);
	
	if(flag == FLAG_RECV)
	{
		for(i = 0 ; i < inputlen ; i ++ )
		{
			//��������Ƿ����0x02����0x03,��������֮һ�����ݴ��󣬷�������
			if(input[i] == 0x02 || input[i] == 0x03)
			{
				printf("the data recv contains 0x02 or 0x03\n");
				return -1;
			}
		
			//����Ƿ����0x1B
			if(input[i] == 0x1B)
			{
				IsEscOK = 1;
				continue;
			}
		
		
			if(!IsEscOK)
				output[m] = input[i];
			else
			{
				IsEscOK = 0;
				output[m] = input[i]+0x1B;
			}
			m++;
		}
		
		*outputlen = m;
		return m;
	}

	while(i < inputlen)
	{
		switch(input[i])
		{
			
			case 0x02:
				output[m]	= 0x1B;
				output[m+1] = 0xe7;
				m += 2;
				break;
			case 0x03:
				output[m]	= 0x1B;
				output[m+1] = 0xE8;
				m += 2;
				break;
			case 0x1B:
				output[m]	= 0x1B;
				output[m+1] = 0x00;
				m += 2;
				break;
			default:
				output[m]	= input[i];
				m += 1;
				break;
		}
		
		output[m]	= 0;
		i++;
	}
	*outputlen = m;
	return m;
}

int main(int argc, char *argv[])
{
	
	unsigned char *reslutData;
	unsigned char *output;
	int size = 0;
	int t = 0,j;
	int i,linp;
	int wgr;//�ܵļ��ܴ���
	linp=sizeof(input);//����������ʱ������ĳ���
	//   linp = 33;
	FILE *FP = NULL,*WP = NULL;


	//unsigned short cryptLen1 = 0;
	//unsigned short cryptLen2 = 0;
	unsigned short cryptLen = 0;
	unsigned char cryptcache[20480];
	unsigned short outLen = 0;
	unsigned char outPut[1024];
	unsigned char Input[20480];
	unsigned int Inputlen = 0;



/*�������tcp client����*/
    int sockfd;
	struct sockaddr_in serv_addr;
CONNECT:
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        error_handling("sockfd() error");
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("192.168.1.11");
    serv_addr.sin_port = htons(2929);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
	{
		perror("close error");
		//error_handling("connect() error!");		
	}
	//���Է���003.lst�ļ�
	FP = fopen("./001.png","r");
	if(FP == NULL)
	{
		perror("open 001.png");
		exit(1);
	}

	char filedata[20480];
	char tmp[20480];
	int Len = 0;
	memset(tmp, 0, sizeof(tmp));
	memset(filedata,0,sizeof(filedata));
	memset(cryptcache, 0, sizeof(cryptcache));
	memset(Input, 0, sizeof(Input));
	Len = fread(filedata,1,20480,FP);
	
	cryptcache[0] = 0x02;
	cryptcache[1] = 0x30;
	cryptcache[2] = 0x30;
	//֡����
	tmp[0] = 0x31;
	tmp[1] = 0x30;
	int filelen = strlen(argv[1]);
	printf("sizeof(argv[1]) is %d\n",filelen);
	memcpy(tmp+2, argv[1], filelen);
	printf("arg is %s\n",argv[1]);
	tmp[2+filelen] = 0x2B;
	//�ļ�ָ��ƫ�� �����ǲ�Ҫд��0x30��ʽ
	tmp[3+filelen] = 0x00;
	tmp[4+filelen] = 0x00;
	tmp[5+filelen] = 0x00;
	tmp[6+filelen] = 0x00;
	
	memcpy(tmp+filelen+7, filedata, Len);
	printf("tmpsize is %d\n",strlen(tmp));
	AES_ECB_encrypt(tmp, filelen+7+Len, cryptcache+3, &cryptLen);
	printf("cryptLen is %d\n", cryptLen);
	printf("strlen(cryptcache) is %d\n",strlen(cryptcache));
//У��λ
	unsigned short CRC16 = 0;
	CRC16 = XKCalculateCRC(cryptcache+1, cryptLen+2);
	printf("CRC16 = 0x%x\n",CRC16);
	cryptcache[cryptLen+3] = (unsigned char)(CRC16 >> 8);
	cryptcache[cryptLen+4] = (unsigned char)(CRC16);

//��һ��һ��Ҫ���ϣ���Ȼ����ʱ��������	
	//����ֽ������Ƿ����0x02��0x03��0x1B�����������Ӧ��ת�����˴�����취�ǽ�ͷβ�����ֽ��ߵ��ڴ���
	check_0x02and0x03(FLAG_SEND,cryptcache+1,2+cryptLen+2,Input+1,&Inputlen);
	
	//cryptcache[cryptLen+5] = 0x03;
	int output_total_len = Inputlen;
	//����ֽ����ټ���ͷβ�����ֽ�
	Input[0]						= 0x02;
	Input[output_total_len + 1] 	= 0x03;

	printf("sumlen is %d  input is %d\n",output_total_len + 2,strlen(Input));
	
	output_total_len += 2;
	Inputlen = output_total_len;
	
	for(i = 0 ; i < Inputlen ; i++)
		printf("0x%x ",Input[i]);
	printf("\n");
	int ret;
	//����һ��ҪдInputlen����Ϊstrlen(Input)
	while(1)
	{
		// MSG_EOR �����־�쳣�Ͽ��󣬳������ֹ��MSG_OOB ���־������޸ķ������� �쳣�Ͽ���ret = -1,fa
		ret = send(sockfd, Input, Inputlen, MSG_NOSIGNAL);
		printf("send return value is %d\n",ret);
		if(ret == -1)
			goto CONNECT;	
		sleep(300);
	}

	
	fflush(WP);
	fclose(FP);


#if 0
	unsigned short CRC16 = 0;
	int ii = 0;
	unsigned short enLen = 0; 
	char Send[36] = {0x02,0x30,0x30};
	char enc[16] = {0x02,0x30,0x30,0x31,0x30,0x30};
	AES_ECB_encrypt(enc + 3,3,Send + 3,&enLen);

	CRC16 = XKCalculateCRC(Send+1,2+enLen);
	printf("priorty = 0x%x\n",CRC16);

	for(ii = 0 ; ii < enLen + 3 ; ii++)
		printf("0x%x ",(uint8_t)Send[ii]);
	printf("----------\n\n");

	char DD[16];
	unsigned short LL = 0;
	AES_ECB_decrypt(Send + 3,16,DD,&LL,1);
	for(ii = 0 ; ii < LL ; ii++)
		printf("0x%x, ",DD[ii]);
	printf("\n\n");
	//exit(1);
#endif
	
#if 0	
	uint8_t input[] = {};
	AES_ECB_encrypt(input,sizeof(input),cryptcache,&cryptLen);
	t = cryptLen;
	for(j=0; j<t; ++j)
		printf("%02x ", cryptcache[j]);
	printf("\n");

	
	AES_ECB_decrypt(cryptcache,cryptLen,outPut,&outLen);
	
	for(j=0; j<outLen; j++)
		printf("%02x ", outPut[j]);
	printf("\n");
#endif

#if 0	
	linp=t;//����������ʱ������ĳ���

	if(linp < 16)
		wgr=1;
	else
		wgr = linp/16;

	mbedtls_aes_setkey_dec(&aes, key, 128);//  set decrypt key
	for(i=0;i<wgr;i++)
	{
		for(j=0; j<16; ++j)
			mid_input[j] = output[16*i+j];
		//		   memcpy(mid_input,output+16*i,16);
		mbedtls_aes_crypt_ecb(&aes, 0, mid_input, mid_input2);
		for(j=0; j<16; ++j)
			inv_output[16*i+j] = mid_input2[j];
	} 
	size = wgr*16-inv_output[wgr*16-1];
	reslutData = (unsigned char *)malloc(size);
	for(j=0; j<(size); ++j)
	{
		reslutData[j] = inv_output[j];
	}
	for(j=0; j<(size); j++)
		printf("%02x ", *reslutData++);
	printf("\n");
	i++;
#endif
	
}


