#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "HMAc_md5.h"



//outΪ����֮��Ĵ���dataΪ��Ҫ���ܵ����ݣ�dlen�������ݵĳ��ȣ�key(in)Ϊ��Կ��klenΪ��Կ����
void hmac_md5(unsigned char* out, unsigned char* data, int dlen, unsigned char* key, int klen){
	int i;
	//���δ��ÿ�������Ľ��
	unsigned char tempString16[LENGTH_MD5_RESULT];
	unsigned char OneEnding[LENGTH_BLOCK];
	unsigned char TwoEnding[LENGTH_BLOCK];
	unsigned char* ThreeEnding = (unsigned char*)malloc(sizeof(unsigned char) * (LENGTH_BLOCK + dlen));
	//unsigned char ThreeEnding[LENGTH_BLOCK + LENGTH_DATA_BUFFER_SIZE];
	unsigned char FourEnding[LENGTH_MD5_RESULT];
	unsigned char FiveEnding[LENGTH_BLOCK];    
	unsigned char SixEnding[LENGTH_BLOCK + LENGTH_MD5_RESULT];

	char ipad;
	char opad;
	MD5_CTX md5;

	ipad = 0x36;
	opad = 0x5c;


	//(1) ����Կkey�������0������һ����ΪB(64�ֽ�)���ַ���(OneEnding)�����key�ĳ���klen����64�ֽڣ����Ƚ���md5���㣬ʹ�䳤��klen=16�ֽڡ�

	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		OneEnding[i] = 0;
	}

	if (klen > LENGTH_BLOCK)
	{
		MD5Init(&md5);
		MD5Update(&md5, key, klen);
		MD5Final(&md5, tempString16);
		for (i = 0; i < LENGTH_MD5_RESULT; i++)
			OneEnding[i] = tempString16[i];
	}
	else
	{
		for (i = 0; i < klen; i++)
			OneEnding[i] = key[i];
	}


	//(2) ����һ�����ɵ��ַ���(OneEnding)��ipad(0x36)��������㣬�γɽ���ַ���(TwoEnding)��
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		TwoEnding[i] = OneEnding[i] ^ ipad;
	}
	//(3) ��������data���ӵ��ڶ����Ľ���ַ���(TwoEnding)��ĩβ��
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		ThreeEnding[i] = TwoEnding[i];
	}
	for (; i < dlen + LENGTH_BLOCK; i++)
	{
		ThreeEnding[i] = data[i - LENGTH_BLOCK];
	}
	//(4) ��md5�����ڵ��������ɵ�������(ThreeEnding)��
	MD5Init(&md5);
	MD5Update(&md5, ThreeEnding, LENGTH_BLOCK + dlen);
	MD5Final(&md5, FourEnding);

	//(5) ����һ�����ɵ��ַ���(OneEnding)��opad(0x5c)��������㣬�γɽ���ַ���(FiveEnding)��
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		FiveEnding[i] = OneEnding[i] ^ opad;
	}
	//(6) �ٽ����Ĳ��Ľ��(FourEnding)���ӵ����岽�Ľ���ַ���(FiveEnding)��ĩβ��
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		SixEnding[i] = FiveEnding[i];
	}
	for (; i < (LENGTH_BLOCK + LENGTH_MD5_RESULT); i++)
	{
		SixEnding[i] = FourEnding[i - LENGTH_BLOCK];
	}
	//(7) ��md5�����ڵ��������ɵ�������(SixEnding)��������ս��(out)��
	MD5Init(&md5);
	MD5Update(&md5, SixEnding, LENGTH_BLOCK + LENGTH_MD5_RESULT);
	MD5Final(&md5, out);
}

//��filename����HMAC_md5���ܲ�����keyΪ��Կ��kelnΪ��Կ����
void hmac_md5_file(char* filename, unsigned char* out, unsigned char* key, int klen) {
	size_t len;
	FILE* fp = fopen(filename, "rb");
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	rewind(fp);
	unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char) * len + 1);
	memset(data, 0, len + 1);
	fread(data, 1, len, fp);
	hmac_md5(out, (unsigned char*)data, len, key, klen);
	fclose(fp);
	return;
}
