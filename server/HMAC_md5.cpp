#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "HMAc_md5.h"



//out为加密之后的串，data为需要加密的数据，dlen加密数据的长度，key(in)为密钥，klen为密钥长度
void hmac_md5(unsigned char* out, unsigned char* data, int dlen, unsigned char* key, int klen){
	int i;
	//依次存放每个步骤后的结果
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


	//(1) 在密钥key后面添加0来创建一个长为B(64字节)的字符串(OneEnding)。如果key的长度klen大于64字节，则先进行md5运算，使其长度klen=16字节。

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


	//(2) 将上一步生成的字符串(OneEnding)与ipad(0x36)做异或运算，形成结果字符串(TwoEnding)。
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		TwoEnding[i] = OneEnding[i] ^ ipad;
	}
	//(3) 将数据流data附加到第二步的结果字符串(TwoEnding)的末尾。
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		ThreeEnding[i] = TwoEnding[i];
	}
	for (; i < dlen + LENGTH_BLOCK; i++)
	{
		ThreeEnding[i] = data[i - LENGTH_BLOCK];
	}
	//(4) 做md5运算于第三步生成的数据流(ThreeEnding)。
	MD5Init(&md5);
	MD5Update(&md5, ThreeEnding, LENGTH_BLOCK + dlen);
	MD5Final(&md5, FourEnding);

	//(5) 将第一步生成的字符串(OneEnding)与opad(0x5c)做异或运算，形成结果字符串(FiveEnding)。
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		FiveEnding[i] = OneEnding[i] ^ opad;
	}
	//(6) 再将第四步的结果(FourEnding)附加到第五步的结果字符串(FiveEnding)的末尾。
	for (i = 0; i < LENGTH_BLOCK; i++)
	{
		SixEnding[i] = FiveEnding[i];
	}
	for (; i < (LENGTH_BLOCK + LENGTH_MD5_RESULT); i++)
	{
		SixEnding[i] = FourEnding[i - LENGTH_BLOCK];
	}
	//(7) 做md5运算于第六步生成的数据流(SixEnding)，输出最终结果(out)。
	MD5Init(&md5);
	MD5Update(&md5, SixEnding, LENGTH_BLOCK + LENGTH_MD5_RESULT);
	MD5Final(&md5, out);
}

//对filename进行HMAC_md5加密操作，key为密钥，keln为密钥长度
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
