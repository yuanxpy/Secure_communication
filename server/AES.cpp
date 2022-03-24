#pragma warning(disable:4996)
#include <stdio.h>
#include<stdlib.h>
#include<string.h>

union b4w
{
	unsigned char bytes[4];
	unsigned int word;
};


const int FILENAME_SIZE = 100;//文件名缓冲区大小

static const unsigned char Sbox[256] = {	//static:内部变量  const：只读，不可变常量
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
	0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
	0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
	0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
	0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
	0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
	0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
	0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
	0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
	0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
	0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
	0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
	0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
	0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
	0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
	0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
	0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
//逆向S 盒矩阵
static const unsigned char Reverse_Sbox[256] = {
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
	0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
	0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
	0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
	0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
	0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
	0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
	0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
	0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
	0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
	0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
	0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
	0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
	0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
	0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
	0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
	0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};


/*轮常量表 The key schedule rcon table*/
static const unsigned char Rcon[10] = {
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

//辅助函数
/*有限域*2乘法 The x2time() function */
static unsigned char x2time(unsigned char x)
{
	if (x & 0x80)
	{
		return (((x << 1) ^ 0x1B) & 0xFF);
	}
	return x << 1;
}
/*有限域*3乘法 The x2time() function */
static unsigned char x3time(unsigned char x)
{
	return (x2time(x) ^ x);
}
/*有限域*4乘法 The x4time() function */
static unsigned char x4time(unsigned char x)
{
	return (x2time(x2time(x)));
}
/*有限域*8乘法 The x8time() function */
static unsigned char x8time(unsigned char x)
{
	return (x2time(x2time(x2time(x))));
}
/*有限域9乘法 The x9time() function */
static unsigned char x9time(unsigned char x)	//9:1001
{
	return (x8time(x) ^ x);
}
/*有限域*B乘法 The xBtime() function */
static unsigned char xBtime(unsigned char x)	//B:1011
{
	return (x8time(x) ^ x2time(x) ^ x);
}
/*有限域*D乘法 The xDtime() function */
static unsigned char xDtime(unsigned char x)	//D:1101
{
	return (x8time(x) ^ x4time(x) ^ x);
}
/*有限域*E乘法 The xEtime() function */
static unsigned char xEtime(unsigned char x)	//E:1110
{
	return (x8time(x) ^ x4time(x) ^ x2time(x));
}

/****************************************************************************************************************/
/*s盒字节代换替换 SubBytes*/
static void SubBytes(b4w state[4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i].bytes[j] = Sbox[state[i].bytes[j]];
		}
	}
}
/*逆向s盒替换Reverse_SubBytes*/
static void Reverse_SubBytes(b4w state[4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i].bytes[j] = Reverse_Sbox[state[i].bytes[j]];
		}
	}
}


/*行移位操作 ShiftRows:*/
static void ShiftRows(b4w state[4]) {
	unsigned char temp;

	/*1nd row*///第二行左移1位
	temp = state[0].bytes[1]; state[0].bytes[1] = state[1].bytes[1]; state[1].bytes[1] = state[2].bytes[1]; state[2].bytes[1] = state[3].bytes[1]; state[3].bytes[1] = temp;
	/*2rd row*///第三行左移2位，交换2次数字来实现
	temp = state[0].bytes[2]; state[0].bytes[2] = state[2].bytes[2]; state[2].bytes[2] = temp;
	temp = state[1].bytes[2]; state[1].bytes[2] = state[3].bytes[2]; state[3].bytes[2] = temp;
	/*3th row*///第四行左移3位，相当于右移1次
	temp = state[3].bytes[3]; state[3].bytes[3] = state[2].bytes[3]; state[2].bytes[3] = state[1].bytes[3]; state[1].bytes[3] = state[0].bytes[3]; state[0].bytes[3] = temp;
}
/*行移位逆向操作 Reverse_ShiftRows:*/
static void Reverse_ShiftRows(b4w state[4]) {
	unsigned char temp;
	/*1nd row*///第二行右移1位
	temp = state[3].bytes[1]; state[3].bytes[1] = state[2].bytes[1]; state[2].bytes[1] = state[1].bytes[1]; state[1].bytes[1] = state[0].bytes[1]; state[0].bytes[1] = temp;
	/*2rd row*///第三行右移2位，交换2次数字来实现
	temp = state[0].bytes[2]; state[0].bytes[2] = state[2].bytes[2]; state[2].bytes[2] = temp;
	temp = state[1].bytes[2]; state[1].bytes[2] = state[3].bytes[2]; state[3].bytes[2] = temp;
	/*3th row*///第四行右移3位，相当于左移1次
	temp = state[0].bytes[3]; state[0].bytes[3] = state[1].bytes[3]; state[1].bytes[3] = state[2].bytes[3]; state[2].bytes[3] = state[3].bytes[3]; state[3].bytes[3] = temp;

}




/*列混合操作 MixColumns*/
static void MixColumns(b4w state[4])
{

	unsigned char temp1, temp2, temp3, temp4;
	for (int i = 0; i < 4; i++)
	{

		temp1 = x2time(state[i].bytes[0]) ^ x3time(state[i].bytes[1]) ^ state[i].bytes[2] ^ state[i].bytes[3];	//2 3 1 1
		temp2 = state[i].bytes[0] ^ x2time(state[i].bytes[1]) ^ x3time(state[i].bytes[2]) ^ state[i].bytes[3];	//1 2 3 1
		temp3 = state[i].bytes[0] ^ state[i].bytes[1] ^ x2time(state[i].bytes[2]) ^ x3time(state[i].bytes[3]);	//1 1 2 3
		temp4 = x3time(state[i].bytes[0]) ^ state[i].bytes[1] ^ state[i].bytes[2] ^ x2time(state[i].bytes[3]);	//3 1 1 2
		state[i].bytes[0] = temp1;
		state[i].bytes[1] = temp2;
		state[i].bytes[2] = temp3;
		state[i].bytes[3] = temp4;
	}



}


/*列混合逆向操作 Reverse_MixColumns*/
static void Reverse_MixColumns(b4w state[4])
{
	unsigned char temp1, temp2, temp3, temp4;
	for (int i = 0; i < 4; i++)
	{

		temp1 = xEtime(state[i].bytes[0]) ^ xBtime(state[i].bytes[1]) ^ xDtime(state[i].bytes[2]) ^ x9time(state[i].bytes[3]);
		temp2 = x9time(state[i].bytes[0]) ^ xEtime(state[i].bytes[1]) ^ xBtime(state[i].bytes[2]) ^ xDtime(state[i].bytes[3]);
		temp3 = xDtime(state[i].bytes[0]) ^ x9time(state[i].bytes[1]) ^ xEtime(state[i].bytes[2]) ^ xBtime(state[i].bytes[3]);
		temp4 = xBtime(state[i].bytes[0]) ^ xDtime(state[i].bytes[1]) ^ x9time(state[i].bytes[2]) ^ xEtime(state[i].bytes[3]);

		state[i].bytes[0] = temp1;
		state[i].bytes[1] = temp2;
		state[i].bytes[2] = temp3;
		state[i].bytes[3] = temp4;
	}
}

/*加轮密钥 AddRoundKey*/
static void AddRoundKey(b4w state[4], b4w* key, int Nr) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i].bytes[j] ^= key[(Nr * 4) + i].bytes[j];
		}
	}
}



void ScheduleKey(unsigned char* inkey, unsigned char* outkey, int Nk, int Nr)//安排一个保密密钥使用
{
	//inkey:初始16字节密钥key
	//outkey：11组*16字节扩展密钥expansionkey
	//Nk：4列
	//Nr：10轮round
	unsigned char temp[4], t;
	int x, i;
	/*copy the key*/
	//第0组：[0-3]直接拷贝
	for (i = 0; i < (4 * Nk); i++)
	{
		outkey[i] = inkey[i];
	}
	//第1-10组：[4-43]
	i = Nk;
	while (i < (4 * (Nr + 1))) //i=4~43 WORD 32bit的首字节地址，每一个4字节
	{//1次循环生成1个字节扩展密钥，4次循环生成一个WORD
		//temp：4字节数组：代表一个WORD密钥
		/*temp=w[i-1]*/
		//i不是4的倍数的时候
		//每个temp = 每个outkey32bit = 4字节
		for (x = 0; x < 4; x++)
			temp[x] = outkey[(4 * (i - 1)) + x];	//i：32bit的首字节地址
		//i是4的倍数的时候
		if (i % Nk == 0)
		{
			/*字循环：循环左移1字节 RotWord()*/
			t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
			/*字节代换：SubWord()*/
			for (x = 0; x < 4; x++)
			{
				temp[x] = Sbox[temp[x]];
			}
			/*轮常量异或：Rcon[j]*/
			temp[0] ^= Rcon[(i / Nk) - 1];
		}
		else if (Nk > 6 && (i % Nk) == 4)	//Nk>6的算法不同，暂时用不到
		{
			/*SubWord*/
			for (x = 0; x < 4; x++)
			{
				temp[x] = Sbox[temp[x]];
			}
		}

		/*w[i] = w[i-4]^w[i-1]*/
		for (x = 0; x < 4; x++)
		{
			outkey[(4 * i) + x] = outkey[(4 * (i - Nk)) + x] ^ temp[x];
		}
		++i;
	}
}

/*字内字节循环左移操作 Rotl:*/
static void Rotl(b4w* state, int n) {
	unsigned char temp;
	for (int i = 0; i < n; i++) {
		temp = state->bytes[0]; state->bytes[0] = state->bytes[1]; state->bytes[1] = state->bytes[2]; state->bytes[2] = state->bytes[3]; state->bytes[3] = temp;
	}
}

/*S盒置换--单位为字  SubByte*/
static void SubByte(b4w* key) {
	for (int i = 0; i < 4; i++) {
		key->bytes[i] = Sbox[key->bytes[i]];
	}
}
///*密钥扩展 KeyExpansion*/
//static void KeyExpansion(b4w* key, b4w* en_key, int Nk, int Nr) {
//	b4w* temp = (b4w*)malloc(sizeof(b4w));
//	if (strlen((const char*)key) == 16) {          //当密钥为128位时
//		Nk = 4;
//		for (int i = 0; i < Nk; i++) {
//			en_key[i].word = key[i].word;
//		}
//		for (int i = Nk; i < (4 * (Nr + 1)); i++) {
//			temp->word = en_key[i - 1].word;
//			if (i % Nk == 0) {
//				Rotl(temp, 1);
//				SubByte(temp);
//				temp->word ^= Rcon[(i / Nk) - 1];
//			}
//			en_key[i].word = en_key[i - Nk].word ^ temp->word;
//		}
//	}
//	else {
//		if (strlen((const char*)key) == 24) {     //当密钥为192位时
//			Nk = 6;
//		}
//		else {                                         //当密钥为256位时
//			Nk = 8;
//		}
//		for (int i = 0; i < Nk; i++) {
//			en_key[i].word = key[i].word;
//		}
//		for (int i = Nk; i < (4 * (Nr + 1)); i++) {
//			temp->word = en_key[i - 1].word;
//			if (i % Nk == 0) {
//				Rotl(temp, 1);
//				SubByte(temp);
//				temp->word ^= Rcon[(i / Nk) - 1];
//			}
//			else if (i % Nk == 4) {
//				SubByte(temp);
//			}
//			en_key[i].word = en_key[i - Nk].word ^ temp->word;
//		}
//	}
//}


/*密钥扩展 KeyExpansion*/
static void KeyExpansion(b4w* key, b4w* en_key, int Nk, int Nr) {
	b4w* temp = (b4w*)malloc(sizeof(b4w));
	if (Nk == 4) {
		for (int i = 0; i < Nk; i++) {
			en_key[i].word = key[i].word;
		}
		for (int i = Nk; i < (4 * (Nr + 1)); i++) {
			temp->word = en_key[i - 1].word;
			if (i % Nk == 0) {
				Rotl(temp, 1);
				SubByte(temp);
				temp->word ^= Rcon[(i / Nk) - 1];
			}
			en_key[i].word = en_key[i - Nk].word ^ temp->word;
		}
	}
	else {
		for (int i = 0; i < Nk; i++) {
			en_key[i].word = key[i].word;
		}
		for (int i = Nk; i < (4 * (Nr + 1)); i++) {
			temp->word = en_key[i - 1].word;
			if (i % Nk == 0) {
				Rotl(temp, 1);
				SubByte(temp);
				temp->word ^= Rcon[(i / Nk) - 1];
			}
			else if (i % Nk == 4) {
				SubByte(temp);
			}
			en_key[i].word = en_key[i - Nk].word ^ temp->word;
		}
	}
}


/*AES加密过程 AESEncrypt*/
void AesEncrypt(b4w de_text[4], b4w* key, int Nr) {
	AddRoundKey(de_text, key, 0);
	for (int i = 1; i < Nr; i++) {
		SubBytes(de_text);
		ShiftRows(de_text);
		MixColumns(de_text);
		AddRoundKey(de_text, key, i);
	}
	SubBytes(de_text);
	ShiftRows(de_text);
	AddRoundKey(de_text, key, Nr);
}



/*AES解密过程 AesDecrypt*/
void AesDecrypt(b4w de_text[4], b4w* key, int Nr) {
	AddRoundKey(de_text, key, Nr);
	Reverse_ShiftRows(de_text);
	Reverse_SubBytes(de_text);
	for (int i = Nr - 1; i > 0; i--) {
		AddRoundKey(de_text, key, i);
		Reverse_MixColumns(de_text);
		Reverse_ShiftRows(de_text);
		Reverse_SubBytes(de_text);
	}
	AddRoundKey(de_text, key, 0);
}


//以ECB模式进行AES加密
void AES_ECBEncrypt(b4w* Messenger, b4w* key, int len)  
{
	unsigned char expansionkey[15 * 16];
	KeyExpansion((b4w*)key, (b4w*)expansionkey, 4, 10);	//密钥扩展算法
	for (int i = 0; i < len; i = i + 4)//len为多少个字长，即以32位比特为单位缓冲区的长度
	{

		AesEncrypt((b4w*)Messenger + i, (b4w*)expansionkey, 10);		//AES 加密
	}
}

//以ECB模式进行AES解密
void AES_ECBDecrypt(b4w* Messenger, b4w* key, int len)
{
	unsigned char expansionkey[15 * 16];
	KeyExpansion((b4w*)key, (b4w*)expansionkey, 4, 10);	//密钥扩展算法
	for (int i = 0; i < len; i = i + 4)//len为多少个字长，即以32位比特为单位缓冲区的长度
	{
		AesDecrypt((b4w*)Messenger + i, (b4w*)expansionkey, 10);
	}
}


//以ECB模式进行文本AES加密，size为text的缓冲区大小
void AES_ECBEncrypt_text(unsigned char* text, unsigned char* key, int size)
{
	int len = strlen((char*)text);
	int ncycle = len / 16; //以16字节为单位的组数（长度不足的不计入）
	int last_num = len % 16; //以16字节为单位最后一组（不足16字节）的长度
	unsigned char* buf = (unsigned char*)malloc(sizeof(unsigned char) * size);

	memcpy(buf, text, size);
	memset(text, 0, size);

	if (last_num != 0) {
		for (int i = 16 * ncycle + last_num; i < 16 * (ncycle + 1); i++) {//使用PKCS7填充空缺
			buf[i] = 16 - last_num;
		}
		AES_ECBEncrypt((b4w*)buf, (b4w*)key, ncycle + 1);
	}
	else {
		AES_ECBEncrypt((b4w*)buf, (b4w*)key, ncycle);
	}

	memcpy(text, buf, size);
}

//以ECB模式进行文本AES解密，size为text的缓冲区大小
void AES_ECBDecrypt_text(unsigned char* text, unsigned char* key, int size)
{
	int len = strlen((char*)text);
	int ncycle = len / 16; //以16字节为单位的组数
	int nCount = 0;//最后一个16字节组中有效的位数
	unsigned char* buf = (unsigned char*)malloc(sizeof(unsigned char) * size);
	memcpy(buf, text, size);
	memset(text, 0, size);
	AES_ECBDecrypt((b4w*)buf, (b4w*)key, ncycle);

	int check_num = 0;
	for (int i = (16 * ncycle) - 1; i >= 16 * (ncycle - 1); i--) {
		if (buf[i] == buf[i - 1]) {
			check_num++;
		}
		else {
			break;
		}
	}

	if (check_num == buf[len - 1] - 1 && check_num != 0) { //如果发现填充数据就将其置为0
		nCount = 16 - buf[len - 1];   //最后一个16字节组中有效的位数
		for (int i = nCount; i < 16; i++) {
			buf[16 * (ncycle - 1) + i] = 0;
		}
	}

	memcpy(text, buf, size);
}




//以ECB模式进行AES加密文件名为filename的文件，并以file_name2保存,返回
void AES_ECBEncrypt_file(char* filename, char* filename2, unsigned char* key)
{
	int nCount;
	unsigned char buf[16] = { 0 };
	FILE* fp = fopen(filename, "rb");  //以二进制方式打开文件
	FILE* fp2 = fopen(filename2, "wb");  //以二进制方式打开（创建）文件
	while ((nCount = fread(buf, 1, 16, fp)) > 0) {
		if (nCount != 16) {
			for (int i = nCount; i < 16; i++) {
				buf[i] = 16 - nCount;
			}
		}
		AES_ECBEncrypt((b4w*)buf, (b4w*)key, 1);
		fwrite(buf, 16, 1, fp2);
		//memset(buf, 0, sizeof(buf));
	}
	fclose(fp);
	fclose(fp2);
}

//以ECB模式进行AES解密文件名为filename的文件，并以temp_file_name保存
void AES_ECBDecrypt_file(char* filename, char* filename2, unsigned char* key)
{
	int nCount;
	int check_num = 0;
	unsigned char buf[16] = { 0 };
	FILE* fp = fopen(filename, "rb");  //以二进制方式打开文件
	FILE* fp2 = fopen(filename2, "wb");  //以二进制方式打开（创建）文件
	while ((nCount = fread(buf, 1, 16, fp)) > 0) {
		AES_ECBDecrypt((b4w*)buf, (b4w*)key, 1);
		check_num = 0;
		for (int i = 15; i > 0; i--) {//检测文件块是否是使用PKCS7填充空缺，是则填充部分不写入文件
			if (buf[i] == buf[i - 1]) {
				check_num++;
			}
			else {
				break;
			}
		}
		if (check_num == buf[15] - 1 && check_num != 0) {
			nCount = 16 - buf[15];
		}

		fwrite(buf, nCount, 1, fp2);
	}

	fclose(fp);
	fclose(fp2);
}
