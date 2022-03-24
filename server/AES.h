#pragma once
union b4w
{
	unsigned char bytes[4];
	unsigned int word;
};

void AES_ECBEncrypt(b4w* Messenger, b4w* key, int len);  //ECB模式下对len个分组的数据进行AES加密函数
void AES_ECBDecrypt(b4w* Messenger, b4w* key, int len); //ECB模式下对len个分组的数据进行AES解密函数

void AES_ECBEncrypt_text(unsigned char* text, unsigned char* key, int size); //ECB模式下对text文本数据进行AES加密函数--使用PKCS7填充空缺
void AES_ECBDecrypt_text(unsigned char* text, unsigned char* key, int size);//ECB模式下对text文本数据进行AES解密函数--使用PKCS7填充空缺
void AES_ECBDecrypt_file(char* filename, char* filename2, unsigned char* key);//ECB模式下对filename文件进行AES加密函数--使用PKCS7填充空缺
void AES_ECBEncrypt_file(char* filename, char* filename2, unsigned char* key);//ECB模式下对fileneme进行AES加密函数--使用PKCS7填充空缺
