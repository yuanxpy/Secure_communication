#pragma once
union b4w
{
	unsigned char bytes[4];
	unsigned int word;
};

void AES_ECBEncrypt(b4w* Messenger, b4w* key, int len);  //ECBģʽ�¶�len����������ݽ���AES���ܺ���
void AES_ECBDecrypt(b4w* Messenger, b4w* key, int len); //ECBģʽ�¶�len����������ݽ���AES���ܺ���

void AES_ECBEncrypt_text(unsigned char* text, unsigned char* key, int size); //ECBģʽ�¶�text�ı����ݽ���AES���ܺ���--ʹ��PKCS7����ȱ
void AES_ECBDecrypt_text(unsigned char* text, unsigned char* key, int size);//ECBģʽ�¶�text�ı����ݽ���AES���ܺ���--ʹ��PKCS7����ȱ
void AES_ECBDecrypt_file(char* filename, char* filename2, unsigned char* key);//ECBģʽ�¶�filename�ļ�����AES���ܺ���--ʹ��PKCS7����ȱ
void AES_ECBEncrypt_file(char* filename, char* filename2, unsigned char* key);//ECBģʽ�¶�fileneme����AES���ܺ���--ʹ��PKCS7����ȱ
