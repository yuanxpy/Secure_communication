#pragma once
union b4w
{
	unsigned char bytes[4];
	unsigned int word;
};

void AES_ECBEncrypt(b4w* Messenger, b4w* key, int len);
void AES_ECBDecrypt(b4w* Messenger, b4w* key, int len);

void AES_ECBEncrypt_text(unsigned char* text, unsigned char* key, int size);
void AES_ECBDecrypt_text(unsigned char* text, unsigned char* key, int size);
void AES_ECBDecrypt_file(char* filename, char* filename2, unsigned char* key);
void AES_ECBEncrypt_file(char* filename, char* filename2, unsigned char* key);
