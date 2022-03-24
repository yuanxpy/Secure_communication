#pragma once

#define LENGTH_MD5_RESULT 16
#define LENGTH_BLOCK 64
#define LENGTH_DATA_BUFFER_SIZE 1024


void hmac_md5(unsigned char* out, unsigned char* data, int dlen, unsigned char* key, int klen);
void hmac_md5_file(char* filename, unsigned char* out, unsigned char* key, int klen);