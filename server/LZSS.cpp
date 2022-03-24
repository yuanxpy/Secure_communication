#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>   
#include <stdlib.h>   
#include <string.h>   
#include <ctype.h>   

#define N        4096      
#define F          18      
#define THRESHOLD   2      
#define NIL         N      

unsigned long int textsize = 0, codesize = 0, printcount = 0;
unsigned char text_buf[N + F - 1];
int     match_position, match_length, lson[N + 1], rson[N + 257], dad[N + 1];


void InitTree(void)
{
    int  i;
    for (i = N + 1; i <= N + 256; i++) rson[i] = NIL;
    for (i = 0; i < N; i++) dad[i] = NIL;
}

void InsertNode(int r)
{
    int  i, p, cmp;
    unsigned char* key;

    cmp = 1;  key = &text_buf[r];  p = N + 1 + key[0];
    rson[r] = lson[r] = NIL;  match_length = 0;
    for (; ; ) {
        if (cmp >= 0) {
            if (rson[p] != NIL) p = rson[p];
            else { rson[p] = r;  dad[r] = p;  return; }
        }
        else {
            if (lson[p] != NIL) p = lson[p];
            else { lson[p] = r;  dad[r] = p;  return; }
        }
        for (i = 1; i < F; i++)
            if ((cmp = key[i] - text_buf[p + i]) != 0)  break;
        if (i > match_length) {
            match_position = p;
            if ((match_length = i) >= F)  break;
        }
    }
    dad[r] = dad[p];  lson[r] = lson[p];  rson[r] = rson[p];
    dad[lson[p]] = r;  dad[rson[p]] = r;
    if (rson[dad[p]] == p) rson[dad[p]] = r;
    else                   lson[dad[p]] = r;
    dad[p] = NIL;
}

void DeleteNode(int p)
{
    int  q;

    if (dad[p] == NIL) return;
    if (rson[p] == NIL) q = lson[p];
    else if (lson[p] == NIL) q = rson[p];
    else {
        q = lson[p];
        if (rson[q] != NIL) {
            do { q = rson[q]; } while (rson[q] != NIL);
            rson[dad[q]] = lson[q];  dad[lson[q]] = dad[q];
            lson[q] = lson[p];  dad[lson[p]] = q;
        }
        rson[q] = rson[p];  dad[rson[p]] = q;
    }
    dad[q] = dad[p];
    if (rson[dad[p]] == p) rson[dad[p]] = q;  else lson[dad[p]] = q;
    dad[p] = NIL;
}

//LZSS算法，读入filename文件，压缩后写入newfilename
void LZSS_compress(char* filename, char* newfilename)
{
    FILE* infile = fopen(filename, "rb");;
    FILE* outfile = fopen(newfilename, "wb");
    int  i, c, len, r, s, last_match_length, code_buf_ptr;
    unsigned char  code_buf[17], mask;

    InitTree();
    code_buf[0] = 0;
    code_buf_ptr = mask = 1;
    s = 0;  r = N - F;
    for (i = s; i < r; i++) text_buf[i] = ' ';
    for (len = 0; len < F && (c = getc(infile)) != EOF; len++)
        text_buf[r + len] = c;
    if ((textsize = len) == 0) return;
    for (i = 1; i <= F; i++) InsertNode(r - i);
    InsertNode(r);
    do {
        if (match_length > len) match_length = len;
        if (match_length <= THRESHOLD) {
            match_length = 1;
            code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = text_buf[r];
        }
        else {
            code_buf[code_buf_ptr++] = (unsigned char)match_position;
            code_buf[code_buf_ptr++] = (unsigned char)
                (((match_position >> 4) & 0xf0)
                    | (match_length - (THRESHOLD + 1)));
        }
        if ((mask <<= 1) == 0) {
            for (i = 0; i < code_buf_ptr; i++)
                putc(code_buf[i], outfile);
            codesize += code_buf_ptr;
            code_buf[0] = 0;  code_buf_ptr = mask = 1;
        }
        last_match_length = match_length;
        for (i = 0; i < last_match_length &&
            (c = getc(infile)) != EOF; i++) {
            DeleteNode(s);
            text_buf[s] = c;
            if (s < F - 1) text_buf[s + N] = c;
            s = (s + 1) & (N - 1);  r = (r + 1) & (N - 1);
            InsertNode(r);
        }
        if ((textsize += i) > printcount) {
            printf("压缩中--%12ld\r", textsize);  printcount += 1024;
        }
        while (i++ < last_match_length) {
            DeleteNode(s);
            s = (s + 1) & (N - 1);  r = (r + 1) & (N - 1);
            if (--len) InsertNode(r);
        }
    } while (len > 0);
    if (code_buf_ptr > 1) {
        for (i = 0; i < code_buf_ptr; i++) putc(code_buf[i], outfile);
        codesize += code_buf_ptr;
    }
    printf("In : %ld bytes\n", textsize);
    printf("Out: %ld bytes\n", codesize);
    printf("Out/In: %.3f\n", (double)codesize / textsize);


    fclose(outfile);
    fclose(infile);
}
//LZSS算法，读入filename文件，解压后写入newfilename
void LZSS_uncompress(char* filename, char* newfilename)
{
    FILE* infile = fopen(filename, "rb");
    FILE* outfile = fopen(newfilename, "wb");
    int  i, j, k, r, c;
    unsigned int  flags;
    for (i = 0; i < N - F; i++)
    {
        text_buf[i] = ' ';
    }
    r = N - F;
    flags = 0;
    for (; ; ) {
        flags >>= 1;
        if ((flags & 256) == 0) {
            if ((c = getc(infile)) == EOF)
            {
                break;
            }
            flags = c | 0xff00;
        }
        if ((flags & 1) != 0) {
            if ((c = getc(infile)) == EOF)
            {
                break;
            }
            putc(c, outfile);
            text_buf[r++] = c;
            r = (r & (N - 1));
        }
        else {
            if ((i = getc(infile)) == EOF) {
                break;
            }
            if ((j = getc(infile)) == EOF)
            {
                break;
            }
            i |= ((j & 0xf0) << 4);
            j = (j & 0x0f) + THRESHOLD;
            for (k = 0; k <= j; k++) {
                c = text_buf[(i + k) & (N - 1)];
                putc(c, outfile);
                text_buf[r++] = c;
                r &= (N - 1);
            }
        }
    }
    fclose(outfile);
    fclose(infile);
}


