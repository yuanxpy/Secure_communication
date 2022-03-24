#include <Winsock2.h>  //windows socket编程头文件
#include <windows.h> 
#include <iostream>
#include <cstring>
#include "dhexchange.h"
#include "AES.h"
#include "HMAC_md5.h"
#include "LZSS.h"

#pragma comment (lib, "ws2_32.lib")  //加载 ws2_32.dll
using namespace std;

const int BUFFER_SIZE = 1024;//缓冲区大小
const int FILENAME_SIZE = 100;//文件名缓冲区大小
const int SELECT_SIZE = 20; //选择命令缓冲区大小
const int KEY_SIZE = 16;  //保存密钥长度
const int LENGTH_MD5 = 16; //md5结果报错的缓冲区大小

char save_place[FILENAME_SIZE] = { 0 }; //存储文件下载后的保存位置的缓冲区
char save_place_AES_temp[FILENAME_SIZE] = { 0 };
char save_place_compress_temp[FILENAME_SIZE] = { 0 };
unsigned char key[KEY_SIZE] = { 0 };//存放密钥的缓冲区




////服务器和客户端的socket套接字
//SOCKET sockSer, cliSock;
////记录服务器和客户端的网络地址
//SOCKADDR_IN serAddr, addrCli;

void key_allocate_cli();
void commuciation_cli();
void commuciation_cli_double();
void file_exchange_cli();
DWORD WINAPI recvMsgThread(LPVOID lpParameter);
DWORD WINAPI recvMsgThread_double(LPVOID lpParameter);  //客户端双人聊天和多人聊天的用于接受数据的线程代码一致

//DWORD WINAPI recvFileThread(LPVOID lpParameter);

int main() {
    
    //cout << "客户端得到共享密钥：" << endl;     //测试共享密钥是否分配成功
    //for (int i = KEY_SIZE - 1; i >= 0; i--) {
    //    printf("%02x ", key[i]);
    //}
    //printf("\n");
    //system("pause");
    int service = 0;
    while (1) {
        cout << "欢迎使用算法作业队的通信客户端" << endl;
        cout << "########################################################################################################" << endl;
        cout << "本软件为您提供安全的聊天通信服务和文件传输服务，选择1进入聊天室，选择2进入双人安全聊天，选择3进入文件传输" << endl;
        cin >> service;

        setbuf(stdin, NULL);  // 清空缓冲区，避免回车对后续程序造成影响
        if (service == 1) {
            commuciation_cli();
        }
        else if (service == 2) {
            key_allocate_cli();  // 客户端和服务端开始通信前初始化共享密钥
            commuciation_cli_double();
        }
        else if (service == 3) {
            key_allocate_cli();  // 客户端和服务端开始通信前初始化共享密钥
            file_exchange_cli();
        }

    }

    return 0;
}


void key_allocate_cli() {             //服务端作为alice，客户端作为bob使用dh协议进行公钥的交换得到共享密钥
    DH_KEY alice_public, bob_public;
    DH_KEY bob_secret, bob_private;

    DH_generate_key_pair(bob_public, bob_private);  //客户端使用随机算法生成自己的公钥和私钥


    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建套接字
    SOCKET cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);
    //向服务器发起连接请求
    if (connect(cliSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "连接错误，错误代码：" << WSAGetLastError() << endl;
        return;
    }

    //接收服务器传回的alice公钥
    char buf[BUFFER_SIZE] = { 0 };
    recv(cliSock, buf, KEY_SIZE, NULL);
    memcpy(alice_public, buf, KEY_SIZE);
    //客户端发送自己的bob公钥
    memcpy(buf, bob_public, KEY_SIZE);
    send(cliSock, buf, sizeof(buf), 0);
    
    //客户端使用自己的私钥和服务端的公钥进行共享密钥的生成
    DH_generate_key_secret(bob_secret, bob_private, alice_public);
    
    memcpy(key, bob_secret, KEY_SIZE);
    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    return;
}




void commuciation_cli_double() {

    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建套接字
    SOCKET cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);
    //向服务器发起连接请求
    if (connect(cliSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "连接错误，错误代码：" << WSAGetLastError() << endl;
        return;
    }
    else {
        cout << "########################################################################################################" << endl;
        cout << "已经成功连接对方" << endl;
        cout << "########################################################################################################" << endl;
    }
    CloseHandle(CreateThread(NULL, 0, recvMsgThread_double, (LPVOID)&cliSock, 0, 0));



    while (1) {
        char buf1[BUFFER_SIZE] = { 0 };
        char select[SELECT_SIZE] = { 0 };
        cout << "开始通信~" << endl;
        cout << "输入quit退出，按a进入聊天~" << endl;
        cout << "########################################################################################################" << endl;
        cin.getline(select, sizeof(select));
        cout << "########################################################################################################" << endl;
        if (strcmp(select, "quit") == 0) {  //输入quit退出文件传输
            break;
        }
        else {
            while (1) {
                unsigned char buf1[BUFFER_SIZE] = { 0 };
                unsigned char buf2[BUFFER_SIZE] = { 0 };
                unsigned char hmac[LENGTH_MD5] = { 0 };
                cout << "[您的输入]：" << endl;
                cin.getline((char*)buf1, sizeof(buf1));
                if (strcmp((char*)buf1, "quit") == 0) {  //输入quit退出聊天
                    break;
                }
                else {
                    AES_ECBEncrypt_text(buf1, key, BUFFER_SIZE);
                    hmac_md5(hmac, (unsigned char*)buf1, sizeof(buf1), key, sizeof(key));
                    strncat((char*)buf2, (char*)hmac, LENGTH_MD5);
                    strcat((char*)buf2, (char*)buf1);


                    //sprintf((char*)buf2, "%s%s", hmac, buf1); //因为不是0结尾所以读取字符串越界导致错误
                    send(cliSock, (char*)buf2, sizeof(buf2), 0);
                }
            }
        }
    }

    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    return;
}

DWORD WINAPI recvMsgThread_double(LPVOID lpParameter) {  //用于接受来自服务器数据的线程
    SOCKET cliSock = *(SOCKET*)lpParameter;
    while (1) {
        unsigned char buffer[BUFFER_SIZE] = { 0 };
        unsigned char hmac[LENGTH_MD5] = { 0 };
        unsigned char check_hmac[LENGTH_MD5] = { 0 };
        int nrecv = recv(cliSock, (char*)buffer, sizeof(buffer), 0);  //接受数据字节数
        if (nrecv >= 0) {  //接收到数据
            strncpy((char*)hmac, (char*)buffer, LENGTH_MD5);
            for (int i = 0; i < sizeof(buffer); i++) {  //去掉HMAC
                buffer[i] = buffer[i + LENGTH_MD5];
                if (i >= sizeof(buffer) - LENGTH_MD5) {
                    buffer[i] = 0;
                }
            }

            hmac_md5(check_hmac, (unsigned char*)buffer, sizeof(buffer), key, sizeof(key));
            AES_ECBDecrypt_text(buffer, key, BUFFER_SIZE);//AES解密
            cout << "[对方]: " << buffer << endl;
            if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
                cout << "本软件提示：对方发送的hmac不正确，消息可能被篡改，请勿将自己的关键信息发送给对方" << endl;

            }

        }
        else if (nrecv < 0) {  //未接收到数据
            cout << "与服务器断开连接" << endl;
            break;
        }
        cout << "[您的输入]：" << endl;
    }
    return 0;
}

void commuciation_cli() {
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建套接字
    SOCKET cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);

    struct sockaddr_in cliAddr;
    memset(&cliAddr, 0, sizeof(cliAddr));  //每个字节都用0填充
    cliAddr.sin_family = PF_INET;
    cliAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliAddr.sin_port = htons(1234);

    //向服务器发起连接请求
    if (connect(cliSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "连接错误，错误代码：" << WSAGetLastError() << endl;
    }

    CloseHandle(CreateThread(NULL, 0, recvMsgThread, (LPVOID)&cliSock, 0, 0));

    while (1) {
        char buf[100] = { 0 };
        cin.getline(buf, sizeof(buf));
        if (strcmp(buf, "quit") == 0) {  //输入quit退出聊天室
            break;
        }
        send(cliSock, buf, sizeof(buf), 0);
    }

    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    //system("pause");
    return;
}

DWORD WINAPI recvMsgThread(LPVOID lpParameter) {  //用于接受来自服务器数据的线程
    SOCKET cliSock = *(SOCKET*)lpParameter;
    while (1) {
        char buffer[BUFFER_SIZE] = { 0 };
        int nrecv = recv(cliSock, buffer, sizeof(buffer), 0);  //接受数据字节数
        if (nrecv >= 0) {  //接收到数据
            cout << buffer << endl;
        }
        else if (nrecv < 0) {  //未接收到数据
            cout << "与服务器断开连接" << endl;
            break;
        }
    }
    return 0;
}


void file_exchange_cli() {
    //初始化默认保存位置
    sprintf(save_place, "D:\\desktop\\recv_cli");
    sprintf(save_place_AES_temp, "D:\\AES_temp_cli");
    sprintf(save_place_compress_temp, "D:\\compress_temp_cli");
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建套接字
    SOCKET cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);
    //向服务器发起连接请求
    if (connect(cliSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cout << "连接错误，错误代码：" << WSAGetLastError() << endl;
        return;
    }
    else {
        cout << "########################################################################################################" << endl;
        cout << "已经成功连接对方" << endl;
        cout << "########################################################################################################" << endl;
    }

    //LPDWORD lpExitCode = (LPDWORD)malloc(sizeof(DWORD));
    //HANDLE f_handle = (CreateThread(NULL, 0, recvFileThread, (LPVOID)&cliSock, 0, 0));

    unsigned char buf[BUFFER_SIZE] = { 0 };
    char filename[FILENAME_SIZE] = { 0 };
    char select[SELECT_SIZE] = { 0 };
    cout << "是否使用文件传输功能" << endl;
    cout << "输入quit退出，输入change_save_place修改文件保存位置，输入upload开始上传文件，输入download开始接受文件" << endl;
    cout << "########################################################################################################" << endl;
    cin.getline(select, sizeof(select));
    cout << "########################################################################################################" << endl;
    if (strcmp(select, "quit") == 0) {  //输入quit退出文件传输
        //关闭套接字
        closesocket(cliSock);
        //终止使用 DLL
        WSACleanup();
        return;
    }
    else if (strcmp(select, "change_save_place") == 0) {
        cout << "请选择（输入）用于接受对方传输文件的保存位置" << endl;
        cin.getline(save_place, sizeof(save_place));
        cout << "########################################################################################################" << endl;
    }
    else if(strcmp(select, "upload") == 0){
        while (1) {
            unsigned char hmac[LENGTH_MD5] = { 0 };
            cout << "请输入要传输的文件路径及文件名：" << endl;
            cin.getline(filename, sizeof(filename));

            //GetExitCodeThread(f_handle, lpExitCode);     //如果线程接收到文件，则主线程退出
            //if (*lpExitCode != STILL_ACTIVE) {
            //    break;
            //}
            cout << "文件开始加密" << endl;
            AES_ECBEncrypt_file(filename, save_place_AES_temp, key);   //AES加密
            cout << "文件完成加密" << endl;
            cout << "文件开始压缩" << endl;
            LZSS_compress(save_place_AES_temp, save_place_compress_temp);//LZSS压缩文件
            cout << "文件完成压缩" << endl;
            hmac_md5_file(save_place_compress_temp, hmac, key, sizeof(key));
            FILE* fp = fopen(save_place_compress_temp, "rb");  //以二进制方式打开文件
            if (fp == NULL) {     //其实这里是没有用的，因为原本没有加密和压缩的时候可以检验输入文件名是否存在，但是加上加密和压缩后就成了检验临时文件是否存在了
                cout << "文件打开失败，请确保需要传输的文件存在" << endl;
                continue;
            }
            else {
                int nCount;

                send(cliSock, (char*)hmac, LENGTH_MD5, 0);  //先传输文件的hmac码
                cout << "文件开始上传" << endl;
                while ((nCount = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
                    send(cliSock, (char*)buf, nCount, 0);
                }
                shutdown(cliSock, SD_SEND);  //文件读取完毕，断开输出流，向服务端发送FIN包
                //recv(cliSock, buf, BUFFER_SIZE, 0);  //阻塞，等待客户端接收完毕
                cout << "文件上传完毕" << endl;
                cout << "########################################################################################################" << endl;
                fclose(fp);
                remove(save_place_AES_temp);
                remove(save_place_compress_temp);
                break;
            }
        }
    } 
    else if (strcmp(select, "download") == 0) {
        cout << "等待对方上传文件中" << endl;
        cout << "########################################################################################################" << endl;
        while (1) {
            unsigned char buffer[BUFFER_SIZE] = { 0 };
            unsigned char hmac[LENGTH_MD5] = { 0 };
            unsigned char check_hmac[LENGTH_MD5] = { 0 };
            int nrecv = recv(cliSock, (char*)buffer, sizeof(buffer), 0);  //接受数据字节数
            if (nrecv > 0) {  //接收到数据
                cout << "########################################################################################################" << endl;
                cout << "接受到来自对方的文件" << endl;
                FILE* fp = fopen(save_place_compress_temp, "wb");  //以二进制方式打开（创建）文件
                if (fp == NULL) {
                    cout << "文件保存失败，请确保需要保存的路径正确\n" << endl;
                }
                else {
                    int nCount;
                    cout << "文件开始下载" << endl;
                    memcpy(hmac, buffer, LENGTH_MD5);   //接受文件的hmac码
                    memset(buffer, 0, sizeof(buffer));
                    while ((nCount = recv(cliSock, (char*)buffer, BUFFER_SIZE, 0)) > 0) {
                        fwrite(buffer, nCount, 1, fp);
                    }
                    fclose(fp);    //要先关闭fp，不然hmac_md5_file中会继续沿着之前读入的位置进行读写，导致明明下载的文件是一样的但是校验文件长度都不对，卡了好久这个bug
                    cout << "文件下载完毕" << endl;
                    hmac_md5_file(save_place_compress_temp, check_hmac, key, sizeof(key));
                    if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
                        cout << "本软件提示：对方发送的文件hmac不正确，文件可能被篡改，文件的安全性未知" << endl;
                    }
                    cout << "文件开始解压" << endl;
                    LZSS_uncompress(save_place_compress_temp, save_place_AES_temp); //LZSS解压
                    cout << "文件完成解压" << endl;
                    cout << "文件开始解密" << endl;
                    AES_ECBDecrypt_file(save_place_AES_temp, save_place, key);       //AES解密
                    cout << "文件完成解密" << endl;
                    cout << "########################################################################################################" << endl;
                    remove(save_place_AES_temp);                                    //删除AES临时文件
                    remove(save_place_compress_temp);                               //删除LZSS临时文件           
                    cout << "接受完毕" << endl;
                    break;
                }
            }
            else if (nrecv < 0) {  //未接收到数据
                cout << "与服务器断开连接" << endl;
                break;
            }
        }
    }

    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    return;
}

//DWORD WINAPI recvFileThread(LPVOID lpParameter) {    //用于接受来自服务器数据的线程
//    SOCKET cliSock = *(SOCKET*)lpParameter;
//    while (1) {
//        unsigned char buffer[BUFFER_SIZE] = { 0 };
//        unsigned char hmac[LENGTH_MD5] = { 0 };
//        unsigned char check_hmac[LENGTH_MD5] = { 0 };
//        int nrecv = recv(cliSock, (char*)buffer, sizeof(buffer), 0);  //接受数据字节数
//        if (nrecv > 0) {  //接收到数据
//            cout << "########################################################################################################" << endl;
//            cout << "接受到来自对方的文件" << endl;
//            FILE* fp = fopen(save_place_compress_temp, "wb");  //以二进制方式打开（创建）文件
//            if (fp == NULL) {
//                cout << "文件保存失败，请确保需要保存的路径正确\n" << endl;
//            }
//            else {
//                int nCount;
//                cout << "文件开始下载" << endl;
//                memcpy(hmac, buffer, LENGTH_MD5);   //接受文件的hmac码
//                memset(buffer, 0, sizeof(buffer));
//                while ((nCount = recv(cliSock, (char*)buffer, BUFFER_SIZE, 0)) > 0) {
//                    fwrite(buffer, nCount, 1, fp);
//                }
//                fclose(fp);    //要先关闭fp，不然hmac_md5_file中会继续沿着之前读入的位置进行读写，导致明明下载的文件是一样的但是校验文件长度都不对，卡了好久这个bug
//                cout << "文件下载完毕" << endl;
//                hmac_md5_file(save_place_compress_temp, check_hmac, key, sizeof(key));
//                if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
//                    cout << "本软件提示：对方发送的文件hmac不正确，文件可能被篡改，文件的安全性未知"<< endl;
//                }
//                cout << "文件开始解压" << endl;
//                LZSS_uncompress(save_place_compress_temp, save_place_AES_temp); //LZSS解压
//                cout << "文件完成解压" << endl;
//                cout << "文件开始解密" << endl;
//                AES_ECBDecrypt_file(save_place_AES_temp, save_place, key);       //AES解密
//                cout << "文件完成解密" << endl;
//                remove(save_place_AES_temp);                                    //删除AES临时文件
//                remove(save_place_compress_temp);                               //删除LZSS临时文件
//                cout << "########################################################################################################" << endl;
//            }
//        }
//        else if (nrecv < 0) {  //未接收到数据
//            cout << "与服务器断开连接" << endl;
//            break;
//        }
//    }
//    closesocket(cliSock);
//    return 0;
//}
//    
