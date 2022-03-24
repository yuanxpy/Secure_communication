#include <Winsock2.h>  //windows socket编程头文件
#include <iostream>
#include <cstring>
#include "dhexchange.h"
#include "AES.h"
#include "HMAC_md5.h"
#include "LZSS.h"
#pragma comment (lib, "ws2_32.lib")  //加载 ws2_32.dll
using namespace std;



//全局常量和变量
const int BUFFER_SIZE = 1024;//缓冲区大小
const int FILENAME_SIZE = 100;//文件名缓冲区大小
const int SELECT_SIZE = 20; //选择命令缓冲区大小
const int KEY_SIZE = 16;  //保存密钥长度
const int LENGTH_MD5 = 16; //md5结果报错的缓冲区大小
const int WAIT_TIME = 10; //每个客户端等待事件毫秒数
const int RECV_TIMEPUT = 10;//接受消息超时时间毫秒数
const int SEND_TIMEPUT = 10;//发送消息超时时间毫秒数
const int MAX_LINK_NUM = 10;  //服务器最大连接数——目前暂定为2，之后可以试试扩展为多人聊天室
SOCKET cliSock[MAX_LINK_NUM]; //服务端负责与客户端通信的套接字，0号为服务端
SOCKADDR_IN cliAddr[MAX_LINK_NUM];
WSAEVENT cliEvent[MAX_LINK_NUM];//客户端事件
int total = 0; //当前连接数

char save_place[FILENAME_SIZE] = { 0 }; //存储文件下载后的保存位置
char save_place_AES_temp[FILENAME_SIZE] = { 0 };
char save_place_compress_temp[FILENAME_SIZE] = { 0 };
unsigned char key[KEY_SIZE] = { 0 };//存放密钥的缓冲区




void key_allocate_ser(); //dh协议共享密钥
void commuciation_ser();//服务器通信函数
void commuciation_ser_double();//服务器双人通信函数
DWORD WINAPI serEventThread(LPVOID lpParameter);//服务器事件处理线程
DWORD WINAPI recvMsgThread_double(LPVOID lpParameter);//服务器事件处理线程
void file_exchange_ser();//服务器文件传输函数

//DWORD WINAPI recvFileThread(LPVOID lpParameter);//服务器文件下载线程



int main() {

    //cout << "服务端得到共享密钥：" << endl;
    //for (int i = KEY_SIZE - 1; i >= 0; i--) {
    //    printf("%02x ", key[i]);
    //}
    //printf("\n");
    //system("pause");
    int service = 0;
    while (1) {
        cout << "欢迎使用算法作业队的通信服务端" << endl;
        cout << "########################################################################################################" << endl;
        cout << "本软件为您提供安全的聊天通信服务和文件传输服务，选择1进入聊天室，选择2进入双人安全聊天，选择3进入文件传输" << endl;
        cin >> service;

        setbuf(stdin, NULL);  // 清空缓冲区，避免回车对后续程序造成影响
        if (service == 1) {
            commuciation_ser();
        }
        else if (service == 2) {
            key_allocate_ser();
            commuciation_ser_double();
        }
        else if (service == 3) {
            key_allocate_ser();
            file_exchange_ser();
        }
    }
    return 0;
}


void key_allocate_ser() {             //服务端作为alice，客户端作为bob使用dh协议进行公钥的交换得到共享密钥
    DH_KEY alice_public, bob_public;
    DH_KEY alice_secret, alice_private;

    DH_generate_key_pair(alice_public, alice_private);  //客户端使用随机算法生成自己的公钥和私钥


    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建TCP的ipv4地址的套接字
    SOCKET serSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);

    //绑定套接字
    bind(serSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR));

    //进入监听状态，队列长度为10
    listen(serSock, 10);

    SOCKADDR cliAddr;
    int nSize = sizeof(SOCKADDR);
    SOCKET cliSock = accept(serSock, (SOCKADDR*)&cliAddr, &nSize);

    //服务端发送自己的alice公钥
    char buf[BUFFER_SIZE] = { 0 };
    memcpy(buf, alice_public, KEY_SIZE);
    send(cliSock, buf, sizeof(buf), 0);

    //接收客户端传回的bob公钥
    recv(cliSock, buf, KEY_SIZE, NULL);
    memcpy(bob_public, buf, KEY_SIZE);


    //客户端使用自己的私钥和服务端的公钥进行共享密钥的生成
    DH_generate_key_secret(alice_secret, alice_private, alice_public);

    memcpy(key, alice_secret, KEY_SIZE);
    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    return;
}


void commuciation_ser_double() {
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建TCP的ipv4地址的套接字
    SOCKET serSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;  //使用IPv4地址
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serAddr.sin_port = htons(1234);  //端口
    //绑定套接字
    bind(serSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR));

    //进入监听状态，队列长度为20
    listen(serSock, 10);

    SOCKADDR cliAddr;
    int nSize = sizeof(SOCKADDR);
    SOCKET cliSock = accept(serSock, (SOCKADDR*)&cliAddr, &nSize);
    //向服务器发起连接请求

    CloseHandle(CreateThread(NULL, 0, recvMsgThread_double, (LPVOID)&cliSock, 0, 0));

    cout << "########################################################################################################" << endl;
    cout << "已经成功连接对方" << endl;
    cout << "########################################################################################################" << endl;

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
                if (strcmp((char*)buf1, "quit") == 0) {  //输入quit退出
                    break;
                }
                else {
                    if (strcmp((char*)buf1, "quit") == 0) {  //输入quit退出聊天
                        break;
                    }
                    AES_ECBEncrypt_text(buf1, key, BUFFER_SIZE);//AES加密

                    hmac_md5(hmac, (unsigned char*)buf1, sizeof(buf1), key, sizeof(key));  //计算hmac码

                    strncat((char*)buf2, (char*)hmac, LENGTH_MD5);
                    strcat((char*)buf2, (char*)buf1);
                    //sprintf((char*)buf2, "%s%s", hmac, buf1); //因为不是0结尾所以读取字符串越界导致错误


                    send(cliSock, (char*)buf2, sizeof(buf2), 0);
                }
            }
        }
    }
    //关闭套接字
    closesocket(serSock);
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    return;
}

DWORD WINAPI recvMsgThread_double(LPVOID lpParameter) {  //用于接受来自客户端数据的线程
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
            cout << "[您的输入]：" << endl;

        }
        else if (nrecv < 0) {  //未接收到数据
            cout << "与客户端断开连接" << endl;
            break;
        }
    }
    return 0;
}


void commuciation_ser() {
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建TCP的ipv4地址的套接字
    SOCKET serSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;  //使用IPv4地址
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serAddr.sin_port = htons(1234);  //端口
    //绑定套接字
    bind(serSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR));

    //给服务端的socket绑定事件对象，用于接受客户端连接的事件
    WSAEVENT serEvent = WSACreateEvent(); //创建一个人工重设的未传信事件对象
    WSAEventSelect(serSock, serEvent, FD_ALL_EVENTS);//绑定事件对象并监听所有事件

    cliSock[0] = serSock;
    cliEvent[0] = serEvent;

    //进入监听状态，队列长度为20
    listen(serSock, 10);

   //创建接受连接的线程
    CloseHandle(CreateThread(NULL, 0, serEventThread, (LPVOID)&serSock, 0, 0));
    cout << "通信服务器开启~" << endl;
    cout << "当前最大同时通信客户端数量" << MAX_LINK_NUM << endl;

    while (1) {
        unsigned char buf1[BUFFER_SIZE] = { 0 };
        unsigned char buf2[BUFFER_SIZE] = { 0 };
        unsigned char hmac[LENGTH_MD5] = { 0 };
        //strcpy(buf1, "[server]");
        cin.getline((char*)buf2, sizeof(buf2));
        if (strcmp((char*)buf2, "quit") == 0) {  //输入quit退出聊天室
            break;
        }
        //strcat(buf1, buf2);
        sprintf((char*)buf1, "[server]%s", buf2);

        cout << buf1 << endl;

        //sprintf((char*)buf2, "%s%s", hmac, buf1);   //因为不是0结尾所以读取字符串越界导致错误

        for (int j = 1; j <= total; j++) {
            send(cliSock[j], (char*)buf1, sizeof(buf1), 0);
        }
    }

    //终止 DLL 的使用
    WSACleanup();
}

//服务器事件处理线程
DWORD WINAPI serEventThread(LPVOID lpParameter) {
    //还原传入参数
    SOCKET serSock = *(SOCKET*)lpParameter;
    while (1) {
        //依次查看服务端和每个客服端是否发生时间，等待WAIT_TIME毫秒
        for (int i = 0; i < total + 1; i++) {
            int index = WSAWaitForMultipleEvents(1, &cliEvent[i], false, WAIT_TIME, false);
            index -= WSA_WAIT_EVENT_0; //index为客户端下标
            
            if (index == WSA_WAIT_TIMEOUT || index == WSA_WAIT_FAILED) { //超时或出错则跳过
                continue;
            }
            else if (index == 0) { //若此终端发生事件
                WSANETWORKEVENTS networkEvent;
                WSAEnumNetworkEvents(cliSock[i], cliEvent[i], &networkEvent);
                if (networkEvent.lNetworkEvents & FD_ACCEPT) {
                    if (networkEvent.iErrorCode[FD_ACCEPT_BIT] != 0) { 
                        cout << i << "号客服端建立连接错误，错误码：" << networkEvent.iErrorCode[FD_ACCEPT_BIT] << endl;
                        continue;
                    }
                    if (total + 1 < MAX_LINK_NUM) {
                        int newIndex = total + 1;
                        int addrLen = sizeof(SOCKADDR);
                        SOCKET newSock = accept(serSock, (SOCKADDR*)&cliAddr[newIndex], &addrLen);
                        if (newSock != INVALID_SOCKET) {
                            //给新客户端分配socket,并为其绑定事件对象，设置监听close，read和write事件
                            cliSock[newIndex] = newSock;
                            WSAEVENT newEvent = WSACreateEvent();
                            WSAEventSelect(cliSock[newIndex], newEvent, FD_CLOSE | FD_READ | FD_WRITE);
                            cliEvent[newIndex] = newEvent;
                            total++;
                            cout << "用户<" << newIndex << ">进入了聊天室，当前连接数：" << total << endl;
                            unsigned char buf1[BUFFER_SIZE] = { 0 };
                            unsigned char buf2[BUFFER_SIZE] = { 0 };
                            unsigned char hmac[LENGTH_MD5] = { 0 };
                            sprintf((char*)buf1, "[server]欢迎用户<%d>进入了聊天室，当前连接数：%d", newIndex, total);

                            //hmac_md5(hmac, (unsigned char*)buf1, sizeof(buf1), key, sizeof(key)); //附加hmac码
                            //strncat((char*)buf2, (char*)hmac, LENGTH_MD5);
                            //strcat((char*)buf2, (char*)buf1);

                            for (int j = 1; j <= total; j++) {
                                send(cliSock[j], (char*)buf1, sizeof(buf1), 0);
                            }
                        }
                    }
                }
                else if (networkEvent.lNetworkEvents & FD_CLOSE) { //客户端被关闭
                    if (networkEvent.iErrorCode[FD_CLOSE_BIT] != 0 && networkEvent.iErrorCode[FD_CLOSE_BIT] != 10053) { //原本测试总出现10053连接错误，后来查阅资料是客户端存在有一段数据未recv接受，但是debug未发现异常，网上说忽略即可，暂时先忽略
                        cout << i << "号客服端退出连接错误，错误码：" << networkEvent.iErrorCode[FD_CLOSE_BIT] << endl;
                        continue;
                    }
                    total--;
                    unsigned char buf1[BUFFER_SIZE] = { 0 };
                    unsigned char buf2[BUFFER_SIZE] = { 0 };
                    unsigned char hmac[LENGTH_MD5] = { 0 };
                    sprintf((char*)buf1, "[server]欢迎用户<%d>退出了聊天室，当前连接数：%d", i, total);

                    //hmac_md5(hmac, (unsigned char*)buf1, sizeof(buf1), key, sizeof(key)); //附加hmac码
                    //strncat((char*)buf2, (char*)hmac, LENGTH_MD5);
                    //strcat((char*)buf2, (char*)buf1);

                    for (int j = 1; j <= total; j++) {
                        send(cliSock[j], (char*)buf1, sizeof(buf1), 0);
                    }
                    cout << "用户<" << i << ">退出了聊天室，当前连接数：" << total << endl;
                    closesocket(cliSock[i]);
                    WSACloseEvent(cliEvent[i]);

                    for (int j = i; j < total; j++) {
                        cliSock[j] = cliSock[j + 1];
                        cliEvent[j] = cliEvent[j + 1];
                        cliAddr[j] = cliAddr[j + 1];
                    }

                }
                else if (networkEvent.lNetworkEvents & FD_READ) { //接收到消息
                    for (int j = 1; j <= total; j++) {
                        unsigned char buf1[BUFFER_SIZE] = { 0 };
                        unsigned char buf2[BUFFER_SIZE] = { 0 };
                        int nrev = recv(cliSock[j], (char*)buf2, sizeof(buf2), 0);
                        if (nrev > 0) {
                             sprintf((char*)buf1, "[用户%d]:%s", j, buf2);

                            cout << buf1 << endl;
                            for (int k = 1; k <= total; k++) {
                                send(cliSock[k], (char*)buf1, sizeof(buf1), 0);
                            }
                        }
                    }

                }
            }
        }
    }
    
}


void file_exchange_ser() {
    //初始化默认保存位置
    sprintf(save_place, "D:\\desktop\\recv_ser");
    sprintf(save_place_AES_temp, "D:\\AES_temp_ser");
    sprintf(save_place_compress_temp, "D:\\compress_temp_ser");
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "载入socket库文件失败" << endl;
        system("pause");
        return;
    }
    //创建TCP的ipv4地址的套接字
    SOCKET serSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;  //使用IPv4地址
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serAddr.sin_port = htons(1234);  //端口
    //绑定套接字
    bind(serSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR));

    //进入监听状态，队列长度为20
    listen(serSock, 10);

    SOCKADDR cliAddr;
    int nSize = sizeof(SOCKADDR);
    SOCKET cliSock = accept(serSock, (SOCKADDR*)&cliAddr, &nSize);
    //向服务器发起连接请求

    //LPDWORD lpExitCode = (LPDWORD)malloc(sizeof(DWORD));
    //HANDLE f_handle = (CreateThread(NULL, 0, recvFileThread, (LPVOID)&cliSock, 0, 0));

    cout << "########################################################################################################" << endl;
    cout << "已经成功连接对方" << endl;
    cout << "########################################################################################################" << endl;


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
    else if (strcmp(select, "upload") == 0) {
        while (1) {
            unsigned char hmac[LENGTH_MD5] = { 0 };
            cout << "请输入要传输的文件路径及文件名：" << endl;
            cin.getline(filename, sizeof(filename));

            //GetExitCodeThread(f_handle, lpExitCode);     //如果线程接收到文件，则主线程退出
            //if (*lpExitCode != STILL_ACTIVE) {
            //    break;
            //}
            cout << "开始文件加密" << endl;
            AES_ECBEncrypt_file(filename, save_place_AES_temp, key);   //AES加密
            cout << "文件完成加密" << endl;
            cout << "开始文件压缩" << endl;
            LZSS_compress(save_place_AES_temp, save_place_compress_temp);//LZSS压缩文件
            cout << "文件完成压缩" << endl;
            hmac_md5_file(save_place_compress_temp, hmac, key, sizeof(key));
            FILE* fp = fopen(save_place_compress_temp, "rb");  //以二进制方式打开文件
            if (fp == NULL) {
                cout << "文件传输失败，请确保需要传输的文件存在" << endl;
                continue;
            }
            else {
                int nCount;
                send(cliSock, (char*)hmac, LENGTH_MD5, 0);  //先传输文件的hmac码

                cout << "文件开始上传" << endl;
                while ((nCount = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
                    send(cliSock, (char*)buf, nCount, 0);
                }
                shutdown(cliSock, SD_SEND);  //文件读取完毕，断开输出流，向客户端发送FIN包
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
                cout << "接受到来自对方的文件 " << endl;
                FILE* fp = fopen(save_place_compress_temp, "wb");  //以二进制方式打开（创建）文件
                if (fp == NULL) {
                    cout << "文件创建失败，请确保需要保存的路径正确\n" << endl;
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
                    hmac_md5_file(save_place_compress_temp, check_hmac, key, sizeof(key));

                    if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
                        cout << "本软件提示：对方发送的文件hmac不正确，文件可能被篡改，文件的安全性未知" << endl;
                    }
                    cout << "文件下载完毕" << endl;
                    cout << "文件开始解压" << endl;
                    LZSS_uncompress(save_place_compress_temp, save_place_AES_temp); //LZSS解压
                    cout << "文件完成解压" << endl;
                    cout << "文件开始解密" << endl;
                    AES_ECBDecrypt_file(save_place_AES_temp, save_place, key);       //AES解密
                    cout << "文件完成解密" << endl;
                    cout << "########################################################################################################" << endl;
                    remove(save_place_AES_temp);                                 //删除AES临时文件
                    remove(save_place_compress_temp);                                 //删除LZSS临时文件
                    cout << "接受完毕" << endl;
                    break;
                }
            }
            else if (nrecv < 0) {  //未接收到数据
                cout << "与客户端断开连接" << endl;
                break;
            }
        }
    }


    //关闭套接字
    closesocket(cliSock);
    closesocket(serSock);
    //终止使用 DLL
    WSACleanup();
    return;
}

//DWORD WINAPI recvFileThread(LPVOID lpParameter) {    //用于接受来自客户端数据的线程
//    SOCKET cliSock = *(SOCKET*)lpParameter;
//    while (1) {
//        unsigned char buffer[BUFFER_SIZE] = { 0 };
//        unsigned char hmac[LENGTH_MD5] = { 0 };
//        unsigned char check_hmac[LENGTH_MD5] = { 0 };
//        int nrecv = recv(cliSock, (char *)buffer, sizeof(buffer), 0);  //接受数据字节数
//        if (nrecv > 0) {  //接收到数据
//            cout << "########################################################################################################" << endl;
//            cout << "接受到来自对方的文件 " << endl;
//            FILE* fp = fopen(save_place_compress_temp, "wb");  //以二进制方式打开（创建）文件
//            if (fp == NULL) {
//                cout << "文件创建失败，请确保需要保存的路径正确\n" << endl;
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
//                hmac_md5_file(save_place_compress_temp, check_hmac, key, sizeof(key));
//
//                if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
//                    cout << "本软件提示：对方发送的文件hmac不正确，文件可能被篡改，文件的安全性未知" << endl;
//                }
//                cout << "文件下载完毕" << endl;
//                cout << "文件开始解压" << endl;
//                LZSS_uncompress(save_place_compress_temp, save_place_AES_temp); //LZSS解压
//                cout << "文件完成解压" << endl;
//                cout << "文件开始解密" << endl;
//                AES_ECBDecrypt_file(save_place_AES_temp, save_place, key);       //AES解密
//                cout << "文件完成解密" << endl;
//                remove(save_place_AES_temp);                                 //删除AES临时文件
//                remove(save_place_compress_temp);                                 //删除LZSS临时文件
//                cout << "########################################################################################################" << endl;
//            }
//        }
//        else if (nrecv < 0) {  //未接收到数据
//            cout << "与客户端断开连接" << endl;
//            break;
//        }
//    }
//    return 0;
//}
//
