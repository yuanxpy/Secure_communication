// Project_SafetyCommuniction.cpp : 定义应用程序的入口点。
//
#include <Winsock2.h>  //windows socket编程头文件
#include <comdef.h>
#include <windows.h> 
#include <iostream>
#include <cstring>
#include <shlobj.h>
#include "framework.h"
#include "Project_SafetyCommuniction.h"
#include "dhexchange.h"
#include "AES.h"
#include "HMAC_md5.h"
#include "LZSS.h"

#pragma comment (lib, "ws2_32.lib") 
#pragma warning(disable:4996)
using namespace std;
#define MAX_LOADSTRING 100

// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名

static HBRUSH hBrush;//画刷
int Connection_Flag=0;//连接状态标识位
int Connection_Type = 0; //连接类别标识位
int Log_Count,Message_Count;
const int BUFFER_SIZE = 1024;//缓冲区大小
const int FILENAME_SIZE = 100;//文件名缓冲区大小
const int SELECT_SIZE = 20; //选择命令缓冲区大小
const int KEY_SIZE = 16;  //保存密钥长度
const int LENGTH_MD5 = 16; //md5结果报错的缓冲区大小
char buf[100] = { 0 };//消息数组
LPSTR buf_LP = (LPSTR)new char[100];;
char save_place[FILENAME_SIZE] = { 0 }; //存储文件下载后的保存位置的缓冲区
char save_place_AES_temp[FILENAME_SIZE] = { 0 };
char save_place_compress_temp[FILENAME_SIZE] = { 0 };
unsigned char key[KEY_SIZE] = { 0 };//存放密钥的缓冲区
SOCKET cliSock;

// 控件及句柄
HWND Button__ChatClass_Connection;//开始连接；
#define HMENU_BUTTON_ChatClass_Connection 8101
HWND Button_SendMassage;
#define HMENU_BUTTON_SendMassage 8102
HWND Button_SendFile;
#define HMENU_BUTTON_SendFile 8103
HWND MassageText;
#define HMENU_TEXT_MassageText 8201
HWND LogText;
#define HMENU_TEXT_LogText 8202
HWND FileText;
#define HMENU_TEXT_FileText 8203
HWND HistoryChatText;
#define HMENU_TEXT_HistoryCahtText 8204
HWND Button_FileChoice;
#define HMENU_BUTTON_FileChoice 8104
HWND Button_Decryption;
#define HMENU_BUTTON_Decryption 8105
HWND Button__CloseConnection;//关闭连接；
#define HMENU_BUTTON_CloseConnection 8106




// 此代码模块中包含的函数的前向声明:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

void key_allocate_cli();
void commuciation_cli();
void commuciation_cli_double();
void file_exchange_cli();
//传入发言人，历史消息框打印"xxx发言：xxx\n"
void WriteHistoryChatText(char* ANumber, char* Abuf);
//将一条消息缓冲到buf，传入发言人，历史消息框打印"xxx发言：xxx\n"
void WriteLogText(char* Measage);
void Savethemassage(HWND hWnd, char* FileAddress);
DWORD WINAPI recvMsgThread(LPVOID lpParameter);
DWORD WINAPI recvMsgThread_double(LPVOID lpParameter);  //客户端双人聊天和多人聊天的用于接受数据的线程代码一致
DWORD WINAPI recvFileThread(LPVOID lpParameter);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: 在此处放置代码。

    // 初始化全局字符串
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PROJECTSAFETYCOMMUNICTION, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PROJECTSAFETYCOMMUNICTION));

    MSG msg;

    // 主消息循环:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PROJECTSAFETYCOMMUNICTION));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_PROJECTSAFETYCOMMUNICTION);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 将实例句柄存储在全局变量中

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    //窗口初始化时
    case WM_CREATE:
    {
        Log_Count = 0;
        Message_Count = 0;
        int MainWindow_width = 0, MainWindow_height = 0;
        cin >> Connection_Flag;
        setbuf(stdin, NULL);  // 清空缓冲区，避免回车对后续程序造成影响
        RECT rect;
        HBRUSH hBrush = CreateSolidBrush(RGB(0, 0, 0));
        if (GetWindowRect(hWnd, &rect))
        {
            MainWindow_width = rect.right - rect.left;
            MainWindow_height = rect.bottom - rect.top;
        }
        Button__ChatClass_Connection = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("加入聊天室"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            5, 5, 85, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_ChatClass_Connection,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        Button_Decryption = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("双人加密加密通信"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            100, 5, 130, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_Decryption,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        Button__CloseConnection = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("关闭连接"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            240, 5, 75, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_CloseConnection,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        Button_SendMassage = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("发送"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            MainWindow_width - 100, MainWindow_height - 140, 75, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_SendMassage,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        Button_SendFile = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("发送文件"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            MainWindow_width - 100, MainWindow_height - 100, 75, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_SendFile,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        Button_FileChoice = CreateWindow(TEXT("button"),//必须为：button    
            TEXT("选择文件"),//按钮上显示的字符    
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            MainWindow_width / 2, MainWindow_height - 100, MainWindow_width / 2 - 110, 35,  //按钮在界面上出现的位置
            hWnd, (HMENU)HMENU_BUTTON_FileChoice,  //设置按钮Button_Connection 自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        FileText = CreateWindow(TEXT("edit"),//消息文本框   
            TEXT("D:\\desktop\\recv_cli\\"),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_LEFT | ES_WANTRETURN | ES_WANTRETURN,
            MainWindow_width / 2, MainWindow_height - 140, MainWindow_width / 2 - 110, 35,  //文本框在界面上出现的位置
            hWnd, (HMENU)HMENU_TEXT_FileText,  //设置按钮ID IDC_BUTTON_EXIT =132自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        MassageText = CreateWindow(TEXT("edit"),//消息输入文本框   
            TEXT("请输入消息.。。。"),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_LEFT | ES_WANTRETURN,
            MainWindow_width / 3 + 5, MainWindow_height / 2 + 5, MainWindow_width / 3 * 2 - 50, MainWindow_height / 2 - 140,  //文本框在界面上出现的位置
            hWnd, (HMENU)HMENU_TEXT_MassageText,  //设置按钮ID IDC_BUTTON_EXIT =132自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        HistoryChatText = CreateWindow(TEXT("edit"),//消息记录文本框   
            TEXT("历史消息：\n"),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | ES_OEMCONVERT,
            MainWindow_width / 3 + 5, 5, MainWindow_width / 3 * 2 - 50, MainWindow_height / 2,  //文本框在界面上出现的位置
            hWnd, (HMENU)HMENU_TEXT_LogText,  //设置按钮ID IDC_BUTTON_EXIT =132自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        LogText = CreateWindow(TEXT("edit"),//日志文本框  
            _T("日志:\n"),
            //TEXT("日志:\n欢迎使用算法作业队的通信客户端\n本软件为您提供安全的聊天通信服务和文件传输服务，请选择你要进行的服务。。。。\n"),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | ES_OEMCONVERT,
            5, 45, MainWindow_width / 3 - 5, MainWindow_height - 120,  //文本框在界面上出现的位置
            hWnd, (HMENU)HMENU_TEXT_LogText,  //设置按钮ID IDC_BUTTON_EXIT =132自己定义ID
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        break;
    }
    // 鼠标点击一个按钮
    case WM_COMMAND:
        {
        int wmId = LOWORD(wParam);
        // 分析菜单选择:
        switch (wmId)
        {
        case HMENU_BUTTON_ChatClass_Connection: {
            if (Connection_Flag==0) {
                SendMessage(LogText, EN_SETFOCUS, 0, 0);
                SendMessageA(LogText, EM_SETSEL, -2, -1);
                //SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)Log_Count);
                //Log_Count= Log_Count+1;
                SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"正在加入多人聊天室，请稍等。。。。\n");
                SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
                commuciation_cli();
                Connection_Flag = 1;
                Connection_Type = 1;
                break;
            }
            else {
                if (Connection_Type == 1) {
                    SendMessage(LogText, EN_SETFOCUS, 0, 0);
                    SendMessageA(LogText, EM_SETSEL, -2, -1);
                    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"您以在聊天室中\n");
                    SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
                    break;
                }
                else {
                    SendMessage(LogText, EN_SETFOCUS, 0, 0);
                    SendMessageA(LogText, EM_SETSEL, -2, -1);
                    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"您以在加密通信中\n");
                    SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
                    break;
                }
            }           
        }      
        case HMENU_BUTTON_SendMassage: {
            if (Connection_Flag == 1) {
                SendMessage(MassageText, WM_GETTEXT, 100, (LPARAM)buf_LP);
                Sleep(1000);
                if(sizeof(buf_LP) == 0){
                    break;
                }
                SendMessage(HistoryChatText, EN_SETFOCUS, 0, 0);
                SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
                SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)"我发送：");
                SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
                SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)buf_LP);
                SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
                SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)"\n");
                if(Connection_Flag==2){
                    _bstr_t C(buf_LP);
                    strcpy(buf,C);
                    unsigned char buf2[BUFFER_SIZE] = { 0 };
                    unsigned char hmac[LENGTH_MD5] = { 0 };
                    // buf1 = (unsigned char)buf_LP;
                    AES_ECBEncrypt_text((unsigned char*)buf, key, BUFFER_SIZE);
                    hmac_md5(hmac, (unsigned char*)buf, sizeof(buf), key, sizeof(key));
                    strncat((char*)buf2, (char*)hmac, LENGTH_MD5);
                    strcat((char*)buf2, (char*)buf);
                    //sprintf((char*)buf2, "%s%s", hmac, buf1); //因为不是0结尾所以读取字符串越界导致错误
                    send(cliSock, (char*)buf2, sizeof(buf2), 0);
                }
                if (Connection_Flag == 1) {
                    _bstr_t C(buf_LP);
                    send(cliSock, C, sizeof(C), 0);
                }
                SendMessage(LogText, EN_SETFOCUS, 0, 0);
                SendMessageA(LogText, EM_SETSEL, -2, -1);
                SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"您发送了一条消息\n");
                //清空消息发送文本框
                SendMessage(MassageText, EN_SETFOCUS, 0, 0);
                SendMessage(MassageText, EM_SETSEL, -1, -1);
                SendMessage(MassageText, WM_SETTEXT, NULL, (LPARAM)"");
            }
            else {
                SendMessage(LogText, EN_SETFOCUS, 0, 0);
                SendMessageA(LogText, EM_SETSEL, -2, -1);
                SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"未连接到服务器\n");
            }
            break;
        }
        case HMENU_BUTTON_SendFile: {
            SendMessage(LogText, EN_SETFOCUS, 0, 0);
            SendMessageA(LogText, EM_SETSEL, -2, -1);
            SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"开始发送文件:\n");
            file_exchange_cli();
            break;
        }
        case HMENU_BUTTON_CloseConnection: {
            SendMessage(LogText, EN_SETFOCUS, 0, 0);
            SendMessageA(LogText, EM_SETSEL, -2, -1);
            SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"正在关闭连接...\n");
            //关闭套接字
            closesocket(cliSock);
            cliSock = NULL;
            Savethemassage(LogText, "LogText.txt");
            Savethemassage(HistoryChatText, "HistoryText.txt");
            Connection_Flag = 0;
            Connection_Type = 0;
            //终止使用 DLL
            WSACleanup();
            //system("pause");
            SendMessage(LogText, EN_SETFOCUS, 0, 0);
            SendMessageA(LogText, EM_SETSEL, -2, -1);
            SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"已断开与服务器连接!\n");
            break;
        }
        case HMENU_BUTTON_Decryption: {
            if (Connection_Flag == 0) {
                SendMessage(LogText, EN_SETFOCUS, 0, 0);
                SendMessageA(LogText, EM_SETSEL, -2, -1);
                SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"开始连接。。。。\n");
                key_allocate_cli();  // 客户端和服务端开始通信前初始化共享密钥
                closesocket(cliSock);
                //终止使用 DLL
                WSACleanup();
                commuciation_cli_double();
                Connection_Flag = 1;
                Connection_Type = 2;
                break;
            }
            else {
                if (Connection_Type == 1) {
                    SendMessage(LogText, EN_SETFOCUS, 0, 0);
                    SendMessageA(LogText, EM_SETSEL, -2, -1);
                    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"您以在聊天室中\n");
                    SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
                    break;
                }
                else {
                    SendMessage(LogText, EN_SETFOCUS, 0, 0);
                    SendMessageA(LogText, EM_SETSEL, -2, -1);
                    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"您以在加密通信中\n");
                    SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
                    break;
                }
            }
        }
        case HMENU_BUTTON_FileChoice: {
            OPENFILENAME opfn;
            LPSTR strFilename = (LPSTR)new WCHAR[40];;//存放文件名  
            //初始化  
            ZeroMemory(&opfn, sizeof(OPENFILENAME));
            opfn.lStructSize = sizeof(OPENFILENAME);//结构体大小  
            //设置过滤  
            opfn.lpstrFilter = "所有文件\0*.*\0文本文件\0*.txt\0MP3文件\0*.mp3\0";
            //默认过滤器索引设为1  
            opfn.nFilterIndex = 1;
            //文件名的字段必须先把第一个字符设为 \0  
            opfn.lpstrFile = strFilename;
            opfn.lpstrFile[0] = '\0';
            opfn.nMaxFile = sizeof(strFilename);
            //设置标志位，检查目录或文件是否存在  
            opfn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            //opfn.lpstrInitialDir = NULL;  
            // 显示对话框让用户选择文件  
            if (GetOpenFileName(&opfn))
            {
                SendMessage(LogText, EN_SETFOCUS, 0, 0);
                SendMessage(FileText, EM_SETSEL, -1, -1);
                SendMessage(FileText, WM_SETTEXT, NULL, (LPARAM)strFilename);
            }
            break;
        }

        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        int hiwId = HIWORD(wParam);
        switch (hiwId) {
            case EN_SETFOCUS:{
                if (wmId == HMENU_TEXT_MassageText) {
                    SendMessageA(MassageText, EM_REPLACESEL, true, (LPARAM)L"");
                }
                break;
            }
        }
        }
        break;
    /* case OCM_CTLCOLORSTATIC: {
    *    HDC hdcStatic = (HDC)wParam;
    *    SetTextColor(hdcStatic, RGB(255, 255, 255));  //白色
    *    SetBkColor(hdcStatic, RGB(0x41, 0x96, 0x4F));  //翠绿色
    *     return (INT_PTR)hBrush;
    * }
    */
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: 在此处添加使用 hdc 的任何绘图代码...
            EndPaint(hWnd, &ps);
        }
        break;
    // 当我们点击×后，结束这个进程
    case WM_DESTROY:
        DeleteObject(hBrush);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}


void key_allocate_cli() {             //服务端作为alice，客户端作为bob使用dh协议进行公钥的交换得到共享密钥
    DH_KEY alice_public, bob_public;
    DH_KEY bob_secret, bob_private;

    DH_generate_key_pair(bob_public, bob_private);  //客户端使用随机算法生成自己的公钥和私钥
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"载入socket库文件失败\n");
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
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"连接错误，错误代码：");
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)WSAGetLastError());
        return;
    }
    CloseHandle(CreateThread(NULL, 0, recvMsgThread, (LPVOID)&cliSock, 0, 0));
    return;
}

void commuciation_cli_double() {

    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"载入socket库文件失败\n");
        return;
    }
    //创建套接字
    cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //初始化地址信息
    struct sockaddr_in serAddr;
    memset(&serAddr, 0, sizeof(serAddr));  //每个字节都用0填充
    serAddr.sin_family = PF_INET;
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serAddr.sin_port = htons(1234);
    //向服务器发起连接请求
    if (connect(cliSock, (SOCKADDR*)&serAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"连接错误，错误代码：");
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)WSAGetLastError());
        return;
    }
    else {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"已经成功连接对方\n");
    }
    CloseHandle(CreateThread(NULL, 0, recvMsgThread_double, (LPVOID)&cliSock, 0, 0));
    SendMessage(LogText, EN_SETFOCUS, 0, 0);
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"开始通信\n");
    // cout << "输入quit退出，按a进入聊天~" << endl;
    // cout << "########################################################################################################" << endl;
    //关闭套接字
    // closesocket(cliSock);
    //终止使用 DLL
    // WSACleanup();
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
            WriteHistoryChatText("[对方]", (char*)buffer);
            if (memcmp(hmac, check_hmac, LENGTH_MD5) != 0) {
                WriteLogText("本软件提示：对方发送的hmac不正确，消息可能被篡改，请勿将自己的关键信息发送给对方");
            }

        }
        else if (nrecv < 0) {  //未接收到数据
            WriteLogText("与服务器断开连接");
            break;
        }
    }
    return 0;
}

void commuciation_cli() {
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"载入socket库文件失败\n");
        SendMessageA(LogText, WM_VSCROLL, SB_BOTTOM, 0);
        return;
    }
    //创建套接字
    cliSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

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
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"连接错误，错误代码：\n");
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)WSAGetLastError());
    }
    CloseHandle(CreateThread(NULL, 0, recvMsgThread, (LPVOID)&cliSock, 0, 0));
    SendMessage(LogText, EN_SETFOCUS, 0, 0);
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"连接成功！\n");
}

DWORD WINAPI recvMsgThread(LPVOID lpParameter) {  //用于接受来自服务器数据的线程
    SOCKET cliSock = *(SOCKET*)lpParameter;
    while (Connection_Flag==1) {
        char buffer[BUFFER_SIZE] = { 0 };
        int nrecv = recv(cliSock, buffer, sizeof(buffer), 0);  //接受数据字节数
        if (nrecv >= 0) {  //接收到数据
            WriteLogText("接收到一条消息\n");
            WriteHistoryChatText("", buffer);
            printf(buffer);
        }
        else if (nrecv < 0) {  //未接收到数据
            WriteLogText("与服务器断开连接\n");
            break;
        }
    }
    return 0;
}

void file_exchange_cli() {
    //初始化默认保存位置
    SendMessage(FileText, WM_GETTEXT, 100, (LPARAM)buf_LP);
    //GetWindowText(FileText, buf_LP, 100);
    SendMessage(LogText, EN_SETFOCUS, 0, 0);
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"文件保存地址:D:\\desktop\\recv_cli\n");
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"AES缓存地址:D:\\AES_temp_cli\n");
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"临时文件:D:\\compress_temp_cli\n");
    //初始化 DLL 和版本信息
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"载入socket库文件失败\n");
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
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"连接错误，错误代码：%d\n");
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)WSAGetLastError());
        return;
    }
    else {
        SendMessage(LogText, EN_SETFOCUS, 0, 0);
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"########################################################################################################\n");
        SendMessageA(LogText, EM_SETSEL, -2, -1);
        SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"已成功连接对方\n");
    }

    LPDWORD lpExitCode = (LPDWORD)malloc(sizeof(DWORD));
    HANDLE f_handle = (CreateThread(NULL, 0, recvFileThread, (LPVOID)&cliSock, 0, 0));
    //这里界面没有指令输入，我打开了一个命令窗口
    AllocConsole();
    FILE* stream;
    freopen_s(&stream, "CON", "r", stdin);//重定向输入流
    freopen_s(&stream, "CON", "w", stdout);
    char buf[BUFFER_SIZE] = { 0 };
    char filename[FILENAME_SIZE] = { 0 };
    char select[SELECT_SIZE] = { 0 };
    cout << "是否使用文件上传功能" << endl;
    cout << "输入quit退出，输入change_save_place修改文件保存位置，输入a开始上传文件" << endl;
    cout << "########################################################################################################" << endl;
    cin.getline(select, sizeof(select));
    cout << "########################################################################################################" << endl;
    if (strcmp(select, "quit") == 0) {  //输入quit退出文件传输
        //关闭套接字
        closesocket(cliSock);
        //终止使用 DLL
        WSACleanup();
        FreeConsole();
        return;
    }
    else if (strcmp(select, "change_save_place") == 0) {
        cout << "请选择（输入）用于接受对方传输文件的保存位置" << endl;
        cin.getline(save_place, sizeof(save_place));
        cout << "########################################################################################################" << endl;
    }
    else {
        while (1) {
            unsigned char hmac[LENGTH_MD5] = { 0 };
            cout << "请输入要传输的文件路径及文件名：" << endl;
            cin.getline(filename, sizeof(filename));

            GetExitCodeThread(f_handle, lpExitCode);     //如果线程接收到文件，则主线程退出
            if (*lpExitCode != STILL_ACTIVE) {
                break;
            }
            cout << "文件开始加密" << endl;
            AES_ECBEncrypt_file(filename, save_place_AES_temp, key);   //AES加密
            cout << "文件完成加密" << endl;
            cout << "文件开始压缩" << endl;
            LZSS_compress(save_place_AES_temp, save_place_compress_temp);//LZSS压缩文件
            cout << "文件完成压缩" << endl;
            hmac_md5_file(save_place_compress_temp, hmac, key, sizeof(key));
            FILE* fp = fopen(save_place_compress_temp, "rb");  //以二进制方式打开文件
            if (fp == NULL) {
                cout << "文件打开失败，请确保需要传输的文件存在" << endl;
            }
            else {
                int nCount;

                send(cliSock, (char*)hmac, LENGTH_MD5, 0);  //先传输文件的hmac码
                cout << "文件开始上传" << endl;
                while ((nCount = fread(buf, 1, BUFFER_SIZE, fp)) > 0) {
                    send(cliSock, buf, nCount, 0);
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

    //关闭套接字
    closesocket(cliSock);
    //终止使用 DLL
    WSACleanup();
    FreeConsole();
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)L"文件上传完毕！\n");
    return;
}

DWORD WINAPI recvFileThread(LPVOID lpParameter) {    //用于接受来自服务器数据的线程
    SOCKET cliSock = *(SOCKET*)lpParameter;
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
                remove(save_place_AES_temp);                                    //删除AES临时文件
                remove(save_place_compress_temp);                               //删除LZSS临时文件
                cout << "########################################################################################################" << endl;
            }
        }
        else if (nrecv < 0) {  //未接收到数据
            cout << "与服务器断开连接" << endl;
            break;
        }
    }
    closesocket(cliSock);
    return 0;
}

//将消息缓冲到buf，传入发言人，历史消息框打印"xxx发言：xxx\n"
void WriteHistoryChatText(char* ANumber,char* Abuf){
    SendMessage(HistoryChatText, EN_SETFOCUS, 0, 0);
    SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
    SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)ANumber);
    SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
    SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)"发言：");
    SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
    SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)Abuf);
    SendMessageA(HistoryChatText, EM_SETSEL, -2, -1);
    SendMessageA(HistoryChatText, EM_REPLACESEL, true, (LPARAM)"\n");
}

//将一条消息缓冲到buf，传入发言人，历史消息框打印"xxx发言：xxx\n"
void WriteLogText(char* Measage) {
    SendMessage(LogText, EN_SETFOCUS, 0, 0);
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)Measage);
    SendMessageA(LogText, EM_SETSEL, -2, -1);
    SendMessageA(LogText, EM_REPLACESEL, true, (LPARAM)"\n");

}

//save Chat&Log History message;
void Savethemassage(HWND hWnd, char*FileAddress) {
    LPSTR buf_Temp = (LPSTR)new char[5000];;
    if (hWnd== MassageText) {
        SendMessage(MassageText, WM_GETTEXT, 5000, (LPARAM)buf_Temp);
        FILE* File1 = fopen(FileAddress, "w");
        if (File1 != NULL) {
            fprintf(File1, buf_Temp);
            fclose(File1);
        }
    }
    if (hWnd == LogText) {
        SendMessage(LogText, WM_GETTEXT, 5000, (LPARAM)buf_Temp);
        FILE* File1 = fopen(FileAddress, "w");
        if (File1 != NULL) {
            fprintf(File1, buf_Temp);
            fclose(File1);
        }   
    }
}