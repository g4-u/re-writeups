#### re01

> No hint.

> WriteUp: This challenge is pretty straight forward asks for a key and gives us a flag.


直接运行WhiteHat.exe，没有任何提示
于是丢到OD里，对`GetWindowTextA`下断，可以找到函数`sub_40199B`：

```c++
void sub_40199B()
{
  int v0; // eax@1
  int v1; // eax@2
  int v2; // [sp+8h] [bp-11Ch]@1
  char v3; // [sp+Ch] [bp-118h]@1
  char v4; // [sp+Dh] [bp-117h]@1
  int v5; // [sp+120h] [bp-4h]@1

  v0 = sub_406250();
  unknown_libname_52(v0);
  v5 = 0;
  v3 = 0;
  memset(&v4, 0, 0xF9u);
  CWnd::GetWindowTextA(&v2);                    // bp here
  if ( *(_DWORD *)(v2 - 12) == 16 )             // string length is 16
  {
    v1 = ATL::CSimpleStringT<char,0>::GetBuffer(&v2);// v1指向输入字符串
    sub_40138F(v1, &v3);                        // 如果字符串长度等于16，则进入字符串处理函数sub_40138F
  }
  ATL::CStringData::Release((ATL::CStringData *)(v2 - 16));
}
```
根据函数`sub_40138F`可以得到正确的输入:
```c++
signed int __fastcall sub_40138F(int a1, int a2)
{
  unsigned __int8 v27[16] = {0x83u,0xF9u,0x81u,0xE8u,0x87u,0xE9u,0x85u,0xAAu,
        0x8Bu,0xFAu,0x8Eu,0xC4u,0x8Du,0xF3u,0x93u,0xF2u}; // [sp+4Ch] [bp-14h]@1

  v2 = a1;
  input = a1;
  v3 = a2;

  GetNativeSystemInfo(&SystemInfo);
  GetLocalTime(&SystemTime);                    // SystemTime: Sat. 8.18.2018
  GetLocaleInfoA(0x400u, 0x20001009u, &LCData, 4);
  v4 = 11;
  while ( *(_BYTE *)(v2 + v4) == 'K' )          // input[11] == 'K'
  {                                             // 实际上只有一次循环
    v4 += 7;
    v26 = v4;
    if ( v4 >= 16 )
    {
      *(_DWORD *)v3 = byte_438A0C[0];
      *(_DWORD *)(v3 + 4) = byte_438A0C[1];
      *(_DWORD *)(v3 + 8) = byte_438A0C[2];
      *(_DWORD *)(v3 + 12) = byte_438A0C[3];
      *(_BYTE *)(v3 + 16) = byte_438A0C[4];     // v3 = "abcdefghiklmopqx"
      v5 = input;
      v6 = (_BYTE *)(v3 + 1);
      v7 = input - v3;                          // v7为两个字符串(v3和input)地址的差值
                                                // index based on v7, 实际上是input
      v8 = 8;
      do
      {
        *v6 ^= v6[v7];
        v6 += 2;
        --v8;
      }
      while ( v8 );                             // 两个字符为一组，将v3每组第二个字符与input每组第二个字符异或
      v9 = (_BYTE *)v3;
      v10 = 16;
      do
      {
        v9[v7] = LOBYTE(SystemTime.wDay) ^ (*v9 + v9[v7]);// 
                                                // input[i] = LOBYTE(SystemTime.wDay) ^ (v3[i] + input[i]);
                                                // or 
                                                // input[i] = 0x12 ^ (v3[i] + input[i]);
        *v9++ ^= LOBYTE(SystemTime.wYear);      // 
                                                // v3[i] ^= LOBYTE(SystemTime.wYear);
                                                // or 
                                                // v3[i] ^= 0xe2;
        --v10;                                  // ++i;
      }
      while ( v10 );                            // while(i<16)
      *(_BYTE *)(v5 + 16) += LOBYTE(SystemTime.wDayOfWeek);// 
                                                // input[16] += LOBYTE(SystemTime.wDayOfWeek)
                                                // or 
                                                // input[16] += 0x6
      i = 0;
      while ( *(&v27[i] + v3 - (signed int)v27) == v27[i] )// 字符判断: v27[i] == v3[i]
      {
        if ( ++i >= 16 )                        // length: 16
        {
          v12 = 0;
          do
          {
            v26 += *(_BYTE *)(v3 + v12);
            v12 += 4;
          }
          while ( v12 < 16 );
          v13 = FindResourceA(0, (LPCSTR)0x86, "EXE");// a HTML document
          GetLastError();
          v14 = LoadResource(0, v13);
          v15 = LockResource(v14);
          v16 = SizeofResource(0, v13);
          v17 = v16;
          v18 = sub_4010FC(v16);                // 使(v16+x)能被3整除(x取0, 1, 2)
                                                // 返回(v16+x)*4/3
          v19 = malloc(v18 + 50);
          v20 = v19;
          if ( !v19 || (sub_401000(v19, (int)v15, v17), (result = sub_40111D(v26 / 2 + v20[350000] + 192)) != 0) )// 
                                                // sub_401000: 输入无关(?)
                                                // 以上这段都可以忽略，重点是函数sub_40111D
                                                // bp here
            result = 1;
          return result;
        }
      }
      return 0;
    }
  }
  return 0;
}
```
脚本：
```python
sec = [0x83,0xF9,0x81,0xE8,0x87,0xE9,0x85,0xAA,0x8B,0xFA,0x8E,0xC4,0x8D,0xF3,0x93,0xF2]
v3 = [ord(c) for c in "abcdefghiklmopqx"]

'''original:

input_str = [ord(c) for c in "asdfasfdasdfasdf"]
for i in range(1, len(v3), 2):
    v3[i] ^= input_str[i]

for i in range(16):
    input_str[i] = (v3[i] + input_str[i]) ^ 0x12
    v3[i] ^= 0xe2
'''

for i in range(len(sec)):
    sec[i] ^= 0xe2
for i in range(1, len(sec), 2):
    sec[i] ^= v3[i]
print(''.join([chr(c) for c in sec]))
```
可以得到key： `aycnemg islKoaqh` (**比赛时做到了这一步**)

> WriteUp: After entering the correct key. The executable drop two files named 2.exe and b.dll in %temp% folder (sub_40111D) and runs the 2.exe using CreateProcessA with "564" as CLA(command line arguments).
> After analyzing 2.exe we see that it checks for the parent process ID and must be named to "WhiteHat" if this so it drops the flag.dll in %temp% folder.
> But wait this flag.dll is not actually a PE file. By seeing it's header we get that it is an PNG file. By changing the extension to .png we get our flag.

函数`sub_40111D`:
```c++
signed int __stdcall sub_40111D(int a1)
{
  HGLOBAL v1; // eax@1
  HRSRC v2; // eax@1
  HRSRC v3; // esi@1
  HGLOBAL v4; // eax@1
  const void *v5; // edi@1
  HANDLE v6; // esi@1
  signed int v7; // ecx@1
  signed int v8; // eax@3
  struct _STARTUPINFOA StartupInfo; // [sp+Ch] [bp-80h]@5
  DWORD v11; // [sp+50h] [bp-3Ch]@1
  DWORD NumberOfBytesWritten; // [sp+54h] [bp-38h]@1
  struct _PROCESS_INFORMATION ProcessInformation; // [sp+58h] [bp-34h]@5
  LPCVOID lpBuffer; // [sp+68h] [bp-24h]@1
  HANDLE hObject; // [sp+6Ch] [bp-20h]@1
  HRSRC hResInfo; // [sp+70h] [bp-1Ch]@1
  char v17; // [sp+74h] [bp-18h]@1
  char v18; // [sp+75h] [bp-17h]@1
  char v19; // [sp+98h] [bp+Ch]@1
  CHAR Buffer; // [sp+178h] [bp+ECh]@1
  char v21; // [sp+179h] [bp+EDh]@1
  CHAR FileName; // [sp+27Ch] [bp+1F0h]@1
  char v23; // [sp+27Dh] [bp+1F1h]@1
  CHAR CommandLine; // [sp+380h] [bp+2F4h]@5
  char v25; // [sp+381h] [bp+2F5h]@5
  int v26; // [sp+3E4h] [bp+358h]@3
  int v27; // [sp+3E8h] [bp+35Ch]@3
  int v28; // [sp+3ECh] [bp+360h]@3

  Buffer = 0;
  memset(&v21, 0, 0x103u);
  FileName = 0;
  memset(&v23, 0, 0x103u);
  memset(&v18, 0, 0x103u);
  GetTempPathA(0x104u, &Buffer);
  GetTempPathA(0x104u, &FileName);
  strcat_s(&Buffer, 0x104u, "b.dll"); // 文件路径
  strcat_s(&FileName, 0x104u, "2.exe"); // 文件路径
  hResInfo = FindResourceA(0, (LPCSTR)0x8D, "SYS");
  GetLastError();
  v1 = LoadResource(0, hResInfo);
  lpBuffer = LockResource(v1);
  hResInfo = (HRSRC)SizeofResource(0, hResInfo);
  hObject = CreateFileA(&FileName, 0x10000000u, 1u, 0, 2u, 0x80u, 0);// create file %TEMP%\2.exe
  WriteFile(hObject, lpBuffer, (DWORD)hResInfo, &NumberOfBytesWritten, 0);
  CloseHandle(hObject);
  v2 = FindResourceA(0, (LPCSTR)0x8E, "SYS");
  v3 = v2;
  v4 = LoadResource(0, v2);
  v5 = LockResource(v4);
  hObject = (HANDLE)SizeofResource(0, v3);
  v6 = CreateFileA(&Buffer, 0x10000000u, 1u, 0, 2u, 0x80u, 0);// create file %TEMP%\b.dll
  WriteFile(v6, v5, (DWORD)hObject, &v11, 0);
  CloseHandle(v6);
  qmemcpy(&v17, "qa\"apgcvg\"Rv\"v{rg?\"dkngq{q\"`klRcvj?\"", 0x24u);
  v7 = 0;
  v19 = aQaApgcvgRvVRg_[36];
  do
  {
    *(&v17 + v7) ^= a1 - 48;
    ++v7;
  }
  while ( v7 < 36 );
  v26 = *(_DWORD *)"p`#pwbqw#Sw";
  v27 = *(_DWORD *)"wbqw#Sw";
  v8 = 0;
  v28 = *(_DWORD *)"#Sw";
  do
    *((_BYTE *)&v26 + v8++) ^= (_BYTE)a1 - 47;
  while ( v8 < 11 );
  CommandLine = 0;
  memset(&v25, 0, 0x63u);
  sprintf(&CommandLine, "%d", a1);
  memset(&StartupInfo, 0, 0x44u);
  StartupInfo.cb = 68;
  if ( CreateProcessA(&FileName, &CommandLine, 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInformation) ) // run 2.exe with CommandLine as argument, which is "564"(dumped) according to function sub_40128F
  {
    WaitForSingleObject(ProcessInformation.hProcess, 0xFFFFFFFF);
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    DeleteFileA(&Buffer);
    DeleteFileA(&FileName);
  }
  return 1;
}
```

最终在%TEMP%文件夹下可以得到三个文件：`b.dll`，`a.exe`，`flag.dll`。
`file`查看flag.dll文件头，可以发现是个PNG文件。
```shell
$ file flag.dll
flag.dll: PNG image data, 560 x 217, 8-bit/color RGB, non-interlaced
```
更改扩展名，打开图片即可看到flag:
`flag is: today is good day`

---

#### re06 - 100p
> Note: If you find flag in format WhiteHat{abcdef}, you should submit in form WhiteHat{sha1(abcdef)}

直接打开`reverse.exe`, 是个key checker, 包括一个文本框和一个button
`file`看一下, 是个`.net`逆向
```shell
$ file reverse.exe
reverse.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Window           s
```

用`reflector`打开, 可以看到`MainWindow`包含一个`tb_key(TextBox)`和一个`btn_check(Button)`.
观察函数, 有一个`btn_check_Click`, 看起来是`button`对应事件:
```csharp
private void btn_check_Click(object sender, RoutedEventArgs e)
{
    // 加密结果看起来是个base64
    if (Enc(this.tb_key.Text, 0x23c5, 0xa09d) == "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ=")
    {
        MessageBox.Show("Correct!! You found FLAG");
    }
    else
    {
        MessageBox.Show("Try again!");
    }
}
```
程序没坑, 把`Enc`函数逆向就可以得到输入的key.
其他函数:

```csharp
public static string Enc(string s, int e, int n)
{
    int num;
    int[] numArray = new int[s.Length];
    // numArray is s
    for (num = 0; num < s.Length; num++)
    {
        numArray[num] = s[num];
    }
    int[] numArray2 = new int[numArray.Length];
    // 用e和n对输入字符串的每一位应用mod函数
    // 结果是1字节变2字节, 注意字节序
    for (num = 0; num < numArray.Length; num++)
    {
        numArray2[num] = mod(numArray[num], e, n);
    }
    string str = "";
    for (num = 0; num < numArray.Length; num++)
    {
        str = str + ((char) numArray2[num]);
    }
    // 然后convert to base64 string
    return Convert.ToBase64String(Encoding.Unicode.GetBytes(str));
}
```
```csharp
// 这个函数可以不用管具体细节
public static int mod(int m, int e, int n)
{
    int[] numArray = new int[100];
    int index = 0;
    // numArray是e的二进制形式
    do
    {
        numArray[index] = e % 2;
        index++;
        e /= 2;
    }
    while (e > 0);
    int num2 = 1;
    for (int i = index - 1; i >= 0; i--)
    {
        num2 = (num2 * num2) % n;
        if (numArray[i] == 1)
        {
            num2 = (num2 * m) % n;
        }
    }
    return num2;
}
```
脚本:
```python
import base64
import hashlib

# 这里就是用python重写了一下上面的mod函数
def mod(m, e, n):
    numArray = []
    index = 0
    while e > 0:
        numArray.append(e % 2) 
        index += 1
        e //= 2
    num2 = 1
    for i in range(index-1, -1, -1):
        num2 = (num2 * num2) % n
        if numArray[i] == 1:
            num2 = (num2 * m) % n
    return hex(num2)[2:].zfill(4) # 这里需要补足4位

# 爆破字典
dicts = {}
for i in range(ord('0'), ord('}')+1):
    index = mod(i, 0x23c5, 0xa09d)[2:4] + mod(i, 0x23c5, 0xa09d)[:2] # little-endian, 小端存储,所以需要把字节顺序颠倒一下
    # mod后的两个字节对应原始输入的一个字节
    dicts[index] = chr(i)

enc = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ="
# base64解码, 因为解码出来的字节有些没有字符表示, 所以用hex表示
dec = base64.b64decode(enc).hex()
flag = ''
for i in range(0, len(dec), 4):
    flag += dicts[dec[i:i+4]]
# flag: WhiteHat{N3xT_t1m3_I_wi11_Us3_l4rg3_nUmb3r}
# 以SHA-1方式提交flag
print(flag[:9] + hashlib.sha1(flag[9:-1].encode("utf-8")).hexdigest() + flag[-1])
```

