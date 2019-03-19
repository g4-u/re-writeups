#### re03 - 380p
> No hint.

直接运行`DebugMe.exe`，发现是输入key然后进行验证。
用OD对`GetWindowText`下断，断在函数`sub_40BFA9`，查看对该函数的引用，可以发现程序大致流程如下：
```shell
+-----+     +------------+     +----------------+      +----------------+
| ... | --> | sub_4029C0 | --> |   sub_40BFA9   | ---> | GetWindowTextW |
+-----+     +------------+     +----------------+  |   +----------------+
              |                                    |
              | validate                           |
              v                                    v
            +------------+             +----------------------+
            | sub_402BB0 |             | GetWindowTextLengthW |
            +------------+             +----------------------+
```

`sub_4029C0`:
```c
int __thiscall sub_4029C0(void *this)
{
  v1 = (const unsigned __int16 *)this;
  v13 = 0;
  sub_404C10(&v13, &word_5AAA50);
  v14 = 0;
  sub_40BFA9((int)(v1 + 0xAC), (int)&v13);      // read window text to v13
  v2 = v13;
  v3 = &word_5AAA50;
  while ( 1 )
  {
    v4 = *v2 < *v3;
    if ( *v2 != *v3 )
      break;
    if ( !*v2 )
      goto LABEL_6;
    v5 = v2[1];
    v4 = v5 < v3[1];
    if ( v5 != v3[1] )
      break;
    v2 += 2;
    v3 += 2;
    if ( !v5 )
    {
LABEL_6:
      v6 = 0;
      goto LABEL_8;
    }
  }
  v6 = -v4 | 1;
LABEL_8:
  if ( v6 == 0 )
  {
    MessageBoxW(0, L"Key is empty!", L"Notify", 0);
  }
  else
  {
    v11 = (int)v3;
    v12 = &v11;
    strcpy(&v11, (int *)&v13);
    if ( sub_402BB0(v1, v7, v11) ) // 显然，该函数为验证函数, v11为输入字符串
      MessageBoxW(0, L"Success: Key is correct!", L"Notify", 0x40u);
    else
      MessageBoxW(0, L"Key is NOT correct!", L"Notify", 0x10u);
  }
  v14 = -1;
  v8 = v13 - 8;
  result = _InterlockedDecrement((volatile signed __int32 *)v13 - 1);
  if ( result <= 0 )
  {
    v10 = *(_DWORD *)v8;
    v11 = (int)v8;
    result = (*(int (__stdcall **)(OLECHAR *))(*(_DWORD *)v10 + 4))(v8);
  }
  return result;
}
```

`sub_402BB0`:
```c
signed int __fastcall sub_402BB0(const unsigned __int16 *a1, int a2, int input)
{
  v82 = (unsigned __int16 *)a1;
  v91 = 0;
  v3 = *(_DWORD *)(input - 12); // input length
  if ( v3 < 10 )  goto fail1;
  if ( v3 <= 10 )  goto LABEL_7;
  strcpy(&v81, &input);         // strcpy
  sub_404010(&sub1, (int)v81);  // 字符串处理
                                // 将"dvfrhtgbPr"的前9位替换为v81前9位对应位置值+3
                                // 伪：
                                // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 3 for i in range(9)
  strcpy(&v81, (int *)&sub1);   // strcpy
  sub_404010(&sub2, (int)v81);  // 字符串处理，将上一步得到的sub1字符串做相同的处理
                                // 或者说，这两步操作等价于：（伪）
                                // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 6 for i in range(9)
  a1 = (const unsigned __int16 *)wcscmp(sub2, L"wiergrrrrrrfwefi");
  /* ... */
  if ( !a1 )                    // ******* fail if equal *******
  {
fail7:
    /* ... */
    goto fail1;
  }
LABEL_15:
  /* ... */
  while ( 1 )
  {
    while ( v3 >= 55 ); // 字符串长度>=55, 直接陷入死循环
    strcpy(&v81, &input);
    sub_404010(&sub1, (int)v81); // string = "dvfrhtgbPr"
                                 // string[i] = v81[i] + 3 for i in range(9)
    strcpy(&v81, &input);
    sub_404100(&sub2, (int)v81); // string = "dvfrhtgbPr"
                                 // string[i] = v81[i+10] for i in range(9)
    strcpy(&v81, &input);
    sub_404200(&sub3, (int)v81); // string = "rfdeswe32f"
                                 // string[i] = v81[i+20] for i in range(9)
    v3 += 50;                    
    v14 = wcscmp(sub2, L"wiergrrrrrrfwefi");
    if ( !v14 ) goto fail2;      // ******* fail if equal *******
    a1 = sub1;
    v15 = L"efffffe3f";
    while ( 1 ) // 这里是一个字符串比较
    {
      v16 = *a1 < *v15;
      if ( *a1 != *v15 )
        break;
      if ( !*a1 )
        goto fail5;
      v17 = a1[1];
      v16 = v17 < v15[1];
      if ( v17 != v15[1] )
        break;
      a1 += 2;
      v15 += 2;
      if ( !v17 )
      {
fail5:
        v18 = 0;
        goto fail4;
      }
    }
    v18 = -v16 | 1;
fail4:
    if ( v18 == 0 )
    {
fail2:
      /* ... */
fail3:
      /* ... */
      goto fail7;
    }
    /* ... */
    if ( v3 != 100 )
      break;
LABEL_7:
    if ( (unsigned int)(v3 - 2) <= 52 )
    {
      strcpy(&v81, &input);
      sub_404010(&sub1, (int)v81);
      strcpy(&v81, &input);
      sub_404100(&sub4, (int)v81);
      v3 = 50;
      v8 = wcscmp(sub4, L"wiergrrrrrrfwefi");
      if ( v8 ) // ******** if not equal ****** 
      {
        /* ... */
      }
      LOBYTE(v91) = 3;
      v5 = (int)(sub4 - 8);
      goto fail3;
    }
  }
  // 这里看起来有点靠谱了
  if ( *(_DWORD *)(input - 12) != 40 || *(_WORD *)(input + 78) != 'x' ) // 输入字符串长度不等于40 or 输入的最后一个字符not 'x'
  {
fail1:
    flag = 0; goto LABEL_92;
  }
  strcpy(&v81, &input);
  sub_404010(&sub1, (int)v81);  // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 3 for i in range(9)
  strcpy(&v81, &input);
  sub_404100(&sub2, (int)v81);  // string = "dvfrhtgbPr"
                                // string[i] = v81[i+10] for i in range(9)
  strcpy(&v81, &input);
  sub_404200(&sub3, (int)v81);  // string = "rfdeswe32f"
                                // string[i] = v81[i+20] + 5 for i in range(9)
  strcpy(&v81, &input);
  sub_404310(&sub4, (int)v81);  // string = "bghtwsqsgr"
                                // string[i] = v81[i+30] + 3 for i in range(9)
  strcpy(&v81, &input);
  sub_404420(&v84, (int)v81);   // string = "bghtwsqbghtwsqsgrsgr"
                                // string[i] = v81[i] + 3 for i in range(19)
  strcpy(&v81, &input);
  sub_404510(&v86, (int)v81);   // string = "bghtwbghtwsqsgrsqsgr"
                                // string[i] = v81[i+20] + 3 for i in range(19)
  strcpy(&v81, &input);
  sub_404620(&v85, (int)v81);   // string = "bghtwsbghtwsqsgrqsgr"
                                // string[i] = v81[10+i] + 2 for i in range(19)
  strcpy(&v81, (int *)&sub1);
  v33 = sub_403420(v82, &v83, (int)v81); // v81[i] = v81[i] + 3 if i&1 else v81[i] + 2
  sub_404810(&sub1, v33); // 最终结果存在sub1中
  /* ... */
  v36 = sub1;
  v37 = L"poskjyrvyr";
  while ( 1 ) // 这是一个字符串比较
  {
    v38 = *v36 < *v37;
    if ( *v36 != *v37 )
      break;
    if ( !*v36 )
      goto LABEL_49;
    v39 = v36[1];
    v38 = v39 < v37[1];
    if ( v39 != v37[1] )
      break;
    v36 += 2;
    v37 += 2;
    if ( !v39 )
    {
LABEL_49:
      v40 = 0;
      goto LABEL_51;
    }
  }
  v40 = -v38 | 1;
  if ( v40 )
    goto fail6;
LABEL_51:
  strcpy(&v81, (int *)&sub2);
  v41 = sub_4035D0(v32, &v83, (int)v81); // v81[i] = v81[i] + 5 if i%5 else v81[i] + 9
  sub_404810(&sub2, v41); // 最终结果存在sub2中
  /* ... */
  if ( strcmp(&sub2, L"j676kn|5nr") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &sub3);
  v45 = sub_403790(v32, &v83, (int)v81); // v81[i] = v81[i] + 1 if i%4 else v81[i] + 3 
  sub_404810(&sub3, v45); // 结果存在sub3中
  /* ... */
  if ( strcmp((const unsigned __int16 **)&sub3, L"uku|nokxqf") ) //字符串比较
    goto fail6;
  strcpy(&v81, (int *)&sub4);
  v49 = sub_403940(v32, &v83, (int)v81); // v81[i] = v81[i] + 1 if i%3 else v91[i] + 2
  sub_404810(&sub4, v49); // 结果存在sub4中
  /* ... */
  if ( strcmp(&sub4, L"dzihggh{er") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v84);
  v53 = sub_403AF0(v32, &v83, (int)v81); // v81[i] = v81[i] + 6 if i&4 else v81[i] + 34
  sub_404810(&v84, v53); // 结果存在v84中
  if ( strcmp((const unsigned __int16 **)&v84, (const unsigned __int16 *)"\x90") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v86);
  v55 = sub_403CA0(v32, &v83, (int)v81); // v81[i] = v81[i] + 4 if i%5 else v81[i] + 18
  sub_404810(&v86, v55); // 结果存在v86中
  if ( strcmp((const unsigned __int16 **)&v86, (const unsigned __int16 *)"‚") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v85);
  v57 = sub_403E60(v32, &v83, (int)v81); // v81[i] = v81[i] if i%4 else  v81[i] + 1
  sub_404810(&v85, v57); // 结果存在v85中
  if ( strcmp((const unsigned __int16 **)&v85, L"d343igy2llogrxhkhtkr") ) // 字符串比较
    goto fail6;
  /* ... */
  if ( *(_WORD *)(v86 + 38) == 114 )
    flag = 1;
  else
fail6:
    flag = 0;
  /* ... */
LABEL_92:
  /* ... */
  return flag;
}
```
仔细查看函数可以发现，前面对字符串比较的处理是`相等则fail`，因此这段可以直接跳过，直接从`if ( *(_DWORD *)(input - 12) != 40 || *(_WORD *)(input + 78) != 'x' )`开始读。

字符串比较共有7处，分别为：
`sub_403420(sub_404010(input[0:10]))` vs `"poskjyrvyr"`
`sub_4035D0(sub_404100(input[10:20]))` vs `"j676kn|5nr"`
`sub_403790(sub_404200(input[20:30]))` vs `"uku|nokxqf"`
`sub_403940(sub_404310(input[30:40]))` vs `"dzihggh{er"`
`sub_403AF0(sub_404420(input[0:20]))` vs `"\x90\x72\x77\x6E\x8A\x7C\x76\x79\x99\x6D\x6A\x3A\x57\x3A\x6F\x6E\x9C\x39\x72\x72"`
`sub_403CA0(sub_404510(input[20:40]))` vs `"\x82\x6C\x76\x7D\x6D\x7E\x6C\x79\x70\x6C\x45\x7D\x6C\x6A\x6A\x78\x6A\x7E\x68\x72"`
`sub_403E60(sub_404620(inpupt[10:30]))` vs `"d343igy2llogrxhkhtkr"`

分别对以上7个过程逆向，可以得到7个字符串`s1-s7`。由于对输入字符串的第一步处理并未利用每段输入的最后一个字符，所以逆向得到的7个字符串的最后一位都是不确定正确的。
容易分析得到，将`s5`和`s6`组合可以得到`key'`，其中第20和40个字符是不确定正确的；根据`s7`可以得到第20个字符；根据程序已知最后一个字符为`'x'`。

脚本：
```python
flag = '' 
string = "\x90\x72\x77\x6E\x8A\x7C\x76\x79\x99\x6D\x6A\x3A\x57\x3A\x6F\x6E\x9C\x39\x72\x72"
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c-6 if i%4 else c-34
    flag += chr(c - 3)
flag += string[19:]

string = "\x82\x6C\x76\x7D\x6D\x7E\x6C\x79\x70\x6C\x45\x7D\x6C\x6A\x6A\x78\x6A\x7E\x68\x72"
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c-4 if i%5 else c-18
    flag += chr(c - 3)
flag += string[19:]

'''
flag_patch = '' # processing bytes[10:29]
string = "d343igy2llogrxhkhtkr"
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c if i%4 else c-1
    flag_patch += chr(c - 2)
flag_patch += string[19:]

flag = flag[:19] + flag_patch[9] + flag[20:39] + 'x'
'''

string = "d343igy2llogrxhkhtkr"
flag_patch = chr(ord(string[9]) - 2)
flag = flag[:19] + flag_patch + flag[20:39] + 'x'
print("WhiteHat{%s}" % flag)
```

