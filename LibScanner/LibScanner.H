#ifndef	_CLIBSCANNER_H_
#define	_CLIBSCANNER_H_

#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <assert.h>
#include <io.h>

#define IMAGE_FLB_START_SIZE             8
#define IMAGE_FLB_START                  "!<flib>\n"

typedef const BYTE* PCBYTE;

typedef struct _FuncHeader//flb文件中的文件头结构
{
	DWORD NameOff;//函数名签名
	DWORD DataOff;//函数数据签名
	DWORD DataSize;//函数数据大小
}FuncHeader,*PFuncHeader;

class CLibScanner
{
 
public:
    CLibScanner();
    ~CLibScanner();
protected:
	PBYTE m_pImage;
	PFuncHeader m_pFuncHeader;
protected:
	BOOL CheckFunc(PFuncHeader pFuncHeader,PCBYTE phead);
public:
    PCSTR CheckIfLibFunc(PCBYTE phead);
    BOOL  ScanLib(LPCSTR szLib);
};


BOOL InitLibScanner(BYTE MajorLinkerVersion);
PCHAR CheckIfLibFunc(PBYTE pFuncData);


#endif	// _CLIBSCANNER_H_
