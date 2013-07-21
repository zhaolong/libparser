#pragma once
#include <stdio.h>
#include <windows.h>
#include <io.h>
#include <vector>
using std::vector;

//flib 文件格式
//签名
#define IMAGE_FLIB_START_SIZE             8
#define IMAGE_FLIB_START                  "!<flib>\n"
//FileHeader文件头，一张FuncHead表
//以一个完全为空的fileheader作为文件头的结尾
//NamSection名称段，里面存储了所有函数名，以null结尾的C风格字符串
//DatSection数据段，里面存储了所有函数数据

typedef struct _FuncHeader
{
	DWORD NameOff;//函数名称偏移
	DWORD NameSize;//主要是用来计算偏移
	DWORD DataOff;//函数数据偏移
	DWORD DataSize;//函数数据大小
}FuncHeader,*PFuncHeader;
typedef struct _FlibFuncHeader//flib文件中的函数头结构
{
	DWORD NameOff;
	//DWORD NameSize;//函数名称以NULL结尾，不需要size了
	DWORD DataOff;
	DWORD DataSize;
}FlibFuncHeader,*PFlibFuncHeader;
typedef vector<FuncHeader> FuncHeaderTable;

class CLibParser
{
public:
	CLibParser(void);
	~CLibParser(void);
protected:
	PBYTE m_pLibImage;
	long  m_fsize;
	FILE* m_pFlibFile;//最后生成的函数库文件
	FILE* m_pNameFile;//中间生成的函数名称文件
	FILE* m_pDataFile;//中间生成的函数数据文件
	CHAR  m_FlibFileName[MAX_PATH];
	CHAR  m_NameFileName[MAX_PATH];
	CHAR  m_DataFileName[MAX_PATH];
	FuncHeaderTable m_FuncTable;//函数头表
protected:
	BOOL LoadLib(PCSTR szLib);
	PBYTE GetFirstObjSection();
	BOOL InitOutPutFile(PCSTR szLib);
	BOOL ParseObjs(PBYTE pObjSect);
	void LinkFile();

	void ModifySuffix(PCHAR filename,PCHAR pSuffix);
	BOOL fopen_S(FILE ** _File, PCSTR _Filename,PCSTR _Mode);
	BOOL bImportlibraryFormat(PBYTE pSect);
public:
	BOOL Parse(PCSTR szLib);
};
