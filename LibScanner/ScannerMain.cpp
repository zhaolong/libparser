// LibScanner.cpp : 定义控制台应用程序的入口点。
//作用：LibParser的测试程序，主要测试LibParser生成的flb文件是否准确
//方法:
//1.PEInfo解析pe文件，获得代码段，
//2.PVDasm反汇编引擎，反汇编代码段，监控其call指令(0xe8)，从而获得各个函数
//3.LibScanner加载flb函数库文件，用其中的函数数据与上面拿到的函数数据进行比较，从而判断是否是库函数

//作者：leeeryan	leeeryan@gmail.com

#include <stdio.h>
#include <tchar.h>
#include <io.h>
#include "PEInfo.h"
#include "LibScanner.h"
#include "PVdasm\\Disasm.h"

void ModifySuffix(PCHAR filename,PCHAR pSuffix)
{
	PCHAR pDest=strrchr(filename,'.');
	do 
	{
		*pDest++=*pSuffix++;
	} while (*pDest&&*pSuffix);
	*pDest=0;
}
FILE* pLogFile=NULL;
int _tmain(int argc, _TCHAR* argv[])
{
	FILE* pFile=NULL;
	PBYTE PEImage=NULL;
	PBYTE pCodeData=NULL;
	DWORD baseAddress=0;
	unsigned int CodeDatSize=0;
	BYTE MajorLinkerVersion=0;
	PCHAR PEFileNam="..\\test.exe";
	CHAR  LogFileNam[MAX_PATH];

#pragma region 加载PE文件 
	fopen_s(&pFile,PEFileNam,"rb");
	if(!pFile)
	{
		printf("Error:Can't open %s",PEFileNam);
		return 0;
	}
	const unsigned int fileLen=_filelength(_fileno(pFile));
	PEImage=new BYTE[fileLen];
	fread_s(PEImage,fileLen,fileLen,1,pFile);
	fclose(pFile);
#pragma endregion 
	
#pragma region 解析PE文件
	CPEInfo PEInfo;
	if(!PEInfo.Parse(PEImage))
		return 0;
	pCodeData=PEInfo.GetCodeData();
	CodeDatSize=PEInfo.GetCodeDataSize();
	MajorLinkerVersion=PEInfo.GetMajorLinkerVersion();
	baseAddress=PEInfo.GetBaseAddress();
#pragma endregion 
	//初始化LibScanner，其中加载对于的flb文件
	if(!InitLibScanner(MajorLinkerVersion))
		return 0;
	
#pragma region 调用反汇编引擎
	strcpy_s(LogFileNam,MAX_PATH,PEFileNam);
	ModifySuffix(LogFileNam,".log");
	fopen_s(&pLogFile,LogFileNam,"wb");
	if(!pFile)
	{
		printf("Error:Can't open %s\n",PEFileNam);
		return 0;
	}
	PVDasm(pCodeData,CodeDatSize,baseAddress,pLogFile);
	fclose(pLogFile);
#pragma endregion 
	
	printf("PEFile %s Analysis Succeed!\n",PEFileNam);
	delete[] PEImage;
	return 0;
}


extern void ShowDecoded(DISASSEMBLY* pDisasm,FILE* pfile);
//call(0xe8)指令会调用下面的函数
void CallHandle(PBYTE pCallData,DISASSEMBLY* pDisasm)
{
	PCHAR pLibFuncNam=NULL;
	while(*pCallData==0xe9)//处理JMP
	{
		int jumpOffset=*(int*)(pCallData+1);
		pCallData=pCallData+jumpOffset+5;
	}
	//判断此函数是否是库函数
	pLibFuncNam=CheckIfLibFunc(pCallData);
	if(pLibFuncNam)
	{
		ShowDecoded(pDisasm,pLogFile);
		fprintf_s(pLogFile,"Call LibFunc:%s\n",pLibFuncNam);
	}
}