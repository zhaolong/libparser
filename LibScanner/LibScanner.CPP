//作用：扫描函数库(.flb)文件，检测函数是否属于此函数库
//函数库文件格式：签名-函数头表-函数名称段-函数数据段

//作者：leeeryan	leeeryan@gmail.com

#include "LibScanner.h"

CLibScanner:: CLibScanner():
m_pImage(NULL),m_pFuncHeader(NULL)
{

}

CLibScanner::~CLibScanner()
{	
	if(m_pImage)free(m_pImage);
}


BOOL  CLibScanner::ScanLib(LPCSTR szLib)
{
    //加载flb文件
	FILE* pFile;
	fopen_s(&pFile,szLib,"rb");
	if (!pFile)
	{
		CHAR ErrorStr[MAX_PATH];
		sprintf_s(ErrorStr,MAX_PATH,"Can't Open %s",szLib);
		MessageBox(NULL,ErrorStr,"Error",MB_ICONWARNING);
		return FALSE;
	}
	int len=_filelength(_fileno(pFile));
	m_pImage=(PBYTE)malloc(len);
	fread_s(m_pImage,len,len,1,pFile);
	fclose(pFile);
	//检测签名
	if (memcmp(m_pImage,IMAGE_FLB_START,IMAGE_FLB_START_SIZE)!=0)
	{
		return FALSE;
	}
	//定位函数头表
	m_pFuncHeader=(PFuncHeader)(m_pImage+IMAGE_FLB_START_SIZE);
	
	fclose(pFile);
    return TRUE;
}


PCSTR CLibScanner::CheckIfLibFunc(PCBYTE pFuncDat)
{
	PFuncHeader pFuncHeader=m_pFuncHeader;
	PCSTR pNam=NULL;
	//遍历函数库
	do 
	{
		if(CheckFunc(pFuncHeader,pFuncDat))
		{	
			pNam=(PCSTR)(m_pImage+pFuncHeader->NameOff);
			return pNam;
		}
		pFuncHeader++;
	} while (pFuncHeader->DataSize);//函数头表以一个完全为空的函数头成员结尾

    return NULL;
}
BOOL CLibScanner::CheckFunc(PFuncHeader pFuncHeader,PCBYTE pFuncDat)
{
	PBYTE pImpFuncDat=m_pImage+pFuncHeader->DataOff;
	//进行逐字节比对
	for (DWORD i=0;i<pFuncHeader->DataSize;i++)
	{
		//跳过重定位信息
		//只要是连续四个字节为0，就当作重定位信息处理
		//注意while:有可能两个重定位信息相邻，比如两个操作数的情况
		while(*(PDWORD)(pImpFuncDat+i)==0)
		{	
			i+=4;
		}
		if (pImpFuncDat[i]!=pFuncDat[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}
/*=========================================CLibScanner END=============================================*/

//用以判断是否是标准库函数
//无法确定是Release还是Debug版本，所以两个版本都要定义
CLibScanner LibScannerRL,LibScannerDB;

BOOL InitLibScanner(BYTE MajorLinkerVersion)
{
	char* pReleaseLibName;
	char* pDebugLibName;
	switch(MajorLinkerVersion)
	{
	case 6:
		pReleaseLibName = "..\\Libs\\VC6Lib\\libc.flb";
		pDebugLibName = "..\\Libs\\VC6Lib\\libcd.flb";
		break;
	case 7:
		pReleaseLibName = "..\\Libs\\VC2003Lib\\libc.flb";
		pDebugLibName = "..\\Libs\\VC2003Lib\\libcd.flb";
		break;
	case 8:
		pReleaseLibName = "..\\Libs\\VC2005Lib\\libcmt.flb"; //VC2005不再使用单线程的libc.lib，默认使用多线程的libcmt.lib。因此VC2005没有libc.lib这个文件
		pDebugLibName = "..\\Libs\\VC2005Lib\\libcmtd.flb";
		break;
	case 9: 
		pReleaseLibName = "..\\Libs\\VC2008Lib\\libcmt.flb"; //VC2008不再使用单线程的libc.lib，默认使用多线程的libcmt.lib。因此VC2008没有libc.lib这个文件
		pDebugLibName = "..\\Libs\\VC2008Lib\\libcmtd.flb";
		break;
	}

	if(!LibScannerDB.ScanLib(pDebugLibName))
	{
		MessageBox(NULL,"ScanLib Failed!","Error",MB_ICONWARNING);
		return FALSE;
	}
	if(!LibScannerRL.ScanLib(pReleaseLibName))
	{
		MessageBox(NULL,"ScanLib Failed!","Error",MB_ICONWARNING);
		return FALSE;
	}
	return TRUE;
}
//检测是否是标准库函数,如果是返回标准库函数名
PCHAR CheckIfLibFunc(PBYTE pFuncData)
{
	PCHAR pFuncName;
	pFuncName = (PCHAR)LibScannerDB.CheckIfLibFunc(pFuncData);
	if(!pFuncName)
	{
		pFuncName = (PCHAR)LibScannerRL.CheckIfLibFunc(pFuncData);
	}
	return pFuncName;
}