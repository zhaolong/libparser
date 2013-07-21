//作用：把静态库lib文件中的函数信息(函数名，函数数据)提取出来，再组织成函数库文件(.flb)
//函数库文件格式：签名-函数头表-函数名称段-函数数据段


//标准：《Microsoft 可移植可执行文件和通用目标文件格式文件规范》，简称《PE COFF文件格式》

//注意：这里指的的LIB是静态库，要和编写DLL所生成的lib区别开来
//《PE COFF文件格式》中称静态库格式为:档案（库）文件格式，在WinNT.h中称 Archive format.
//《PE COFF文件格式》中称另一种Lib为：导入库格式-是描述由一个映像导出供其它映像使用的符号的库
//下面统一按照《PE COFF文件格式》的叫法，称档案（库）文件格式

//作者：leeeryan	leeeryan@gmail.com


#include "LibParser.h"
#include "ObjParser.h"

CLibParser::CLibParser(void):
m_pLibImage(NULL),
m_pFlibFile(NULL),m_pNameFile(NULL),m_pDataFile(NULL)
{
}

CLibParser::~CLibParser(void)
{
	if(m_pLibImage)delete[] m_pLibImage;
}

BOOL CLibParser::Parse(PCSTR szLib)
{
	if(!LoadLib(szLib))
		return FALSE;
	//获得第一个Obj成员
	PBYTE pObjSect=GetFirstObjSection();
	if(!pObjSect)
	{
		MessageBox(NULL,"This Lib is error!","Error",MB_ICONWARNING);
		return FALSE;
	}
	//初始化输出文件
	if(!InitOutPutFile(szLib))
		return FALSE;
	//遍历所有目标文件(Obj)成员
	if(!ParseObjs(pObjSect))
		return FALSE;
	//链接nam,dat文件为flib文件
	LinkFile();

	return TRUE;
}
BOOL CLibParser::ParseObjs(PBYTE pObjSect)
{
	do 
	{
		PIMAGE_ARCHIVE_MEMBER_HEADER pAME=(PIMAGE_ARCHIVE_MEMBER_HEADER)pObjSect;
		pObjSect+=sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);//去掉头部，剩下的就是Obj(COFF格式)

		//判断是否是导入库格式，以防止错误的把导入库lib当做静态库lib，而程序直接挂掉
		if(bImportlibraryFormat(pObjSect))
		{
			MessageBox(NULL,"This is not a Archive Format File,it's a Import Format File!",
				"WARNING",MB_ICONWARNING);
			return FALSE;
		}

		//解析目标成员(OBJ)
		CObjParser objParser;
		objParser.Parse(pObjSect,m_pNameFile,m_pDataFile,&m_FuncTable);

		//注意：BYTE Size[10];要用atol((LPSTR)..)这种方法才能得到正确size
		pObjSect += atol((LPSTR)pAME->Size) ;

		//注意：两个成员之间有可能是由\n隔开,《PE COFF 文件格式》中并没有提到
		if(*pObjSect=='\n') 
			pObjSect++;

	} while (pObjSect<m_pLibImage+m_fsize);

	return TRUE;
}
//链接nam,dat文件为flib文件
//分别把nam文件(函数名称段)，dat文件(函数数据段)内容拷贝到两个buf里
//再按照:签名-函数头表-函数名称段-函数数据段 顺序写入flib文件中
void CLibParser::LinkFile()
{
	//计算出函数头表，名称段，数据段的大小
	DWORD sizeofFuncHeader=(m_FuncTable.size()+1)*sizeof(FlibFuncHeader);
	DWORD sizeofNamSection=_filelength(_fileno(m_pNameFile));
	DWORD sizeofDatSection=_filelength(_fileno(m_pDataFile));
	//计算出基础偏移，方便下面修正偏移
	DWORD baseNameOff=IMAGE_FLIB_START_SIZE+sizeofFuncHeader;
	DWORD baseDataOff=baseNameOff+sizeofNamSection;
	//把nam文件内容拷贝到buf里
	fclose(m_pNameFile);
	fopen_S(&m_pNameFile,m_NameFileName,"rb");
	PBYTE pNamSection=(PBYTE)malloc(sizeofNamSection);
	fread(pNamSection,sizeofNamSection,1,m_pNameFile);
	//把dat文件内容拷贝到buf里
	fclose(m_pDataFile);
	fopen_S(&m_pDataFile,m_DataFileName,"rb");
	PBYTE pDatSection=(PBYTE)malloc(sizeofDatSection);
	fread(pDatSection,sizeofDatSection,1,m_pDataFile);

	FlibFuncHeader funcHeader;
	//为flib文件写入签名
	fwrite(&IMAGE_FLIB_START,IMAGE_FLIB_START_SIZE,1,m_pFlibFile);
	fflush(m_pFlibFile);
	//写入函数头表
	FuncHeaderTable::const_iterator it=m_FuncTable.begin();
	for (;it!=m_FuncTable.end();++it)
	{
		memset(&funcHeader,0,sizeof(funcHeader));
		//修订偏移
		funcHeader.NameOff=(*it).NameOff+baseNameOff;
		funcHeader.DataOff=(*it).DataOff+baseDataOff;
		funcHeader.DataSize=(*it).DataSize;
		//写入函数头成员
		fwrite(&funcHeader,sizeof(funcHeader),1,m_pFlibFile);
		fflush(m_pFlibFile);
	}
	//以一个完全为空的函数头作为函数头表的结尾
	memset(&funcHeader,0,sizeof(funcHeader));
	fwrite(&funcHeader,sizeof(funcHeader),1,m_pFlibFile);
	fflush(m_pFlibFile);
	//写入函数名称段
	fwrite(pNamSection,sizeofNamSection,1,m_pFlibFile);
	fflush(m_pFlibFile);
	//写入函数数据段
	fwrite(pDatSection,sizeofDatSection,1,m_pFlibFile);
	fflush(m_pFlibFile);
	//释放之前分配的两个buf
	free(pNamSection);
	free(pDatSection);

	//关闭文件
	fclose(m_pFlibFile);
	fclose(m_pNameFile);
	fclose(m_pDataFile);
	//删除nam,dat文件
	remove(m_NameFileName);
	remove(m_DataFileName);
}
BOOL CLibParser::LoadLib(PCSTR szLib)
{
	FILE * pFile ;
	if(!fopen_S(&pFile,szLib,"rb"))
		return FALSE;
	m_fsize = _filelength(_fileno(pFile));

	m_pLibImage = new BYTE[m_fsize];
	if (m_pLibImage == NULL)
	{
		MessageBox(NULL,"Can't Allocate For Lib!","Error",MB_ICONWARNING);
		fclose(pFile);
		return FALSE;
	}
	fread(m_pLibImage,m_fsize,1,pFile);
	//检测签名,判断是否为lib文件
	if(memcmp(m_pLibImage,IMAGE_ARCHIVE_START,IMAGE_ARCHIVE_START_SIZE)!=0)
	{
		MessageBox(NULL,"This is not a Lib!","Error",MB_ICONWARNING);
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	return TRUE;
}
BOOL CLibParser::InitOutPutFile(PCSTR szLib)
{
	int strSize=strlen(szLib)+1;
	if (strSize>MAX_PATH)
	{
		MessageBox(NULL,"File name is too long !","Error",MB_ICONWARNING);
		return FALSE;
	}
	
	strcpy_s(m_FlibFileName,strSize,szLib);
	ModifySuffix(m_FlibFileName,".flb");
	if(!fopen_S(&m_pFlibFile,m_FlibFileName,"wb"))
		return FALSE;
	strcpy_s(m_NameFileName,strSize,szLib);
	ModifySuffix(m_NameFileName,".nam");
	if(!fopen_S(&m_pNameFile,m_NameFileName,"wb"))
		return FALSE;
	strcpy_s(m_DataFileName,strSize,szLib);
	ModifySuffix(m_DataFileName,".dat");
	if(!fopen_S(&m_pDataFile,m_DataFileName,"wb"))
		return FALSE;

	return TRUE;
}
PBYTE CLibParser::GetFirstObjSection()
{
	int iCtrl=0;
	//第一个链接器成员
	PBYTE pSect = m_pLibImage+IMAGE_ARCHIVE_START_SIZE;
	if(!pSect)return NULL;
	while(pSect)
	{
		//第二个链接器成员
		if(memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name,IMAGE_ARCHIVE_LINKER_MEMBER,16)==0)
		{
			//Nothing
		}
		//第三个长名称成员
		else if(memcmp(((PIMAGE_ARCHIVE_MEMBER_HEADER)pSect)->Name,IMAGE_ARCHIVE_LONGNAMES_MEMBER,16)==0)//LONG Name
		{
			//Nothing
			//尽管长名称成员的头部必须存在，但它本身却可以为空。
		}	
		else //First Obj Section
		{
			return pSect;
		}
		//注意BYTE Size[10];要用atol((LPSTR)..)这种方法才能得到正确size
		PIMAGE_ARCHIVE_MEMBER_HEADER pAME=(PIMAGE_ARCHIVE_MEMBER_HEADER)pSect;
		pSect += atol((LPSTR)pAME->Size) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
		//两个成员之间有可能是由\n隔开
		if(*pSect=='\n') pSect++;

		iCtrl++;//防止遇到错误的Lib文件，而导致死循环
		if (iCtrl>3)
		{
			break;
		}
	}
	return NULL;
}
//导入库格式与档案(库)格式非常相似，他们的不同点：
//1.导入库格式可能没有长成员
//2.导入库格式里有的目标成员是伪造的目标文件而不是真正的目标文件，即并不是COFF格式
//而是一种称之为“短格式的导入库格式”，具体参见《PE COFF文件格式》第8节
BOOL CLibParser::bImportlibraryFormat(PBYTE pSect)
{
	//通过判断其是否有短格式成员来判断其是否是导入库格式
	WORD Sig1=*(PWORD)(pSect);
	WORD Sig2=*(PWORD)(pSect+2);
	if (Sig1==IMAGE_FILE_MACHINE_UNKNOWN&&Sig2==0xffff)
	{
		return TRUE;
	} 
	else
	{
		return FALSE;
	}
}
BOOL CLibParser::fopen_S(FILE ** _File, PCSTR _Filename,PCSTR _Mode)
{
	fopen_s(_File,_Filename,_Mode);
	if(*_File==NULL)
	{
		CHAR szError[MAX_PATH];
		sprintf_s(szError,MAX_PATH,"Can't Open %s",_Filename);
		MessageBox(NULL,szError,"Error",MB_ICONWARNING);
		return FALSE;
	}
	return TRUE;
}
//修改后缀名，截断超过原始后缀长度部分
void CLibParser::ModifySuffix(PCHAR filename,PCHAR pSuffix)
{
	PCHAR pDest=strrchr(filename,'.');
	do 
	{
		*pDest++=*pSuffix++;
	} while (*pDest&&*pSuffix);
	*pDest=0;
}