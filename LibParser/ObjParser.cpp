//作用：分析从lib文件中提取出的目标文件(obj)成员(COFF文件格式)
//从中提取出函数名，函数数据 分别写入nam dat文件
//并将函数名偏移，函数名大小，函数数据偏移，函数数据大小 插入 FuncHeaderTable

//作者：leeeryan	leeeryan@gmail.com


#include "ObjParser.h"

CObjParser::CObjParser(void):
m_pObjImage(NULL),m_pFileHeader(NULL),m_pSectionHeader(NULL),m_pRelocation(NULL),
m_pStrings(NULL),m_pNamFile(NULL),m_pDatFile(NULL),m_pFuncTable(NULL)
{
}

CObjParser::~CObjParser(void)
{
	//不必释放，因为这是之前m_pLibImage指向的一整块内存的一部分，会导致重复释放内存
	//if(m_pObjImage)delete m_pObjImage;
}
//《PE COFF 文件格式》 中提到：辅助符号表记录格式之一：函数定义；
//里面有函数大小，以及指向下个函数符号表的索引，是理想的工具，
//但实践证明，并不适用，函数符号表后面根本没有辅助符号表
BOOL CObjParser::Parse(PBYTE objImage,FILE* pNamFile,FILE* pDatFile,FuncHeaderTable* funcTable)
{
	m_pObjImage=objImage;
	m_pNamFile=pNamFile;
	m_pDatFile=pDatFile;
	m_pFuncTable=funcTable;
	
	m_pFileHeader=(PIMAGE_FILE_HEADER)objImage;
	m_pSectionHeader=(PIMAGE_SECTION_HEADER)(objImage+sizeof(IMAGE_FILE_HEADER));
	m_pSymbol=(PIMAGE_SYMBOL)(objImage+m_pFileHeader->PointerToSymbolTable);
	m_pStrings=(PCHAR)(m_pSymbol+m_pFileHeader->NumberOfSymbols);
	
	//只处理函数符号
	PIMAGE_SYMBOL pSymbol;
	//新建一个函数头
	FuncHeader funcHeader;
	//遍历符号表
	for (DWORD i=0;i<m_pFileHeader->NumberOfSymbols;i++)
	{
		pSymbol=m_pSymbol+i;
// 		存储类别为EXTERNAL（2）、Type 域的值表明它是一个函数（0x20）
//		以及SectionNumber 域的值大于0，它就标志着函数的开头
		if(ISFCN(pSymbol->Type)&&pSymbol->SectionNumber>0
			&&pSymbol->StorageClass==IMAGE_SYM_CLASS_EXTERNAL)
		{
			memset(&funcHeader,0,sizeof(funcHeader));

			GetNameofSymb(pSymbol,funcHeader);	
			GetDataofSymb(pSymbol,funcHeader);	

			m_pFuncTable->push_back(funcHeader);
		}
		//直接跳过辅助符号表
		i+=pSymbol->NumberOfAuxSymbols;
	}

	return TRUE;
}
void CObjParser::GetNameofSymb(PIMAGE_SYMBOL pSymbol,FuncHeader& funcHeader)
{
	PCHAR pName=NULL;
	CHAR shortNam[9]={0};
	//如果符号名称长度不超过8 个字节，那么符号表的ShortName 域
	//就是包含符号名本身的一个8 字节长的数组；
	if (pSymbol->N.Name.Short)
	{
		//pName= (PCHAR)pSymbol->N.ShortName;
		//注意：符号名可能正好占满8个字节，那就没有NULL结束符了，
		//所以不能简单的用上面的方法
		
		memcpy_s(shortNam,9,pSymbol->N.ShortName,8);

		pName=shortNam;
	} 
	// 否则的话，它给出了字符串表中的一个偏移地址
	else
	{
		pName= m_pStrings+pSymbol->N.Name.Long;
	}

	//记录偏移
	if (m_pFuncTable->size()==0)
	{
		funcHeader.NameOff=0;
	} 
	else
	{
		FuncHeader& funcHeadPrev=m_pFuncTable->at(m_pFuncTable->size()-1);
		funcHeader.NameOff=funcHeadPrev.NameOff+funcHeadPrev.NameSize;
	}
	//记录大小
	funcHeader.NameSize=strlen(pName)+1;
	//写入nam文件
	fwrite(pName,funcHeader.NameSize,1,m_pNamFile);
	fflush(m_pNamFile);
}
//获得函数数据
void CObjParser::GetDataofSymb(PIMAGE_SYMBOL pSymbol,FuncHeader& funcHeader)
{
	PIMAGE_SECTION_HEADER pISH = m_pSectionHeader+(pSymbol->SectionNumber-1);//SectionNumber从1 开始的索引
	if(!pISH)
	{
		MessageBox(NULL,"Get SectionHeader Error!","Error",MB_ICONWARNING);
		return;
	}
	//记录偏移
	if (m_pFuncTable->size()==0)
	{
		funcHeader.DataOff=0;
	} 
	else
	{
		FuncHeader& funcHeadPrev=m_pFuncTable->at(m_pFuncTable->size()-1);
		funcHeader.DataOff=funcHeadPrev.DataOff+funcHeadPrev.DataSize;
	}	
	//记录大小
	//这种记算函数大小的方法并准确，这样做是默认这个pSymbol所在节从pSymbol->Value偏移处开始到
	//节结束都是pSymbol所对应的函数数据，但有可能此节还包括其他函数数据
	//不过大部分我们常用的函数都是第一种情况，而确定函数大小又比较复杂，故占用这套方法
	//拿节大小SizeOfRawData-函数在此节的偏移Value
	funcHeader.DataSize=pISH->SizeOfRawData-pSymbol->Value;
	//标志重定位 位置
	MarkRelocatePos(pISH);
	//获取函数数据
	PBYTE funData=m_pObjImage+pISH->PointerToRawData+pSymbol->Value;
	//写入dat文件
	fwrite(funData,funcHeader.DataSize,1,m_pDatFile);
	fflush(m_pDatFile);
}
//标志重定位信息
void CObjParser::MarkRelocatePos(PIMAGE_SECTION_HEADER pISH)
{
	//用四个字节0标志重定位信息位置
	DWORD pReloMark=0;
	DWORD modifyOff=0;
	//获得重定位表
	PIMAGE_RELOCATION pIR = (PIMAGE_RELOCATION)(m_pObjImage + pISH->PointerToRelocations);
	//重定位表大小
	DWORD RefCount = pISH->NumberOfRelocations;
	for(DWORD i =0;i<RefCount;i++)
	{
		//待重定位偏移
		modifyOff=pISH->PointerToRawData+pIR[i].VirtualAddress;
		//修订
		memcpy_s(m_pObjImage+modifyOff,4,&pReloMark,4);		
	}
}	