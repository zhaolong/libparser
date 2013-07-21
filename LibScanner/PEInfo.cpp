//作用：解析PE文件，获得代码段
//作者：leeeryan	leeeryan@gmail.com
#include "PEInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


CPEInfo::CPEInfo(void):
m_pImageBase(NULL),m_pDosHeader(NULL),
m_pNTHeaders(NULL),m_pFileHeader(NULL),m_pOptionalHeader(NULL),
m_pSectionHeader(NULL),m_pCodeData(NULL)
{
}
CPEInfo::~CPEInfo(void)
{
}
BOOL CPEInfo::Parse(PBYTE pImageBase)
{
	m_pImageBase=pImageBase;

	if (!ReadDosHeader())
	{
		return FALSE;
	}
	if (!ReadNTHeaders())
	{
		return FALSE;
	}
	if (!ReadSectionTable())
	{
		return FALSE;
	}
	if (!ReadCodeData())
	{
		return FALSE;
	}
	return TRUE;
}

//***********************************************************
//Read Dos Header
//***********************************************************
BOOL CPEInfo::ReadDosHeader()
{
	m_pDosHeader=(PIMAGE_DOS_HEADER)m_pImageBase;

	if(m_pDosHeader->e_magic!= IMAGE_DOS_SIGNATURE)
	{
		MessageBox(NULL,"DOS文件头有误!","Error",MB_ICONWARNING);
		return FALSE;
	}
	return TRUE;
}
//***********************************************************
//Read NT SignNature
//***********************************************************	
BOOL CPEInfo::ReadNTHeaders()
{ 

	m_pNTHeaders=(PIMAGE_NT_HEADERS)(m_pImageBase+m_pDosHeader->e_lfanew);

	if(m_pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBox(NULL,"无效的PE文件!","Error",MB_ICONWARNING);
		return FALSE;
	}
	
	//Read FileHeader
	m_pFileHeader=&m_pNTHeaders->FileHeader;
	//Read OptionalHeader
	m_pOptionalHeader=&m_pNTHeaders->OptionalHeader;

	return TRUE;
}
//***********************************************************
//Read Section Table
//***********************************************************	
BOOL CPEInfo::ReadSectionTable()
{	
	m_numberOfSections = m_pFileHeader->NumberOfSections;
	//第一个IMAGE_SECTION_HEADER的位置
	m_pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeaders);

	return TRUE;
}
//***********************************************************
//Read Code Data
//***********************************************************	
BOOL CPEInfo::ReadCodeData()
{
	/*
	采取查找人口点RVA是否在某一个节的虚拟地址范围内的方法来查找代码段，即
	Section．VirtualAddress<=RVA<=Section．VirtualAddress+Section．SizeOfRawDat
	*/
	DWORD EntryPointRVA=m_pOptionalHeader->AddressOfEntryPoint;
	m_EntryPointVA=m_pOptionalHeader->ImageBase+EntryPointRVA;

	for (int index=0;index<m_numberOfSections;index++)
	{
		if (m_pSectionHeader[index].VirtualAddress<=EntryPointRVA&&
			EntryPointRVA<=m_pSectionHeader[index].VirtualAddress+m_pSectionHeader[index].SizeOfRawData)
		{
			m_SHCodeIndex=index;
			//定位代码段
			DWORD offset=m_pSectionHeader[m_SHCodeIndex].PointerToRawData;
			m_pCodeData=m_pImageBase+offset;
			
			m_CodeSize=m_pSectionHeader[index].SizeOfRawData;
			m_BaseAddress=m_pOptionalHeader->ImageBase+m_pSectionHeader[index].VirtualAddress;
			break;
		}
	}
	if(!m_pCodeData)
	{
		MessageBox(NULL,"无法确定代码段!","Error",MB_ICONWARNING);	
		return FALSE;
	}

	return TRUE;
}