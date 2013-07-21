#pragma once
#include <Windows.h>

class CPEInfo
{
public:
	CPEInfo(void);
	~CPEInfo(void);
protected:
	PBYTE m_pImageBase;
protected:
	PIMAGE_DOS_HEADER m_pDosHeader;
	
	//PE Head
	PIMAGE_NT_HEADERS m_pNTHeaders;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER32 m_pOptionalHeader; 
	//区块表
	PIMAGE_SECTION_HEADER m_pSectionHeader;
protected:
	//入口点相对虚拟地址
	DWORD m_EntryPointVA;
	//Code Section Header Index
	int m_SHCodeIndex;
	//区块数目
	WORD m_numberOfSections;
	//代码段起始指针
	PBYTE m_pCodeData;
	//代码大小
	DWORD m_CodeSize;
	DWORD m_BaseAddress;
protected:
//***********************************************************
//Read Dos Header
//***********************************************************
    BOOL ReadDosHeader();
//***********************************************************
//Read NT Headers
//***********************************************************	
	BOOL ReadNTHeaders();
//***********************************************************
//Read Code Data
//***********************************************************	
	BOOL ReadCodeData();
//***********************************************************
//Read Section Table
//***********************************************************	
	BOOL ReadSectionTable();

public:
	BOOL Parse(PBYTE pImageBase);
	
	inline DWORD GetBaseAddress(){return m_BaseAddress;}
	inline DWORD GetCodeDataSize(){return m_CodeSize;}
	inline PBYTE GetCodeData(){return m_pCodeData;}
	inline BYTE  GetMajorLinkerVersion()const{return m_pOptionalHeader->MajorLinkerVersion;}
};