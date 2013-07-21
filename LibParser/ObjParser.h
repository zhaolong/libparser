#pragma once
#include "LibParser.h"

class CObjParser
{
public:
	CObjParser(void);
	~CObjParser(void);
protected:
	PBYTE m_pObjImage;

	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_SECTION_HEADER m_pSectionHeader;
	PIMAGE_RELOCATION m_pRelocation;
	PIMAGE_SYMBOL m_pSymbol;
	PCHAR m_pStrings;//×Ö·û´®±í

	FILE* m_pNamFile;
	FILE* m_pDatFile;
	FuncHeaderTable* m_pFuncTable;
protected:
	void GetNameofSymb(PIMAGE_SYMBOL pSymbol,FuncHeader& funcHead);
	void GetDataofSymb(PIMAGE_SYMBOL pSymbol,FuncHeader& funcHead);

	void MarkRelocatePos(PIMAGE_SECTION_HEADER pISH);
public:
	BOOL Parse(PBYTE objImage,FILE* pNamFile,FILE* pDatFile,FuncHeaderTable* funcTable);
	
};
