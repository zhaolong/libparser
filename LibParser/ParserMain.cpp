// LibParser.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include "LibParser.h"


int main(int argc, CHAR* argv[])
{
	PCSTR szLib[]=
	{
		"..\\Libs\\VC6Lib\\libc.lib",
		"..\\Libs\\VC6Lib\\libcd.lib",
		"..\\Libs\\VC2003Lib\\libc.lib",
		"..\\Libs\\VC2003Lib\\libcd.lib",
		"..\\Libs\\VC2005Lib\\libcmt.lib",
		"..\\Libs\\VC2005Lib\\libcmtd.lib",
		"..\\Libs\\VC2008Lib\\libcmt.lib",
		"..\\Libs\\VC2008Lib\\libcmtd.lib"
	};
	const unsigned int num = sizeof(szLib)/sizeof(PCSTR);
	for (unsigned int i=0;i<num;i++)
	{
		CLibParser g_Parser;
		if(g_Parser.Parse(szLib[i]))
			printf("Parse Lib %s Succeed!\n",szLib[i]);
		else 
			printf("Parse Lib %s Failed!\n",szLib[i]);
	}
	return 0;
}

