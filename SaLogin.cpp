// SaLogin.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "SaLogin.h"
#include "SaCrazy.h"
#include "MD5A.h"
#include "Autil.h"
#include "SASO.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
/************************************************************************************
*下面ParseKey和EncodeLoginFenBao两个函数对不同的服必须进行相应的修改，ParseKey用于计算动态
*key,EncodeLoginFenBao用于封装71号封包（即登入封包）
*************************************************************************************/


CWinApp theApp;
CMd5A md5;							//加密密码用

using namespace std;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// 初始化 MFC 并在失败时显示错误
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: 更改错误代码以符合您的需要
			_tprintf(_T("错误: MFC 初始化失败\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: 在此处为应用程序的行为编写代码。
		}
	}
	else
	{
		// TODO: 更改错误代码以符合您的需要
		_tprintf(_T("错误: GetModuleHandle 失败\n"));
		nRetCode = 1;
	}

	return nRetCode;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
//									不导出的内部函数
//获取当前程序的运行路径
CString GetAppPath()
{
	//取当前程序所在的路径
	TCHAR szFilePath[MAX_PATH],*p;
	GetModuleFileName(NULL,szFilePath,MAX_PATH);
	//查找字符串中某个字符最后一次出现的位置
	//返回值：指向最后一次在字符串中出现的该字符的指针，如果要查找的字符再串中没有出现，则返回NULL
	if(CString(szFilePath).GetLength()>3)
		(_tcsrchr(szFilePath,_T('\\')))[1]=0;	
	return szFilePath;
}
//获取计算机名和Mac地址
void GetHostNameAndMac(char *dst)
{
	char chMac[100]={0},chVal[100]={0};
	GetNicInfo(chMac,TRUE,'-',0);
	CString szMerge,szIP;
	szIP=GetIPAddress();
	szMerge.Format(_T("%s::%s"),(LPCTSTR)CharToCString(chMac),szIP);
	CStringToChar(dst,100,szMerge);	
}
//生成09sa的logchar
//type为config.ini中的type字段，用于区分不同的服
//cdkey为用户帐号
//prefix为logchar前缀
void MakeLogChar(char *type,char *cdkey,char *prefix,char *dst)
{
	char chHostMac[100]={0},buf[100]={0};
	int len;
	GetHostNameAndMac(chHostMac);	
	//sprintf_s(chHostMac, "%d", GetTickCount());
	strcpy_s(buf,100,md5.MDString(chHostMac));
	if(strcmp(prefix,"ddshiqi-")==0)
	{
		buf[31]=0;
		buf[30]=0;
	}
	sprintf_s(chHostMac,"%s%s",prefix,buf);
	if(strcmp(type,"shiqisa3.0")==0 || strcmp(type,"maowusa2.5")==0 || strcmp(type,"09sa8.5")==0 || strcmp(type,"09sa2.5")==0 || strcmp(type,"chaojisa3.0")==0)//豆丁不要加密
	{
		strcpy_s(dst,100,chHostMac);		
	}
	else
	{
		int keylen=strlen(cdkey);
		len=strlen(chHostMac);
		int j=0,i;
		for(i=0;i<len;i++)
		{
			dst[i]=chHostMac[i]+cdkey[j];
			j++;
			if(j>=keylen)
				j=0;
		}
		dst[i]=0;
	}	
}
//石器so
int decode_addr;//解密函数地址
int hex_addr;
int process_hex_to_rkey(char * hex, char * out)
{
	**(char***)hex_addr = (char*)hex;
	__asm {
		mov     ecx, dword ptr ss : [out];
		mov eax, decode_addr;
		call    eax;
	}

	return 0;
}
void nop() {}
//石器pk
#pragma pack(1)
typedef struct PK_CODECONF
{
	int _dump;
	char login_recv[8];
	char content[0x44];
	char content2[0x44];
	char fix_key[8];
	char _dump2[6];
	char fix_content[0x60];
	char final_key[8];
	char fix_key2[8];
	char _dump3[6];

}PK_CODECONF;
#pragma pack()

char P1[] = {
	0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x01
};

char S1[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

char P2[] = {
	0x0E, 0x04, 0x0D, 0x01, 0x01, 0x0F, 0x0B, 0x08, 0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07, 0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01, 0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08,
	0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B, 0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00, 0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D,
	0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A, 0x03, 0x0D, 0x04, 0x07, 0x0F, 0x02, 0x08, 0x0E, 0x0C, 0x00, 0x01, 0x0A, 0x06, 0x09, 0x0B, 0x05,
	0x00, 0x0E, 0x07, 0x0B, 0x0A, 0x04, 0x0D, 0x01, 0x05, 0x08, 0x0C, 0x06, 0x09, 0x03, 0x02, 0x0F, 0x0D, 0x08, 0x0A, 0x01, 0x03, 0x0F, 0x04, 0x02, 0x0B, 0x06, 0x07, 0x0C, 0x00, 0x05, 0x0E, 0x09,
	0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05, 0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08, 0x0D, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0A, 0x02, 0x08, 0x05, 0x0E, 0x0C, 0x0B, 0x0F, 0x01,
	0x0D, 0x06, 0x04, 0x09, 0x08, 0x0F, 0x03, 0x00, 0x0B, 0x01, 0x02, 0x0C, 0x05, 0x0A, 0x0E, 0x07, 0x01, 0x0A, 0x0D, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0F, 0x0E, 0x03, 0x0B, 0x05, 0x02, 0x0C,
	0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A, 0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F, 0x0D, 0x08, 0x0B, 0x05, 0x06, 0x0F, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0C, 0x01, 0x0A, 0x0E, 0x09,
	0x0A, 0x06, 0x09, 0x00, 0x0C, 0x0B, 0x07, 0x0D, 0x0F, 0x01, 0x03, 0x0E, 0x05, 0x02, 0x08, 0x04, 0x03, 0x0F, 0x00, 0x06, 0x0A, 0x01, 0x0D, 0x08, 0x09, 0x04, 0x05, 0x0B, 0x0C, 0x07, 0x02, 0x0E,
	0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06, 0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09, 0x0E, 0x0B, 0x02, 0x0C, 0x04, 0x07, 0x0D, 0x01, 0x05, 0x00, 0x0F, 0x0A, 0x03, 0x09, 0x08, 0x06,
	0x04, 0x02, 0x01, 0x0B, 0x0A, 0x0D, 0x07, 0x08, 0x0F, 0x09, 0x0C, 0x05, 0x06, 0x03, 0x00, 0x0E, 0x0B, 0x08, 0x0C, 0x07, 0x01, 0x0E, 0x02, 0x0D, 0x06, 0x0F, 0x00, 0x09, 0x0A, 0x04, 0x05, 0x03,
	0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B, 0x0A, 0x0F, 0x04, 0x02, 0x07, 0x0C, 0x09, 0x05, 0x06, 0x01, 0x0D, 0x0E, 0x00, 0x0B, 0x03, 0x08,
	0x09, 0x0E, 0x0F, 0x05, 0x02, 0x08, 0x0C, 0x03, 0x07, 0x00, 0x04, 0x0A, 0x01, 0x0D, 0x0B, 0x06, 0x04, 0x03, 0x02, 0x0C, 0x09, 0x05, 0x0F, 0x0A, 0x0B, 0x0E, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0D,
	0x0E, 0x04, 0x0D, 0x01, 0x01, 0x0F, 0x0B, 0x08, 0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07, 0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01, 0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08,
	0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B, 0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00, 0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D,
	0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D, 0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01, 0x0D, 0x00, 0x0B, 0x07, 0x04, 0x09, 0x01, 0x0A, 0x0E, 0x03, 0x05, 0x0C, 0x02, 0x0F, 0x08, 0x06,
	0x01, 0x04, 0x0B, 0x0D, 0x0C, 0x03, 0x07, 0x0E, 0x0A, 0x0F, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02, 0x06, 0x0B, 0x0D, 0x08, 0x01, 0x04, 0x0A, 0x07, 0x09, 0x05, 0x00, 0x0F, 0x0E, 0x02, 0x03, 0x0C
};

char P3[] = {
	0x10, 0x07, 0x14, 0x15, 0x1D, 0x0C, 0x1C, 0x11, 0x01, 0x0F, 0x17, 0x1A, 0x05, 0x12, 0x1F, 0x0A, 0x02, 0x08, 0x18, 0x0E, 0x20, 0x1B, 0x03, 0x09, 0x13, 0x0D, 0x1E, 0x06, 0x16, 0x0B, 0x04, 0x19
};

char P4[] = {
	0x28, 0x08, 0x30, 0x10, 0x38, 0x18, 0x40, 0x20, 0x27, 0x07, 0x2F, 0x0F, 0x37, 0x17, 0x3F, 0x1F, 0x26, 0x06, 0x2E, 0x0E, 0x36, 0x16, 0x3E, 0x1E, 0x25, 0x05, 0x2D, 0x0D, 0x35, 0x15, 0x3D, 0x1D,
	0x24, 0x04, 0x2C, 0x0C, 0x34, 0x14, 0x3C, 0x1C, 0x23, 0x03, 0x2B, 0x0B, 0x33, 0x13, 0x3B, 0x1B, 0x22, 0x02, 0x2A, 0x0A, 0x32, 0x12, 0x3A, 0x1A, 0x21, 0x01, 0x29, 0x09, 0x31, 0x11, 0x39, 0x19
};

char P5[] = {
	0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12, 0x0A, 0x02, 0x3C, 0x34, 0x2C, 0x24, 0x1C, 0x14, 0x0C, 0x04, 0x3E, 0x36, 0x2E, 0x26, 0x1E, 0x16, 0x0E, 0x06, 0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08
};

char P6[] = {
	0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3B, 0x33, 0x2B, 0x23, 0x1B, 0x13, 0x0B, 0x03, 0x3D, 0x35, 0x2D, 0x25, 0x1D, 0x15, 0x0D, 0x05, 0x3F, 0x37, 0x2F, 0x27, 0x1F, 0x17, 0x0F, 0x07
};


void init_struct(PK_CODECONF* conf)
{
	char data[] = {
		0x8C, 0x34, 0x3B, 0x0F, 0xA0, 0x3A, 0x45, 0x87, 0xAF, 0x13, 0x43, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0xB6, 0xB4, 0xB9, 0xB3, 0xE6, 0x8A, 0x29, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x0E, 0x7D, 0x3D, 0xE6, 0xD8, 0xD2, 0x4F, 0xE5, 0x85, 0xDB, 0xA9, 0xDA, 0x5B, 0x85, 0xBF, 0xE5, 0xD7, 0x19, 0xFD, 0x80, 0xAB, 0x5B, 0x36, 0x6E, 0xB3, 0x8A, 0xAE, 0xFC, 0xD9, 0xAC,
		0xB8, 0x3A, 0x96, 0x00, 0x7E, 0xFF, 0x34, 0x3E, 0x7C, 0xFF, 0xB8, 0xB1, 0xC6, 0x74, 0x74, 0xA3, 0x4F, 0x7B, 0x54, 0xE5, 0x77, 0xF7, 0x5F, 0x82, 0xE7, 0xC5, 0x33, 0x9C, 0x03, 0x7F, 0xEF, 0x83,
		0xA7, 0xD7, 0xFA, 0xC4, 0xBB, 0x92, 0x9B, 0x70, 0xA7, 0xF9, 0x3D, 0x12, 0xFA, 0xBB, 0xBC, 0x0F, 0xB6, 0x58, 0xDC, 0x6E, 0x77, 0xB2, 0x1E, 0x6B, 0x54, 0x3D, 0x69, 0x6F, 0x77, 0x6D, 0x55, 0x66,
		0x4F, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0xB6, 0xB4, 0xB9, 0xB3, 0xE6, 0x8A, 0x29
	};
	memcpy(conf, data, sizeof(data));
}
void __declspec(naked) FirstCode()
{
	__asm {
		push ebx;
		push esi;
		push edi;
		mov edi, ecx;
		xor eax, eax;
		jmp __0f257810;
		lea esp, [esp + 00000000h];
	__0f257810:
		movzx esi, byte ptr[eax + P5]; 0x20字节，P5
			dec esi;
		mov edx, esi;
		sar esi, 03h;
		not edx;
		and edx, 07h;
		mov cl, [edx + S1];
		test[esi + edi + 04h], cl;
		mov ecx, eax;
		mov esi, eax;
		not ecx;
		je __0f257847;
		sar esi, 03h;
		and ecx, 07h;
		add esi, edi;
		mov bl, [ecx + S1];
		or [esi + 0ch], bl;
		jmp __0f25785c;
	__0f257847:
		and ecx, 07h;
		sar esi, 03h;
		add esi, edi;
		mov bl, [ecx + S1];
		mov cl, bl;
		not cl;
		and[esi + 0ch], cl;
	__0f25785c:
		movzx edx, byte ptr[eax + P6]; 0x20字节，P6
			dec edx;
		mov ecx, edx;
		sar edx, 03h;
		not ecx;
		and ecx, 07h;
		mov cl, [ecx + S1];
		test[edx + edi + 04h], cl;
		je __0f25787f;
		or [esi + 50h], bl;
		jmp __0f257884;
	__0f25787f:
		not bl;
		and[esi + 50h], bl;
	__0f257884:
		inc eax;
		cmp eax, 20h;
		jnge __0f257810;
		pop edi;
		pop esi;
		pop ebx;
		ret;
	}
}

void __declspec(naked) CalcNextDword()
{
	__asm {
		push ebp;
		mov ebp, esp;
		sub esp, 24h;
		mov eax, 0xB665A78E; [0f41b490] : [B665A78E];
		xor eax, ebp;
		mov[ebp - 04h], eax;
		mov eax, [ebp + 08h];
		push ebx;
		movzx eax, al;
		mov ebx, ecx;
		push esi;
		push edi;
		mov[ebp - 18h], eax;
		lea edi, [ebx + eax * 4];
		mov[ebp - 24h], ebx;
		xor eax, eax;
		mov byte ptr[ebp - 0ch], 00;
		mov[ebp - 0bh], 00000000;
		xor edx, edx;
		mov byte ptr[ebp - 07h], 00;
		mov byte ptr[ebp - 14h], 00;
		mov[ebp - 13h], ax;
		lea esi, [eax + 30h];
		mov[ebp - 11h], al;
	__0f257ba5:
		movzx ecx, byte ptr[edx + P1]; 30字节，P1
			dec ecx;
		mov eax, ecx;
		sar ecx, 03h;
		not eax;
		and eax, 07h;
		mov al, [eax + S1]; 8字节，S1
			test[ecx + edi + 4ch], al;
		mov eax, edx;
		lea ecx, [ebp - 0ch];
		je __0f257bde;
		shr eax, 03h;
		add ecx, eax;
		mov eax, edx;
		not eax;
		and eax, 07h;
		mov al, [eax + S1];
		or [ecx], al;
		jmp __0f257bf4;
	__0f257bde:
		shr eax, 03h;
		add ecx, eax;
		mov eax, edx;
		not eax;
		and eax, 07h;
		mov al, [eax + S1];
		not al;
		and[ecx], al;
	__0f257bf4:
		inc edx;
		dec esi;
		jne __0f257ba5;
		mov edi, [ebp - 18h];
		lea edx, [esi + 06h];
		mov esi, [ebp + 0ch];
		xor ecx, ecx;
	__0f257c03:
		test esi, esi;
		je __0f257c15;
		mov eax, [ebp - 18h];
		mov edi, [ebp - 18h];
		lea eax, [eax + eax * 2h];
		lea eax, [eax + 4eh];
		jmp __0f257c1f;
	__0f257c15:
		mov eax, 0000002bh;
		sub eax, edi;
		lea eax, [eax + eax * 2h];
	__0f257c1f:
		lea eax, [ecx + eax * 2h];
		mov al, [eax + ebx];
		xor[ebp + ecx - 0ch], al;
		inc ecx;
		dec edx;
		jne __0f257c03;
		xor al, al;
		mov[ebp - 20h], 00000008h;
			xor bh, bh;
		mov[ebp - 0dh], al;
		xor bl, bl;
		xor dl, dl;
		xor edi, edi;
	__0f257c41:
		movzx esi, al;
		mov eax, esi;
		movzx edx, dl;
		not eax;
		mov ecx, esi;
		and eax, 07h;
		shr ecx, 03h;
		movzx eax, byte ptr[eax + S1];
		test[ebp + ecx - 0ch], al;
		mov eax, 00000002h;
		lea ecx, [esi + 05h];
		cmovne edx, eax;
		lea eax, [esi - 03h];
		not eax;
		sar ecx, 03h;
		and eax, 07h;
		mov[ebp - 1ch], edx;
		movzx eax, byte ptr[eax + S1];
		test[ebp + ecx - 0ch], al;
		je __0f257c89;
		inc dl;
		mov[ebp - 1ch], edx;
	__0f257c89:
		lea ecx, [esi + 01h];
		movzx edx, bl;
		mov eax, ecx;
		sar ecx, 03h;
		not eax;
		and eax, 07h;
		movzx eax, byte ptr[eax + S1];
		test[ebp + ecx - 0ch], al;
		mov eax, 00000008h;
			lea ecx, [esi + 02h];
		cmovne edx, eax;
		mov eax, ecx;
		not eax;
		sar ecx, 03h;
		and eax, 07h;
		movzx eax, byte ptr[eax + S1];
		test[ebp + ecx - 0ch], al;
		je __0f257cc9;
		add dl, 04h;
	__0f257cc9:
		lea ecx, [esi + 03h];
		mov eax, ecx;
		sar ecx, 03h;
		not eax;
		and eax, 07h;
		mov al, [eax + S1];
		test[ebp + ecx - 0ch], al;
		je __0f257ce5;
		add dl, 02h;
	__0f257ce5:
		lea eax, [esi - 04h];
		not eax;
		lea ecx, [esi + 04h];
		and eax, 07h;
		sar ecx, 03h;
		mov al, [eax + S1];
		test[ebp + ecx - 0ch], al;
		je __0f257d01;
		inc dl;
	__0f257d01:
		mov eax, [ebp - 1ch];
		movzx ecx, al;
		add ecx, edi;
		movzx eax, dl;
		add ecx, ecx;
		mov bl, [eax + ecx * 8 + P2]; 0x200字节，P2
			cmp bl, 08h;
			jb __0f257d37;
		movzx edx, bh;
		lea ecx, [ebp - 14h];
		mov eax, edx;
		not edx;
		shr eax, 03h;
		and edx, 07h;
		add ecx, eax;
		mov al, [edx + S1];
		or [ecx], al;
		add bl, 0xf8;
	__0f257d37:
		cmp bl, 04h;
		jb __0f257d5a;
		movzx edx, bh;
		lea ecx, [ebp - 14h];
		inc edx;
		mov eax, edx;
		not edx;
		sar eax, 03h;
		and edx, 07h;
		add ecx, eax;
		mov al, [edx + S1];
		or [ecx], al;
		add bl, 0xfc;
	__0f257d5a:
		cmp bl, 02h;
		jb __0f257d7f;
		movzx edx, bh;
		lea ecx, [ebp - 14h];
		add edx, 02h;
		mov eax, edx;
		not edx;
		sar eax, 03h;
		and edx, 07h;
		add ecx, eax;
		mov al, [edx + S1];
		or [ecx], al;
		add bl, 0xfe;
	__0f257d7f:
		cmp bl, 01h;
		jb __0f257da1;
		movzx edx, bh;
		lea ecx, [ebp - 14h];
		add edx, 03h;
		mov eax, edx;
		not edx;
		sar eax, 03h;
		and edx, 07h;
		add ecx, eax;
		mov al, [edx + S1];
		or [ecx], al;
	__0f257da1:
		mov al, [ebp - 0dh];
		xor dl, dl;
		add al, 06h;
		xor bl, bl;
		add bh, 04h;
		mov[ebp - 0dh], al;
		add edi, 04h;
		dec[ebp - 20h];
		jne __0f257c41;
		mov eax, [ebp - 18h];
		xor edx, edx;
		mov ebx, [ebp - 24h];
		lea edi, [eax * 4h + 00000050h];
		lea esi, [edx + 20h];
		mov edi, edi;
	__0f257dd0:
		movzx ecx, byte ptr[edx + P3]; 0x20字节，P3
			dec ecx;
		mov eax, ecx;
		sar ecx, 03h;
		not eax;
		and eax, 07h;
		mov al, [eax + S1];
		test[ebp + ecx - 14h], al;
		mov eax, edx;
		mov ecx, edx;
		not eax;
		je __0f257e07;
		shr ecx, 03h;
		and eax, 07h;
		add ecx, edi;
		mov al, [eax + S1];
		or [ecx + ebx], al;
		jmp __0f257e1a;
	__0f257e07:
		and eax, 07h;
		shr ecx, 03h;
		add ecx, edi;
		mov al, [eax + S1];
		not al;
		and[ecx + ebx], al;
	__0f257e1a:
		inc edx;
		dec esi;
		jne __0f257dd0;
		mov ecx, [ebp - 04h];
		pop edi;
		pop esi;
		xor ecx, ebp;
		pop ebx;
		//call 0f3748d6; checkesp;
		mov esp, ebp;
		pop ebp;
		ret 0008h;
	}
}

void __declspec(naked) SingleStepDword()
{
	__asm {
		push ebp;
		mov ebp, esp;
		mov edx, [ebp + 08h];
		push esi;
		movzx esi, dl;
		push edi;
		push[ebp + 0ch];
		mov edi, ecx;
		push edx;
		movzx eax, byte ptr[edi + esi * 4h + 4ch];
		mov[edi + esi * 4h + 0ch], al;
		movzx eax, byte ptr[edi + esi * 4h + 4dh];
		mov[edi + esi * 4h + 0dh], al;
		movzx eax, byte ptr[edi + esi * 4h + 4eh];
		mov[edi + esi * 4h + 0eh], al;
		movzx eax, byte ptr[edi + esi * 4h + 4fh];
		mov[edi + esi * 4h + 0fh], al;
		call CalcNextDword;
		movzx eax, byte ptr[edi + esi * 4h + 08h];
		xor[edi + esi * 4h + 50h], al;
		movzx eax, byte ptr[edi + esi * 4h + 09h];
		xor[edi + esi * 4h + 51h], al;
		movzx eax, byte ptr[edi + esi * 4h + 0ah];
		xor[edi + esi * 4h + 52h], al;
		movzx eax, byte ptr[edi + esi * 4h + 0bh];
		xor[edi + esi * 4h + 53h], al;
		pop edi;
		pop esi;
		pop ebp;
		ret 0008h;
	}
}

void __declspec(naked) MkKey()
{
	__asm {
		push esi;
		mov esi, ecx;
		xor eax, eax;
		jmp __0f257780;
		lea esp, [esp + 00000000];
		mov edi, edi;
	__0f257780:
		mov cl, [eax + P4]; 0x40字节，P4
			movzx edx, cl;
		cmp cl, 20h;
		ja __0f2577a8;
		dec edx;
		mov ecx, edx;
		sar edx, 03h;
		not ecx;
		and ecx, 07h;
		mov cl, [ecx + S1];
		test[edx + esi + 00000090h], cl;
		jmp __0f2577c0;
	__0f2577a8:
		lea ecx, [edx - 01h];
		add edx, -0x21;
		not ecx;
		sar edx, 03h;
		and ecx, 07h;
		mov cl, [ecx + S1];
		test[edx + esi + 4ch], cl;
	__0f2577c0:
		mov ecx, eax;
		mov edx, eax;
		not ecx;
		je __0f2577dd;
		and ecx, 07h;
		shr edx, 03h;
		mov cl, [ecx + S1];
		or [edx + esi + 00000102h], cl;
		jmp __0f2577f2;
	__0f2577dd:
		and ecx, 07h;
		shr edx, 03h;
		mov cl, [ecx + S1];
		not cl;
		and[edx + esi + 00000102h], cl;
	__0f2577f2:
		inc eax;
		cmp eax, 40h;
		jb __0f257780;
		pop esi;
		ret;
	}
}

void __declspec(naked) Main_Asm()
{
	__asm {
		push ebp;
		mov ebp, esp;
		push ecx;
		push ebx;
		push esi;
		mov esi, ecx;
		//call 0f257b20; 清空类
		//mov ecx, esi;
		//call 0f257530; 填入固定段
		mov ecx, esi;
		call FirstCode; FirstCode;
		mov bl, 01h;
		mov[ebp - 04h], bl;
	__0f257aa0:
		push 00;
		push[ebp - 04h];
		mov ecx, esi;
		call SingleStepDword; SingleStepDword
			inc bl;
		mov[ebp - 04h], bl;
		cmp bl, 10h;
		jna __0f257aa0;
		mov ecx, esi;
		call MkKey; MkKey
			pop esi;
		pop ebx;
		mov esp, ebp;
		pop ebp;
		ret;
	}

}

int Change(char s[], char bits[]) {
	int i, n = 0;
	for (i = 0; s[i]; i += 2) {
		if (s[i] >= 'A' && s[i] <= 'F')
			bits[n] = s[i] - 'A' + 10;
		else bits[n] = s[i] - '0';
		if (s[i + 1] >= 'A' && s[i + 1] <= 'F')
			bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
		else bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
		++n;
	}
	return n;
}
//动态key解密
//type为config.ini中的type字段，用于区分不同的服
//ciphertext为要解密的密文
//plaintext为解密后的明文
void CalculateKey(char *type,char *ciphertext,char *plaintext)
{
	int i,len;
	char *p;
	p=ciphertext+1;
	len=strlen(ciphertext)-1;
	if(strcmp(type,"shiqitv2.5")==0 || strcmp(type,"shengsi2.5")==0)
	{
		char key[7][10]={{'4','5','6','7','8','9','A','B','C','D'},
		{'H','L','P','T','X','b','f','j','n','r'},
		{'L','b','r','5','L','b','r','5','L','b'},
		{'b','b','b','b','c','c','c','c','d','d'},
		{'s','t','u','v','w','x','y','z','{','}'},
		{'H','L','P','T','X','b','f','j','n','r'},
		{'H', 'X', 'n', '1', 'H', 'X', 'n', '1', 'H', 'X'}};
		int j;
		for (i = 0; i < len; i++)
		{
			if (i > 2)
			{
				j = i - 1;
			}
			else
			{
				j = i;
			}
			plaintext[i] = key[i][p[j] % 10];
		}
	}
	else if (strcmp(type, "shiqiso") == 0)
	{
		//AllocConsole();
		//freopen("CON", "w", stdout);
		/*extern int decode_addr;
		extern int hex_addr;
		HMODULE hmod = LoadLibraryA("sqsq.dll");
		ASSERT(hmod);
		decode_addr = (int)hmod + 0x284C0;
		hex_addr = (int)hmod + 0x2896B;

		extern int process_hex_to_rkey(char * hex, char * out);
		char out[32] = { 0 };
		process_hex_to_rkey(ciphertext, out);
		strcpy(plaintext, out);
		FreeLibrary(hmod);*/
		//std::cout << ciphertext << std::endl;
		//std::cout << out << std::endl;
		//std::cout << plaintext << std::endl;

		CString strtmp(p);
		//AfxMessageBox(strtmp);
		//CString str = strtmp.Right(strtmp.GetLength() - 1);
		SASO *so = new SASO(strtmp);
		char *SOKey = so->RunningKey();
		CString strKey(SOKey);
		//AfxMessageBox(strKey);
		strcpy(plaintext, SOKey);
	}
	else if (ciphertext[0] == 'Z')
	{
		char key[10] = { 3,7,8,2,9,5,4,3,7,8 };
		for (i = 0; i < len; i++)
		{
			plaintext[i] = (p[i] - key[i]) % 64;
		}
	}
	else if (ciphertext[0] == 'X')
	{
		for (i = 0; i < len; i++)
		{
			if (strcmp(type, "dongdong2.5") == 0)
			{
				plaintext[i] = (p[i] + 13 - 65) % 26 + 'A';
			}
			else
			{
				plaintext[i] = p[i] % 10 + 48;
			}
		}
	}
	else if (ciphertext[0] == 'L')
	{
		char key[10] = { 0x46,0x42,0x45,0x47,0x41,0x48,0x43,0x46,0x42,0x45 };
		for (i = 0; i < len; i++)
		{
			plaintext[i] = p[i] - key[i];
		}
	}
	plaintext[len] = 0;
}
//计算running_key，仅对兄弟石器有效。
void Calc3CDefaultKey(char *key, int keylen)
{
	char cipher[60][30] = {
		"1aAnN4twtu8d3gBN","rplKHXExiRfI930o","Xsdhd}q834pklPBW","QzclaymdnNsDgJCN","hNDatXPdFPWqZopA",
		"XGGaFmI853qRQykJ","zG8k7orkjLaDhxWX","I2UXAtDfhj1qiDKe","iHek0yLEU0YivBjo","rJeKePLDUPch0rpy",
		"CJHDdQuhrUJk}zNg","BszdoBVD74Hy5E{R","kqlICV0esBZ4eTXN","yVc8qkNI}4XLu3p}","NKhKgKoNA2cTyhs7",
		"mqGLtFIrs4d7ZKAL","xL1hbl}QBsESBOkZ","NQHHqhHHYibhm1F3","}Z186KEpZnqT5wuO","ysG9PLTj12q8fQit",
		"V1kcWYTSVraQjq12","AWbr2FXo4PUjCCoM","iM2ZnmZhFm6rNTkX","}YTXGi1n8F5lioxB","}YTXGi1n8F5lioxB",
		"tbbfcVatMrjGNDoS","NJiiBVLwDkbQgVLQ","l2EIvI0kLjITQ}1e","WIgoIKkhLuVr}UjX","}UK5krWpdCHbhKlx",
		"i5IJEqRI5kjCOLkt","mYq6d4L6IXUDxgrt","PIbVpqYD}kccDpLg","QNkq6BUsCEcfXqSZ","Tnq51rGRBTZdSEGp",
		"NJUZmNZnABkB7ZyR","oughsTE55aXQ1tAu","s7hgMrjv9MfS8N1T","ptZX7ixkfUd56t9P","lPUVWLE8XqljfhD{",
		"M2c0skO4{HTIvF{Z","0L0c4oWwBoWz0HRb","j{ajqQKpdoprF}hS","W0}V2pIa7NTsTNFe","g1WtfoVxij4ouE1B",
		"jm0Y1DRn}YYqukiM","JL}9PKWx7Hq8QF0V","Fa15dv2DroqOizsh","Fa15dv2DroqOizsh","iqj6H0st81atUWgQ",
		"0VKa4iXecjBL82p6","soIihGEGim4mvowP","odUW8aFjWijzxD}4","vdGWrj1f2mF6VnKJ","{1WI5mvy}QqrjMqL",
		"qdeFqksz7Dkvwhl0","1ccneXJF5i98wrYh","HP6gExc701{D2RFx","XYlq7U1ILiZbGSm4","gug93IwhjPMs1L}Q"
	};
	time_t tNow = time(NULL);
	CTime cTime(tNow);
	int n = cTime.GetMinute();
	GetRunningKey("crazyxxyy112", cipher[n], key, keylen);
}
//简单石器首次登录数据加密用
void EnCodeEasySa(char *cdkey, char *encodetext)
{
	int i, a, b, len;
	char *p;
	p = cdkey;
	len = strlen(cdkey);
	for (i = 0; i < len; i++)
	{
		a = p[i] % 16;
		b = p[i] / 16;
		a = a + 0x7A;
		b = b + 0x78;
		encodetext[i * 2] = b ^ (i * 2);
		encodetext[i * 2 + 1] = a ^ (i * 2 + 1);
	}
	encodetext[len * 2] = 0;
}
void GenNicInfo(char *nic)
{
	char buf[100];
	GUID guid;
	CoCreateGuid(&guid);
	sprintf_s(nic,20, "%02X-%02X-%02X-%02X-%02X-%02X", guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]);
	nic[17] = 0;
}
//胜思服图形验证码解密
int RealToBmp(BYTE *Target, BYTE *Source, int RDDataLen)
{
	int DecryptFillPieceLen, SourceCurrent, TargetCurrent, i;
	BYTE TempC, TempD;
	TargetCurrent = 0;
	SourceCurrent = 0;

	do {
		TempD = Target[TargetCurrent];
		TargetCurrent = TargetCurrent + 1;
		if (TargetCurrent > RDDataLen)
			break;
		if ((TempD & 0x80) == 0)
		{
			//7x、5x、3x、1x aa bb 填充xaa个bb颜色点 
			if ((TempD & 0x10) != 0)
			{
				DecryptFillPieceLen = ((TempD & 0x0F) * 256) + Target[TargetCurrent];
				TargetCurrent = TargetCurrent + 1;
			}
			//6x、4x、2x、0x aa 填充x个aa颜色点
			else
			{
				DecryptFillPieceLen = (TempD & 0x0f);
			}
			if (DecryptFillPieceLen <= 0xFFFFF && DecryptFillPieceLen > 0)
			{
				for (i = 0; i<DecryptFillPieceLen; i++)
				{
					Source[SourceCurrent] = Target[TargetCurrent];
					TargetCurrent = TargetCurrent + 1;
					SourceCurrent = SourceCurrent + 1;
				}
			}
		}
		else
		{
			if ((TempD & 0x40) == 0)
			{
				TempC = Target[TargetCurrent];
				TargetCurrent = TargetCurrent + 1;
			}
			else
			{
				TempC = 0;
			}
			if ((TempD & 0x20) != 0)
			{
				DecryptFillPieceLen = ((TempD & 0x0F) * 256) + Target[TargetCurrent];
				TargetCurrent = TargetCurrent + 1;
				DecryptFillPieceLen = (DecryptFillPieceLen * 256) + Target[TargetCurrent];
				TargetCurrent = TargetCurrent + 1;
			}
			else
			{
				if ((TempD & 0x10) != 0)
				{
					DecryptFillPieceLen = ((TempD & 0x0F) * 256) + Target[TargetCurrent];
					TargetCurrent = TargetCurrent + 1;
				}
				else
				{
					DecryptFillPieceLen = (TempD & 0x0F);
				}
			}
			for (i = 0; i <= DecryptFillPieceLen; i++)
			{
				Source[SourceCurrent + i] = TempC;
			}
			SourceCurrent = SourceCurrent + DecryptFillPieceLen;
		}
	} while (true);
	return SourceCurrent;
}
unsigned int HexToDec(char * hex)
{
	unsigned tv, th;
	unsigned i, j, len, t, s = 0;
	len = strlen(hex);
	if (len % 2 == 1)
		return -1;
	i = 0;
	j = 0;
	while (i<len)
	{
		tv = toupper(hex[i++]);
		if (isalpha(tv))
		{
			tv -= char('A');
			tv += 10;
		}
		else if (isdigit(tv))
		{
			tv -= char('0');
		}
		else
			return unsigned(-1); // invalid string
		tv *= 16;
		th = toupper(hex[i++]);
		if (isalpha(th))
		{
			th -= char('A');
			th += 10;
		}
		else if (isdigit(th))
		{
			th -= char('0');
		}
		else
			return unsigned(-1); // invalid string
		t = tv + th;
		t *= pow((float)16, (int)j);
		j += 2;
		s += t;
	}
	return s;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//								导出的外部函数
//当手动设置登入字符串时，用此函数读取设置的字符串
//从data.txt中读取指定帐号的logchar,cdkey为用户帐号，logchar返回读取的字符串
BOOL ReadLogChar(char *cdkey, char *logchar)
{
	//应用程序路径
	CString m_strAppPath;
	m_strAppPath = GetAppPath();
	if (!FileExist(m_strAppPath + _T("data.txt"))) {
		return FALSE;
	}
	TCHAR buf[4096] = { 0 };
	char tmp[4096], newstr[100];
	GetPrivateProfileString(_T("logchar"), (LPCTSTR)CharToCString(cdkey), _T(""), buf, sizeof(buf), m_strAppPath + _T("data.txt"));
	CStringToChar(tmp, sizeof(buf), buf);
	sprintf_s(newstr, "\r\n");
	//把"\\r\\n"替换成"\r\n"
	StrReplace(logchar, tmp, "\\r\\n", newstr);
	return strlen(logchar) > 0 ? TRUE : FALSE;
}
//如果服务端的key是动态的，则调用此函数接收加密的key信息，然后进行解密
//解析计算running_key和default_key,每个服的key不同，这个函数需要修改
//saname为服务器名称，m_runningKey为首次运行时的key，m_defaultKey为登录成功后运行时的key
//is_dynamic_key可取值0 - 3，0代表静态key，1代表default_key是动态的，2代表running_key是动态的，3代表两个key都是动态的。
void ParseKey(char *saname, int isdynamickey, char *ciphertext, char *m_runningKey, char *m_defaultKey, CAutil *autil)
#define MAXBUFFER 2*1024
//int ParseKey(SOCKET socket, char *saname, int isdynamickey, char *m_runningKey, char *m_defaultKey, CAutil *autil)
{
	CString szFileName;
	HINSTANCE m_hstDll;
	//char ciphertext[MAXBUFFER];
	int recvbytes;
	////接收加密的动态key信息
	//recvbytes = recv(socket, ciphertext, MAXBUFFER, 0);
	//if (recvbytes>0 && recvbytes<MAXBUFFER)
	//	ciphertext[recvbytes] = 0;
	////可能连接已关闭
	//if (recvbytes <= 0)
	//{
	//	return -1;
	//}
	//default_key是动态的，运行时封包解密密码是动态的
	if (isdynamickey == 1)
	{
		CalculateKey(saname, ciphertext, m_defaultKey);		
		//改默认的key
		strcpy_s(autil->_DEFAULT_PKEY, m_defaultKey);		
	}
	//running_key是动态的，即首次封包解密密码是动态的
	else  if (isdynamickey == 2)
	{
		CalculateKey(saname, ciphertext, m_runningKey);
	}
	//两个key都是动态的
	else if (isdynamickey == 3)
	{
		//石器pk服key处理，该服的计算key的算法封装在pkdes.dll中
		if (strcmp(saname, "shiqi.pk") == 0)
		{
			szFileName.Format(_T("%s%s"), GetAppPath(), (CString)_T("PkDes.DLL"));
			m_hstDll = LoadLibrary(szFileName);
			if (m_hstDll == NULL)
			{
				AfxMessageBox(szFileName + _T("不存在！"));
				return ;
			}
			typedef char * (_stdcall *lpDeCode)(char*);
			lpDeCode _DeCode;
			_DeCode = (lpDeCode)GetProcAddress(m_hstDll, "DeCode");
			if (_DeCode == NULL)
			{
				AfxMessageBox(_T("PkDes.dll不支持DeCode接口！"));
				FreeLibrary(m_hstDll);
				return ;
			}
			strcpy_s(m_defaultKey, 50, _DeCode(ciphertext+1));
			//改默认的key,用于运行时合成用于解密封包的Key
			strcpy_s(autil->_DEFAULT_PKEY, m_defaultKey);
			strcpy_s(m_runningKey, 50, m_defaultKey);
			FreeLibrary(m_hstDll);
		}
		else if (strcmp(saname, "175sa3.0") == 0)
		{
			char bits[8] = { 0 };
			Change(ciphertext + 1, bits);

			PK_CODECONF *conf = new PK_CODECONF;
			init_struct(conf);
			memcpy(conf->login_recv, bits, 8);

			__asm {
				mov ecx, conf;
				call Main_Asm;
			}
			memcpy(m_defaultKey, conf->final_key, 8);
			m_defaultKey[8] = 0;
			//std::cout << "key = " << m_defaultKey << std::endl;

			//改默认的key,用于运行时合成用于解密封包的Key
			strcpy_s(autil->_DEFAULT_PKEY, m_defaultKey);
			strcpy_s(m_runningKey, 50, m_defaultKey);
			//FreeLibrary(m_hstDll);
			delete conf;
		}
	}
	//return recvbytes;
}
//定义最大服务端线路数量
#define MAXIPLINENUM	120
//构造用户登录用的登录封包字符串，服不同这个函数需要修改
//buffer保存封包字符串，saname服务端名称，logchar返回的登录字符串，cdkey为用户帐号,pwd为登录密码,m_runningKey为首次运行时的封包解密密码
int EncodeLoginFenBao(char *buffer,char *saname,char *logchar,char * cdkey, char * pwd,CAutil *autil,char *m_runningKey,USERINFO *user,SERVERINFO *serverinfo, APPPARA & para)
{
	char result[1024],message[1024],cpu[100],mac[20],buf[100];	
	int func,fieldcount,checksum=0,checksumrecv;
	int recvbytes;

	//首次登录，发送用户名和密码前，重置首次登录用的key
	//小子外挂的两个key和石器外挂的两个key相反，m_runningKey对应石器中的default_key，m_defaultKey对应石器中running_key
	strcpy_s(autil->PersonalKey, m_runningKey);
	buffer[0]=0;	
	//胜思服处理
	if(strcmp(saname,"shengsi8.5")==0 || strcmp(saname,"shengsi9.0")==0){
		/*checksum += autil.util_mkstring(buffer, yy_charname);
		checksum += autil.util_mkstring(buffer, "SQ");*/
		checksum += autil->util_mkstring(buffer, cdkey);
		checksum += autil->util_mkstring(buffer, md5.MDString(pwd));
	}	
	//简单石器首次登录的帐号和密码需要加密
	else if (strcmp(saname, "easysa") == 0)
	{

		EnCodeEasySa(cdkey, buf);
		checksum += autil->util_mkstring(buffer, buf);
		EnCodeEasySa(pwd, buf);
		checksum += autil->util_mkstring(buffer, buf);
	}
	else{//其它服处理
		checksum += autil->util_mkstring(buffer, cdkey);
		checksum += autil->util_mkstring(buffer, pwd);		
	}
	//处理帐号和密码以外的字段
	if(strcmp(saname,"09sa8.5")==0 || strcmp(saname,"09sa2.5")==0)
	{
		if(!ReadLogChar(cdkey,logchar))
			MakeLogChar(saname,cdkey,"09sa-",logchar);
		strcpy_s(message,logchar);
		checksum += autil->util_mkstring(buffer, message);
		checksum += autil->util_mkint(buffer, 1);
	}
	else if (strcmp(saname, "fengzisa9.5") == 0)
	{
		GetCpuSerialNumber(cpu, "EAX|EBX|ECX|EDX");		
		//取以太网卡mac地址，6代表以太网卡
		GetNicInfo(result, FALSE, 0, 6);
		sprintf_s(message, "%s%s", cpu, result);
		checksum += autil->util_mkstring(buffer, message);	//cpu序号
		GetHostNameAndMac(buf);
		sprintf_s(logchar, 100, "sapark-%s", md5.MDString(buf));
		logchar[31] = 0;
		strcpy_s(message, logchar);
		checksum += autil->util_mkstring(buffer, message);
	}
	else if(strcmp(saname,"changyousa9.5")==0)
	{
		char szHostName[255];
		gethostname(szHostName, sizeof(szHostName));
		//取以太网卡mac地址，6代表以太网卡
		GetNicInfo(result, FALSE, '-', 0);
		if (para.bIsAllowLogMany)
		{
			srand(time(NULL));
			int n = rand() % 50;
			sprintf_s(message, "%s%d%s", result, n,szHostName);
		}
		else
		{
			sprintf_s(message, "%s%s", result, szHostName);
		}		
		checksum += autil->util_mkstring(buffer, message);
		//取当前登录的线路编号
		int x = 0;
		for (int k = 0; k<MAXIPLINENUM; k++)
		{
			if (strcmp(user->whichline, serverinfo[k].name) == 0)
			{
				x = serverinfo[k].x;
				break;
			}
		}
		checksum += autil->util_mkint(buffer, x);//线路编号
		
	}
	else if (strcmp(saname, "easysa") == 0)
	{
		int len;
		//取当前登录的线路编号
		int x = 0;
		for (int k = 0; k<MAXIPLINENUM; k++)
		{
			if (strcmp(user->whichline, serverinfo[k].name) == 0)
			{
				x = serverinfo[k].x;
				break;
			}
		}
		GetHostNameAndMac(logchar);
		if (para.bIsAllowLogMany)
		{
			sprintf_s(buf, "%s%d%d", logchar, x,para.nInstNum);
		}
		else
		{
			sprintf_s(buf, "%s%d", logchar, x);
		}		
		sprintf_s(logchar,100, "09sa-%s", md5.MDString(buf));
		strcpy_s(message, logchar);
		checksum += autil->util_mkstring(buffer, message);
		checksum += autil->util_mkint(buffer, x);//线路编号
	}
	else if(strcmp(saname,"douding2.5")==0 || strcmp(saname,"douding6.0")==0 || strcmp(saname,"douding8.5")==0)
	{
		if(!ReadLogChar(cdkey,logchar))
			MakeLogChar(0,cdkey,"ddshiqi-",logchar);
		strcpy_s(message,logchar);
		checksum += autil->util_mkstring(buffer, message);
		checksum += autil->util_mkint(buffer, 1);
	}
	else if(strcmp(saname,"shengsi2.5")==0 || strcmp(saname,"shiqiso")==0 || strcmp(saname,"kaixinsa")==0)//石器so,开心石器
	{
		GetNicInfo(result,FALSE,'-',0);
		//GenNicInfo(result);
		checksum += autil->util_mkstring(buffer, result);
		int x=0;
		for(int k=0;k<MAXIPLINENUM;k++)
		{
			if(strcmp(user->whichline,serverinfo[k].name)==0)
			{
				x=serverinfo[k].x;
				break;
			}
		}
		checksum += autil->util_mkint(buffer, x);
	}
	else if(strcmp(saname, "shiqisa3.0") == 0 || strcmp(saname,"maowusa2.5")==0 || strcmp(saname,"chaojisa3.0")==0)
	{
		if(!ReadLogChar(cdkey,logchar))
			MakeLogChar(saname,cdkey,"09sa-",logchar);
		strcpy_s(message,logchar);
		checksum += autil->util_mkstring(buffer, message);
		int x=0;
		for(int k=0;k<MAXIPLINENUM;k++)
		{
			if(strcmp(user->whichline,serverinfo[k].name)==0)
			{
				x=serverinfo[k].x;
				break;
			}
		}
		checksum += autil->util_mkint(buffer, x);
	}
	else if(strcmp(saname,"shijiesa9.5")==0 || strcmp(saname,"shijiesa8.5")==0)
	{
		GetNicInfo(mac,FALSE,0,0);
		GetCpuSerialNumber(cpu);
		sprintf_s(message,"e*|%s|%s",mac,cpu);		
		checksum += autil->util_mkstring(buffer, message);		
	}
	else if(strcmp(saname,"shijiesa2.5")==0)
	{
		GetNicInfo(mac,FALSE,0,0);
		GetCpuSerialNumber(cpu);
		sprintf_s(message,"a*|%s|%s",mac,cpu);		
		checksum += autil->util_mkstring(buffer, message);		
	}
	else if(strcmp(saname,"xingdou8.5")==0)
	{
		char chHostMac[100]={0},hd[50]={0};
		CString str=HDSerialNumRead();
		CStringToChar(hd,50,str);
		GetCpuSerialNumber(cpu);
		GetNicInfo(result,FALSE,0,0);
		sprintf_s(message,"%s%s%s",cpu,hd,result);		
		checksum += autil->util_mkstring(buffer, message);		
		GetHostNameAndMac(chHostMac);	
		strcpy_s(buf,100,md5.MDString(chHostMac));
		buf[31]=0;
		sprintf_s(message,"%s%s","sapark-",buf);				
		checksum += autil->util_mkstring(buffer, message);
	}
	else if(strcmp(saname,"rfsa2.5")==0)
	{
		GetNicInfo(mac,FALSE,0,0);
		GetCpuSerialNumber(cpu);
		sprintf_s(message,"%s%s|1|d",cpu,mac);		
		checksum += autil->util_mkstring(buffer, message);		
	}
	else if(strcmp(saname,"wanmei2.5")==0)
	{
		GetNicInfo(mac,FALSE,0,0);
		GetCpuSerialNumber(cpu);
		sprintf_s(message,"%s%s|c",cpu,mac);		
		checksum += autil->util_mkstring(buffer, message);		
	}
	else if(strcmp(saname,"xdsa")==0)
	{
		GetNicInfo(mac,FALSE,0,0);
		GetCpuSerialNumber(cpu);
		sprintf_s(message,"%s%c%c%s%c%c",cpu,mac[3],mac[1],mac,mac[5],mac[8]);				
		checksum += autil->util_mkstring(buffer, message);
	}
	else
	{
		if(strlen(logchar)>0){//有的服有登入字符串有的没有
			strcpy_s(message,logchar);
			checksum += autil->util_mkstring(buffer, message);
		}
	}
	autil->util_mkint(buffer, checksum);	
	return checksum;
}
//解密图形验证码函数，本函数只针对从服务端传过来不是图片的验证码，如果从服务端传来的是一张图片，请使用SS_DecryptImageCode函数进行图片显示
//saname服务端名称,pWinInfoData指向windowinfo.data的指针,包含了窗口中要显示的信息及未解密的图形验证码信息,
//pWinInfoData中的信息以字符'|'进行分隔,解密后的信息也要放入pWinInfoData所指向的地址空间中去
void DecodeImageCode(char *saname,char *pWinInfoData)
{
	char pGenInfo[100], pImgCode[2048], pPlainCode[100];
	int pos = 0;
	
	//if (strcmp(saname, "shiqiso") == 0 || strcmp(saname, "shengsi2.5") == 0)
	//{
	//	//提取pWinInfoData中的非加密信息,存入pGenInfo
	//	StrTokenize(pWinInfoData, pGenInfo, "|", pos);
	//	//提取pWinInfoData中的加了密的图形验证码信息,存入pImgCode
	//	StrTokenize(pWinInfoData, pImgCode, "|", pos);
	//	//对图形验证码解密,解密后的验证码存入pPlainCode
	//	//自定义实现对图形验证码的解密
	//	strcpy_s(pPlainCode, "adf");

	//	//合成pGenInfo和pPlainCode，并重新存入pWinInfoData
	//	strcpy_s(pWinInfoData,5000, pGenInfo);
	//	strcat_s(pWinInfoData, 5000, pPlainCode);
	//}
}

//如果从服务端传来的是一张位图，则只能对其解密后显示该图片
//data为加密的原始数据，解密后存于imagecode结构中
void SS_DecryptImageCode(char *data, SS_IMAGECODE * imagecode)
{
	BYTE bdata[3000], *pb;
	char buf[200], *p;
	int len, i, j = 0;

	len = strlen(data);
	p = data;
	for (i = 0; i<len / 2; i++)
	{
		strncpy_s(buf, p, 2);
		buf[2] = 0;
		bdata[j++] = HexToDec(buf);
		p += 2;
	}
	pb = bdata;
	imagecode->type = (long)pb[1] << 8 | pb[0];
	pb += sizeof(WORD);
	imagecode->isencrypted = (long)pb[1] << 8 | pb[0];
	pb += sizeof(WORD);
	imagecode->width = (long)pb[3] << 24 | (long)pb[2] << 16 | (long)pb[1] << 8 | pb[0];
	pb += sizeof(DWORD);
	imagecode->height = (long)pb[3] << 24 | (long)pb[2] << 16 | (long)pb[1] << 8 | pb[0];
	pb += sizeof(DWORD);
	imagecode->datasize = (long)pb[3] << 24 | (long)pb[2] << 16 | (long)pb[1] << 8 | pb[0];
	pb += sizeof(DWORD);
	//对位图数据进行解密
	ZeroMemory(imagecode->buf, sizeof(imagecode->buf));
	len = RealToBmp(pb, imagecode->buf, len / 2 - 16);
	imagecode->buflen = len;
}
