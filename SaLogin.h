// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 SALOGIN_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// SALOGIN_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef SALOGIN_EXPORTS
#define SALOGIN_API __declspec(dllexport)
#else
#define SALOGIN_API __declspec(dllimport)
#endif

// 此类是从 SaLogin.dll 导出的
class SALOGIN_API CSaLogin {
public:
	CSaLogin(void);
	// TODO: 在此添加您的方法。
};

extern SALOGIN_API int nSaLogin;

SALOGIN_API int fnSaLogin(void);
typedef struct {
	BOOL bIsAllowLogMany;
	int nInstNum;
}APPPARA;
//服务端ip地址和端口号
typedef struct{
	char name[50];
	char ip[30];
	int port;
	int x;  //线路编号
}SERVERINFO;

//登录帐号信息
typedef struct{
	char charname[30];
	char password[30];
	char safecode[30];
	int whichone;			//要登入哪个人物
	int index;				//当前帐号在pDp数组中的索引序号
	char scriptName[200];	//脚本文件名
	char configFile[200];	//配置文件名
	char whichteam[20];		//属于哪个队伍
	int membertype;			//成员类型,0为队员,1为队长
	//以下为线路信息，登录前存储于g_serverinfo中
	char whichline[50];		//登入哪条线路
	char lineip[30];		//线路ip
	int port;				//端口号
	char privilege_script[50];	//正在运行的特权脚本
	char logchar[100];			//登录时发送给服务端的字符串
}USERINFO;
//图形验证码信息，针对从服务端传回的是一张图片，而非加密的文本形式
typedef struct {
	WORD type;
	WORD isencrypted;
	DWORD width;		//图片宽度
	DWORD height;		//图片高度
	DWORD datasize;		//图形数据文本的总大小
	BYTE buf[3000];		//指向位图数据的指针
	WORD buflen;		//位图数据的大小
}SS_IMAGECODE;


