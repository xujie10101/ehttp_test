#include <sstream>
#include <cstdlib>
#include "simple_log.h"
#include "http_server.h"
#include "Data.h"
#include "log4z.h"
#include "cJSON.h"
#include "internal.h"

static std::map<CData, CData> mMapFile;

const char* getFileType(const char* name)
{
	const char* dot = NULL;

	dot = strrchr(name, '.');
	if (dot == NULL)
		return "text/plain; charset=utf-8";
	if (strcmp(dot, "js") == 0) 
		return "application/javascript";
	if (strcmp(dot, ".json") == 0)
		return "application/json;charset=utf-8";
	if (strcmp(dot, ".pdf") == 0)
		return "application/pdf";
	if (strcmp(dot, ".html") == 0 || 
		strcmp(dot, ".htm") == 0)
		return "text/html; charset=utf-8";
	if (strcmp(dot, "ioc") == 0)
		return "image/x-icon";
	if (strcmp(dot, "bmp") == 0)
			return "image/bitmap";
	if (strcmp(dot, ".jpg") == 0 || 
		strcmp(dot, ".jpeg") == 0)
		return "image/jpeg";
	if (strcmp(dot, ".gif") == 0)
		return "image/gif";
	if (strcmp(dot, ".png") == 0)
		return "image/png";
	if (strcmp(dot, ".css") == 0)
		return "text/css";
	if (strcmp(dot, ".au") == 0)
		return "audio/basic";
	if (strcmp(dot, ".wav") == 0)
		return "audio/wav";
	if (strcmp(dot, ".avi") == 0)
		return "video/x-msvideo";
	if (strcmp(dot, ".mov") == 0 || strcmp(dot, ".qt") == 0)
		return "video/quicktime";
	if (strcmp(dot, ".mpeg") == 0 || strcmp(dot, ".mpe") == 0)
		return "video/mpeg";
	if (strcmp(dot, ".vrml") == 0 || strcmp(dot, ".wrl") == 0)
		return "model/vrml";
	if (strcmp(dot, ".midi") == 0 || strcmp(dot, ".mid") == 0)
		return "audio/midi";
	if (strcmp(dot, ".mp3") == 0)
		return "audio/mpeg";
	if (strcmp(dot, ".mp4") == 0)
		return "audio/mp4";
	if (strcmp(dot, ".ogg") == 0)
		return "application/ogg";
	if (strcmp(dot, ".pac") == 0)
		return "application/x-ns-proxy-autoconfig";
	if (strcmp(dot, ".pcap") == 0)
		return "application/x-pcap";

	return "text/plain; charset=utf-8";
}


#define		MAX_CONNS_WORKER	0x100000

void ModifytxQueue()
{
	socket_t fdClient = socket(AF_INET, SOCK_DGRAM, 0);

	struct ifconf lxfig = { 0 };
	char szBuf[1024] = { 0 };
	lxfig.ifc_buf = szBuf;
	lxfig.ifc_len = 1024;

	if (ioctl(fdClient, SIOCGIFCONF, &lxfig)) {
		return;
	}

	ifreq* it = lxfig.ifc_req;
	const struct ifreq* const end = it +
		(lxfig.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		if (0 == strcmp(it->ifr_name, "lo")) {
			continue;
		}
		it->ifr_ifru.ifru_ivalue = 51200;
		ioctl(fdClient, SIOCSIFTXQLEN, it);
	}
	::close(fdClient);
}

void ModifySyslimit()
{
	struct rlimit rlim, rlim_new;
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0)
	{
		rlim_new.rlim_cur = rlim_new.rlim_max = MAX_CONNS_WORKER;
		if (setrlimit(RLIMIT_NOFILE, &rlim_new) != 0) {
			rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
			setrlimit(RLIMIT_NOFILE, &rlim_new);
		}
	}

	if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
		rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &rlim_new) != 0) {
			rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
			setrlimit(RLIMIT_CORE, &rlim_new);
		}
	}

	if (system("sysctl -w net.core.somaxconn=65536")) {
		return;
	}

	if (system("sysctl -w net.core.rmem_max=8388608")) {
		return;
	}

	if (system("sysctl -w net.core.wmem_max=8388608")) {
		return;
	}

	if (system("sysctl -w net.core.rmem_default=8388608")) {
		return;
	}

	if (system("sysctl -w net.core.wmem_default=8388608")) {
		return;
	}

	if (system("sysctl -w net.ipv4.udp_rmem_min=8388608")) {
		return;
	}

	if (system("sysctl -w net.ipv4.udp_wmem_min=8388608")) {
		return;
	}

	if (system("sysctl -w net.ipv4.udp_mem='2097152 4194304 8388608'")) {
		return;
	}

	if (system("sysctl -w kernel.core_pattern=./core-%e-%t 1>/dev/null 2>&1")) {
		return;
	}
	/*
	if (system("sysctl -w net.ipv4.tcp_rmem='2097152 4194304 8388608'")) {
		return;
	}

	if (system("sysctl -w net.ipv4.tcp_wmem='2097152 4194304 8388608'")) {
		return;
	}

	if (system("sysctl -w net.ipv4.tcp_mem='2097152 4194304 8388608'")) {
		return;
	}
	*/
	//system("sysctl -a|grep net.core|sort");
	if (system("sysctl -p")) {
		return;
	}
}

int GetFilePaths(const char* directory)
{
	DIR* dir = 0;
	struct stat st;
	char sFilePath[256] = {0};
	struct dirent* filename;
	if (0 == getcwd(sFilePath, 256)) {
		LOGFMTE("Get path fail!");
		return XX_ERR_NONE;
	}

	if (0 == directory) {
		LOGFMTE(" directory is null ! :%s", directory);
		return XX_ERR_ERROR;
	}
	lstat(directory, &st);
	if (!S_ISDIR(st.st_mode)) {
		LOGFMTE("directory is not a valid directory ! :%s", directory);
		return XX_ERR_ERROR;
	}

	if (0 == (dir = opendir(directory))) {
		LOGFMTE("Can not open dir %s", directory);
		return XX_ERR_ERROR;
	}
	/* read all the files in the dir ~ */
	while ((filename = readdir(dir)) != 0) {
		if (strcmp(filename->d_name, ".") == 0 ||
			strcmp(filename->d_name, "..") == 0) {
			continue;
		}
		snprintf(sFilePath, sizeof(sFilePath), "%s/%s", directory, filename->d_name);

		if (lstat(sFilePath, &st) == -1) {
			LOGFMTE("directory is not a valid directory ! %s",sFilePath);
			return XX_ERR_ERROR;
		}

		if (S_ISDIR(st.st_mode)) {
			GetFilePaths(sFilePath);
			continue;
		}
		snprintf(sFilePath, sizeof(sFilePath), "%s/%s", directory, filename->d_name);
		// CAutoMutex AutoMutex(m_mutexMapFile);
		mMapFile[filename->d_name] = sFilePath;
		LOGFMTI("[%s][%s]",filename->d_name,sFilePath);
	}
	return XX_ERR_NONE;
}

void sendJson(cJSON* json, Response &response){
	char* ptr = cJSON_Print(json);

    response._body = ptr;
	cJSON_Delete(json);
	SAFE_FREE(ptr);
}

void getMachineCode(Request &request, Response &response) {

#if 0
	m_local_uid = "6fd8a6b13ea6368130696af1ab494eb1";
	char szStr[1024] = { 0 };
#if  defined (__aarch64__) || defined(mips)
	printf("__aarch64__\n");
	std::string cmd = "cat /proc/cpuinfo |grep Serial | awk '{print $3}'";
	ExecuteCMD(cmd.c_str(), szStr);
	UID += szStr;
	cmd = "cat /sys/bus/mmc/devices/mmc1\\:0001/cid";
	ExecuteCMD(cmd.c_str(), szStr);
	UID += szStr;
	char szMd5[64] = { 0 };
	MD5Digest((char*)UID.c_str(), UID.size(), szMd5);
	UID = szMd5;
	LOGFMTI("szMd5:%s", szMd5);
#elif defined __x86_64__
	printf("__x86_64__\n");
	printf("%s\n",m_local_uid.c_str());
#endif
#endif

	cJSON* JsonObject1 = cJSON_CreateObject();
	cJSON_AddItemToObject(JsonObject1, "code", cJSON_CreateNumber(200));
	cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("m_local_uid.c_str()"));
	cJSON_AddItemToObject(JsonObject1, "data", cJSON_CreateString("success"));

    sendJson(JsonObject1, response);
}

void getProjectInfo(Request &request, Response &response) {
	int nType = 1;
	std::string projectName = "";
	std::string code = "";
	std::string versionNum = "";
	if (0 == nType){
		projectName = "安全联网网关";
		versionNum = "AQLW-P-MD1000";
		code = "209";
	}else if (1 == nType){
//#ifndef mips
//		projectName = "安全加固网关";
//#else
		projectName = "视频安全接入网关";
//#endif
		versionNum = "ANCHOR_AQJR";
		code = "118";
	}else if (2 == nType){
		projectName = "前端转换设备";
		versionNum = "ZD8911 A3-4";
		code = "118";
	}else if (3 == nType) {
		projectName = "安全联网网关";
		versionNum = "ZXH";
		code = "209";
	}else if (4 == nType) {
		projectName = "安全加固网关";
		versionNum = "ZXH";
		code = "118";
	}else if (5 == nType) {
		projectName = "安全联网网关";
		versionNum = "AQLW-P-XDJAOA";
		code = "118";
	}

	cJSON* JsonObject1 = cJSON_CreateObject();
	cJSON* JsonObject2 = cJSON_CreateObject();
	cJSON_AddItemToObject(JsonObject1, "code", cJSON_CreateNumber(200));
	cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("成功"));
	cJSON_AddItemToObject(JsonObject1, "data", JsonObject2);

	cJSON_AddItemToObject(JsonObject2, "code", cJSON_CreateString("200"));
	cJSON_AddItemToObject(JsonObject2, "versionNum", cJSON_CreateString("buildVersion.c_str()"));
	char st_time[64] = { 0 };

	cJSON_AddItemToObject(JsonObject2, "time", cJSON_CreateString("st_time"));
	cJSON_AddItemToObject(JsonObject2, "type", cJSON_CreateString(CData(nType).c_str()));
	cJSON_AddItemToObject(JsonObject2, "projectName", cJSON_CreateString(projectName.c_str()));

    sendJson(JsonObject1, response);
}

void preHandle(Request &request, Response &response) {
	cJSON* JsonObject1 = cJSON_CreateObject();
	cJSON* JsonObject2 = cJSON_CreateObject();

	#if LICENSE
		int num = licenseCheck(m_local_uid);
	#else
		int num = 0;
	#endif

	if (num != 0)
	{
		LOGFMTE("证书验证失败，%d", num);
		cJSON_AddItemToObject(JsonObject1, "code", cJSON_CreateNumber(400));
		cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("证书验证失败"));
		cJSON_AddItemToObject(JsonObject1, "data", NULL);
	}
	else
	{
		cJSON_AddItemToObject(JsonObject1, "code", cJSON_CreateNumber(200));
		cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("成功"));
		cJSON_AddItemToObject(JsonObject1, "data", JsonObject2);
		cJSON_AddItemToObject(JsonObject2, "machineCode", cJSON_CreateString("machineCode.c_str()"));
#if LICENSE
		cJSON_AddItemToObject(JsonObject2, "issuedTime", cJSON_CreateString(g_start_time.c_str()));//开始时间
		cJSON_AddItemToObject(JsonObject2, "expiryTime", cJSON_CreateString(g_end_time.c_str()));//结束时间
		int n1 = 0, m1 = 0, d1 = 0, n2 = 0, m2 = 0, d2 = 0;
		sscanf((char*)g_end_time.c_str(), "%d-%d-%d", &n2, &m2, &d2);
		sscanf((char*)g_start_time.c_str(), "%d-%d-%d", &n1, &m1, &d1);

		int sum = 0;
		//scanf("%d %d %d", &n1, &m1, &d1);//起始年月日 
		//scanf("%d %d %d", &n2, &m2, &d2);//最终年月日 
		sum = dateDifference(n1, m1, d1, n2, m2, d2);
		cJSON_AddItemToObject(JsonObject2, "days", cJSON_CreateNumber(sum));	//剩余时间
		std::string temp = "证书校验通过，证书有效期：";
		temp += g_start_time.c_str();
		temp += " - ";
		temp += g_end_time.c_str();
		cJSON_AddItemToObject(JsonObject2, "message", cJSON_CreateString(temp.c_str()));
#else
		cJSON_AddItemToObject(JsonObject2, "issuedTime", cJSON_CreateString(""));//开始时间
		cJSON_AddItemToObject(JsonObject2, "expiryTime", cJSON_CreateString(""));//结束时间
		cJSON_AddItemToObject(JsonObject2, "days", cJSON_CreateNumber(0));	//剩余时间
		cJSON_AddItemToObject(JsonObject2, "message", cJSON_CreateString(""));
#endif
	}

    sendJson(JsonObject1, response);
}

void licenseByAuto(Request &request, Response &response) {
	#if LICENSE
		int num = licenseCheck(m_local_uid);
	#else
		int num = 0;
	#endif

	cJSON* JsonObject1 = cJSON_CreateObject();
	cJSON* JsonObject2 = cJSON_CreateObject();
	cJSON_AddItemToObject(JsonObject1, "code", cJSON_CreateNumber(400));
	cJSON_AddItemToObject(JsonObject1, "data", JsonObject2);
	if (num != 0) {
		cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("证书验证失败，请更新证书!"));
		cJSON_AddItemToObject(JsonObject2, "flag", cJSON_CreateFalse());
		LOGFMTE("程序未授权，%d", num);
	}
	else
	{
		cJSON_AddItemToObject(JsonObject1, "msg", cJSON_CreateString("证书验证成功!"));
		cJSON_AddItemToObject(JsonObject2, "flag", cJSON_CreateFalse());
	}

	sendJson(JsonObject1, response);
}

void response_file(Request &request, Response &response) {
    std::map<CData, CData>::iterator Iter;
    CData sFileName = request.get_request_uri();
    if (sFileName.empty() || sFileName == "/") { sFileName = "/index.html";LOGFMTI("----------"); }
    Json::Value root;
    LOGFMTI("%s", sFileName.c_str());
    if ((Iter = mMapFile.find(sFileName)) != mMapFile.end()) {
        std::ifstream is(Iter->second.c_str());
        if (!is.good()) {
            root["code"] = -1;
            root["msg"] = "file not found:" + Iter->second.ToString();
            response.set_body(root);
            return;
        }
        std::stringstream ss;
        ss << is.rdbuf();//read the file
        std::string file_content = ss.str();
        response._body = file_content;
        // response.set_head("Content-Type", "text/html");
		response.set_head("Content-Type", getFileType(Iter->second.c_str()));
		
    }
    else {
        root["code"] = -1;
        root["msg"] = "file not found:" + Iter->second.ToString();
        response.set_body(root);
        LOGFMTE("%s", sFileName.c_str());
    }
}

// Make sure the callback method is threadsafe
void login(Request &request, Response &response) {
    std::string name = request.get_param("name");
    std::string pwd = request.get_param("pwd");

    LOG_DEBUG("login user which name:%s, pwd:%s", name.c_str(), pwd.c_str());
    
    // root["code"] = 0;
    // root["msg"] = "login success!";
    response._body = "login success!";
}

void removeSubstring(std::string& mainString, const std::string& substring) {
    size_t pos = mainString.find(substring);
    if (pos != std::string::npos) {
        mainString.erase(pos, substring.length());
    }
}

int main() {
    GetFilePaths("web");
    HttpServer http_server;
    
    std::map<std::string, std::pair<method_handler_ptr, HttpMethod>> headers;
    headers["/hello"]={ login, GET_METHOD };;
    headers["/"]={response_file, GET_METHOD};
    headers[" "]={response_file, GET_METHOD};
    // headers["/test"]=POST_METHOD;
	headers["/license/getProjectInfo"]={getProjectInfo, POST_METHOD};
	headers["/license/getMachineCode"]={getMachineCode, POST_METHOD};
	headers["/license/preHandle"]={preHandle, POST_METHOD};
    std::string tmp;
    std::string value;
    for (const auto& pair : mMapFile) {
        tmp = pair.second.ToString();
        value = tmp;
        removeSubstring(tmp, "web");
        headers[tmp]={ response_file, GET_METHOD };
        mMapFile.erase(pair.first);
        mMapFile[tmp] = value;
	}

	for (const auto& pair : headers) {
        std::cout << pair.first << std::endl;
        http_server.add_mapping(pair.first, pair.second.first, pair.second.second);
	}

    // http_server.add_mapping("/login", login, POST_METHOD | GET_METHOD);

    http_server.set_port(18080);
    http_server.start_sync();
    return 0;
}