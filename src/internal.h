#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <map>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char 	uint8;
typedef unsigned short 	uint16;

#ifdef	WIN32

#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <MSWSock.h>
#include <winsock2.h>
#include <mmsystem.h>

#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <malloc.h>
#include <time.h>
#include <process.h>
#include <iphlpapi.h>
#include <assert.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")

typedef SOCKET					socket_t;
typedef __int64					int64;
typedef unsigned __int64		uint64;

#define strcasecmp 				_stricmp
#define snprintf 				_snprintf
#define strncasecmp 			_memicmp

#else

#include <sys/types.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <net/if.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>

#include <dlfcn.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <sys/prctl.h>


#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

typedef int							socket_t;
typedef long long					int64;
typedef unsigned long long			uint64;

#define INFINITE					-1
#define	SOCKET_ERROR				-1
#define INVALID_SOCKET				-1
#define WSAGetLastError()          errno
#define closesocket(s)			   close(s)

#endif
#define XX_ERR_NONE						0  /* no error */
#define	XX_ERR_ERROR					-1  /* no error */
#define MAX_BUFFER_512KSZ				0x80000
#define MAX_BUFFER_1MSIZE				0x100000
#define MAX_BUFFER_2MSIZE				0x200000
// #define MAX_BUFFER_4MSIZE				0x400000
#define MAX_BUFFER_4MSIZE				1024*10

#define OSIP_STATIC_DECLARE(class_name)			\
public:											\
	static class_name* instance();

#define OSIP_STATIC_IMP(class_name)				\
	class_name * class_name::instance(){		\
        static class_name m_instance;           \
		return &m_instance;						\
	}

#define osip_max(a, b) (a > b) ? a : b
#define osip_min(a, b) (a < b) ? a : b
#define xx_min(a, b)					(a < b) ? a : b
#define xx_max(a, b)					(a > b) ? a : b
#define xx_memcpy(p, off, ch, len)		memcpy(p + off, ch, len);	\
										off += len;

#define SAFE_FREE(P)					if (P){free(P); P = NULL;}
#define SAFE_DELETE(P)                  if (P){delete P; P = NULL;}
#define SAFE_DELETEA(P)                 if (P){delete[] P; P = NULL;}
#define SAFE_CLOSEHD(P)					if (P){CloseHandle(P); P = NULL;}

#endif
