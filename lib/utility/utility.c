#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <dirent.h>
#include "mylib.h"

static int _rand(void)
{
	static int first = 0;
	if (!first) {
		first	= 1;
		srand(time(NULL));
	}
	return rand();
}

int my_rand(int start, int end) 
{
	return start + _rand() % (end - start);
}

// 检查字符串尾的'\0'是否符合要求
// force选项表示指定字符串长度(即指定'\0'位置)
// 不加force选项将在str[0] - str[max_len]范围内查找'\0'
// 查找失败 或者str长度为0 或者str为NULL都视为错误
int str_tail_check(const char *str, int max_len, int force)
{
	const char *tmp;
	int i;
	tmp	= str;

	if (str == NULL)
		return 1;

	for (i = 0; i < max_len + 1; i++) {
		if (tmp[i] == '\0')
			break;
	}

	if (force)
		return !(i == max_len);
	else
		return !(i != 0 && i < max_len);

}

// 将一个字节的二进制数转换为2字节字符
// 即将二进制的数字转换为对应的16进制字符
// 比如data为00010001(一个字节)转换为"11"(00110001 00110001)两个字节
//	     11111111转换为"FF" 
// 从其本质上来说， 虽然内存中的数据经过转换之后发生了变化
// 但其代表的数值不变， 只不过数字存的是其数值， 而字符存的是其ascii
// 码对应的数值
//free
unsigned char *char_bin_to_str(unsigned char data)
{
        unsigned char *buf;
        buf = malloc(2);
        unsigned char hi,lo;

        hi = (data >> 4) & 0x0f;
        lo = data & 0x0f;

        if ((lo >= 0) && (lo < 10)) {
                buf[0] = 0x30 + lo;
        }

        if ((lo > 9) && (lo < 16)) {
                buf[0] = 0x41 + lo - 10;
        }

        if ((hi >= 0) && (hi < 10)) {
                buf[1] = 0x30 + hi;
        }

        if ((hi > 9) && (hi < 16)) {
                buf[1] = 0x41 + hi - 10;
        }

        return buf;
}

char * bin2str( void *bin, int size)
{
	int i;
	int len = 0;
	static char buf[1024];
	unsigned char *b = bin;
	if (!b) {
		buf[0] = '\0';
		return buf;
	}
	
	for (i=0; i<size && len < sizeof(buf)-3;i++) {
		len += snprintf(buf+len,sizeof(buf)-len,"%02X",b[i]);
	}
	buf[len] = '\0';
	return buf;
}

void get_ip_by_fd(int fd, char *ip)
{
	int			len;
	struct sockaddr_in	addr;

	len	= sizeof(struct sockaddr_in);
	if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
		DEBUG("getsockname faild\n");	
		return;
	} 
	strcpy(ip, inet_ntoa(addr.sin_addr));
}

#define MAC_FORMAT_STRING 		"%02x-%02x-%02x-%02x-%02x-%02x"
#define MAC_FORMAT_STRING_CAPITAL	"%02X-%02X-%02X-%02X-%02X-%02X"
#define MAC_FORMAT_STRING_KERNEL	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_FORMAT_SPLIT(mac)		(mac)[0],(mac)[1],(mac)[2],(mac)[3],(mac)[4],(mac)[5]

//2 mac
char *mac2str(unsigned char *mac)
{
	static char buf[18] = { 0 };

	if (!mac)
		return "NULL";

	memset(buf, 0, sizeof(buf));
	sprintf(buf, MAC_FORMAT_STRING_CAPITAL, MAC_FORMAT_SPLIT(mac));
	return buf;
}

char *mac2str_kernel(unsigned char *mac)
{
	static char buf[64] = { 0 };

	if (!mac)
		return "NULL";

	memset(buf, 0, sizeof(buf));
	sprintf(buf, MAC_FORMAT_STRING_KERNEL, MAC_FORMAT_SPLIT(mac));
	return buf;
}

//2 :mac2-mac
char *mac2mac(char *mac)
{
	static char buf[24 + 1] = { 0 };
	int i;

	if (!mac)
		return NULL;
	strncpy(buf, mac, 24);
	for (i = 0; i < strlen(buf); i++) {
		if (buf[i] == ':')
			buf[i] = '-';
	}
	return buf;
}

char *mac2mac_kernel(char *mac)
{
	static char buf[24 + 1] = { 0 };
	int i;

	if (!mac)
		return NULL;
	strncpy(buf, mac, 24);
	for (i = 0; i < strlen(buf); i++) {
		if (buf[i] == '-')
			buf[i] = ':';
	}
	return buf;
}

//2 ip
char *ip2str(t_ipaddr ip)
{
	struct in_addr addr;
	addr.s_addr = ip;

	// NOTE:
	// The inet_ntoa() function converts the Internet host address in, given in network byte order, 
	// to a string in IPv4 dotted-decimal notation.  The string is returned in a statically allocated buffer, 
	// which subsequent calls will overwrite.

	return inet_ntoa(addr);
}

t_ipaddr str2ip(char *str)
{
	struct in_addr addr;

	inet_aton(str, &addr);
	return addr.s_addr;
}

/*  return the valid dns string, or return NULL */
char *dns_check(const char *in)
{
	static char out[64]; 
	int i = 0;

	memset(out, 0, sizeof(out));

	while (*in && *in == '.')
		in++;
		
	while (*in && i < sizeof(out) - 1) {
		if (*in == '.') {
			if (*(in - 1) != '.') 
				out[i++] = '.';
		} else if (isgraph(*in)) {
			out[i++] = *in;
		} else {
			return NULL;
		}
		in++;
	}

	if (i > 1 && out[i - 1] == '.')
		out[i - 1] = 0;
	return out;
}

int ip_mask_check(t_ipaddr ip, t_ipaddr mask)
{
	int ret = 0;
	t_ipaddr tmp = 0;

	tmp = ip & ~mask;
	if (tmp == 0) {
		ret = -1;
	} else if ((tmp | mask) == 0xffffffff) {
		ret = -1;
	}
	return ret;
}

//1 IP MAC Check Valid
static int IsHex(char hexdig)
{
	if ((hexdig >= '0' && hexdig <= '9') ||
	    (hexdig >= 'a' && hexdig <= 'f') ||
	    (hexdig >= 'A' && hexdig <= 'F'))
		return 0;

	return -1;
}

//INPUT: Mask must be network byte order
int maskCheck(struct in_addr mask)
{
	in_addr_t addr;

	unsigned char *parts = (unsigned char *)&mask.s_addr;
	
	addr = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
	if(((((addr ^ (addr - 1)) >> 1) ^ addr) == (in_addr_t)-1)){
		return 0;
	}
	return -1;
}
int igd_mac_is_valid(unsigned char *mac)
{
	unsigned char tmp[6] = { 0, };
	/*  muticast mac */
	if ((mac[0] & 0x1) == 0x1) 
		return 0;
	if (!memcmp(mac, tmp, 6))
		return 0;
	return 1;
}

int mac_check_valid(char *mac)
{
	int i = 0, n = 0;
	char *cp = NULL;

	cp = mac;
	while ('\0' != *cp) {
		if ('-' == *cp || ':' == *cp) {
			i++;
			if ((n % 2) != 0 || (n / 2) != i)
				return -1;
		} else {
			n++;
			if (-1 == IsHex(*cp))
				return -1;
		}
		cp++;
	}

	if (5 != i || 12 != n)	// 5 * '-' or ':' and 12 * hex number
		return -1;

	return 0;
}

int ip_check_valid(char *ip)
{
	int iDot = 0, iCnt = 0, i;
	char *cp = ip;

	if (NULL == ip || 0 == strlen(ip)) {
		return -1;
	}

	i = atoi(cp);
	if (i <= 0 || i > 223 || i == 127)	//  127.x.x.x and 224-255.x.x.x is not  allowed
		return -1;

	while ('\0' != *cp) {
		iCnt++;
		if ('.' == *cp) {
			if (*(cp + 1) < '0' || *(cp + 1) > '9')
				return -1;
			i = atoi(cp + 1);
			if (i < 0 || i > 255)
				return -1;
			iDot++;
		} else {
			if (*cp < '0' || *cp > '9')
				return -1;
		}
		cp++;
	}

	if (3 != iDot || (iCnt > 15 || iCnt < 7))	// 7-15 chars,3 dots
		return -1;

	if (!strcmp(ip, "0.0.0.0"))	// 0.0.0.0 is not allowed
	{
		return -1;
	}

	return 0;
}

time_t get_now_time(void)
{
	time_t now_time;

	time(&now_time);

	return now_time;
}

int get_now_tm(struct tm *value)
{
	time_t now;
	struct tm *tmp;

	if (!value)
		return -1;
	
	now = get_now_time();
	tmp = localtime(&now);
	*value = *tmp;

	return 0;
}

int close_parent_fd(void)
{
        struct dirent **namelist = NULL;
        int n = 0;
        char dir[2048] = {0};

        sprintf(dir,"/proc/%d/fd", getpid());

        n = scandir(dir, &namelist, 0, alphasort);
        if(n < 0){
                return -1;
        }

        while(n--){
                int fd =  0;
                if(strcmp(".", namelist[n]->d_name) == 0){
                        free(namelist[n]);
                        continue;
                }
                if(strcmp("..", namelist[n]->d_name) == 0){
                        free(namelist[n]);
                        continue;
                }
                fd = atoi(namelist[n]->d_name);
                if(fd == 0 || fd == 1 || fd == 2){
                        free(namelist[n]);
                        continue;
                }
                close(fd);
                free(namelist[n]);
        }

        free(namelist);

        return 0;
}

pid_t pid_get(char *name)
{
	FILE *fp;
	char *ret = NULL;
	char buf[1024] = {0};
	char cmdline[1024] = {0};
	pid_t	pid = -1;

	P_VALID_RET(name, -1);
	snprintf(cmdline, sizeof(cmdline), "pidof %s", name);
	DEBUG("cmdline:%s\n", cmdline);

	fp	= popen(cmdline, "r");
	if (!fp) {
		DEBUG("popen faild\n");	
		return -1;
	}
	
	ret 	= fgets(buf, sizeof(buf), fp);
	if (!ret) {
		DEBUG("get pipe data faild\n");	
		return -1;
	}

	sscanf(buf, "%d", &pid);
	DEBUG("buf:%s pid:%d\n", buf, pid);
	pclose(fp);

	return pid;
}

