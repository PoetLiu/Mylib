#ifndef __UTILITY_H_
#define __UTILITY_H_

typedef u_int32_t t_ipaddr;
typedef unsigned char uchar;

int my_rand(int start, int end);
int str_tail_check(const char *str, int max_len, int force);
unsigned char *char_bin_to_str(unsigned char );
char *bin_to_str(char *, int);
void get_ip_by_fd(int fd, char *ip);
char *mac2str(unsigned char *mac);
char *mac2str_kernel(unsigned char *mac);
char *mac2mac(char *mac);
char *mac2mac_kernel(char *mac);
char *ip2str(t_ipaddr ip);
t_ipaddr str2ip(char *str);
char *dns_check(const char *in);
int ip_mask_check(t_ipaddr ip, t_ipaddr mask);
int maskCheck(struct in_addr mask);
int igd_mac_is_valid(unsigned char *mac);
int mac_check_valid(char *mac);
int ip_check_valid(char *ip);
time_t get_now_time(void);
int get_now_tm(struct tm *value);
int close_parent_fd(void);
pid_t pid_get(char *name);

#endif
