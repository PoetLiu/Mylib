#ifndef __ENCODE_H__
#define __ENCODE_H__

int str_is_ascii(const char *s);
int str_is_utf8(const char *s);
int str_is_gbk(const char *s):
int str_gbk2utf8(void *dst,void *src,int max_dst_len);
int str_unicode2utf8(void *dst,void *src,int max_dst_len);
int str_utf82gbk(void *dst,void *src,int max_dst_len);

#endif
