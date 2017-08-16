#ifndef _DEBUG_H
#define _DEBUG_H
#define DEBUG(fmt, args...)	\
	do {			\
		printf("DEBUG:%s-%d-%s: "fmt, __FILE__, __LINE__, __FUNCTION__, ##args);\
	}while(0)

#define ERROR(fmt, args...)	\
	do {			\
		printf("ERROR:%s-%d-%s: "fmt, __FILE__, __LINE__, __FUNCTION__, ##args);\
	}while(0)
#endif	// _DEBUG_H
