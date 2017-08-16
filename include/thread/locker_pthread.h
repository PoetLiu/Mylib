#ifndef __LOCKER_PTHREAD_H__
#define __LOCKER_PTHREAD_H__

#include "list.h"

#define RET_OK		0
#define RET_FAIL	1
Locker *locker_pthread_create(void);
#endif
