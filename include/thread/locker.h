#ifndef __LOCKER_H__
#define __LOCKER_H__

struct _Locker;
typedef struct _Locker Locker;
typedef int (*LOCKER_LOCK)(Locker *);
typedef int (*LOCKER_UNLOCK)(Locker *);
typedef int (*LOCKER_DESTROY)(Locker *);
typedef Locker *(*LOCKER_CREATE)(void);

struct _Locker
{
	LOCKER_LOCK lock;
	LOCKER_UNLOCK  unlock;
	LOCKER_DESTROY destroy;
	char priv[0];
};

#endif
