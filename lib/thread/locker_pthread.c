#include <pthread.h>
#include <stdlib.h>
#include "mylib.h"

static int locker_pthread_lock(Locker *thiz);
static int locker_pthread_unlock(Locker *thiz);
static int locker_pthread_destroy(Locker *thiz);

typedef struct _PrivInfo
{
	pthread_mutex_t mutex;
}PrivInfo;

Locker *locker_pthread_create(void)
{
	Locker *thiz = (Locker *)malloc(sizeof(Locker) + sizeof(PrivInfo));
	if (thiz != NULL) {
		PrivInfo *priv	= (PrivInfo *)thiz->priv;	
		thiz->lock	= locker_pthread_lock;
		thiz->unlock	= locker_pthread_unlock;
		thiz->destroy	= locker_pthread_destroy;
		pthread_mutex_init(&(priv->mutex), NULL);
	}
	return thiz;
}

static int locker_pthread_lock(Locker *thiz)
{
	PrivInfo *priv	= (PrivInfo *)thiz->priv;
	int ret = pthread_mutex_lock(&priv->mutex);
	return ret == 0 ? RET_OK : RET_FAIL;
}

static int locker_pthread_unlock(Locker *thiz)
{
	PrivInfo *priv	= (PrivInfo *)thiz->priv;
	int ret = pthread_mutex_unlock(&priv->mutex);
	return ret == 0 ? RET_OK : RET_FAIL;
}

static int locker_pthread_destroy(Locker *thiz)
{
	PrivInfo *priv	= (PrivInfo *)thiz->priv;
	int ret = pthread_mutex_destroy(&priv->mutex);
	SAFE_FREE(thiz);
	return ret == 0 ? RET_OK : RET_FAIL;
}
