#ifndef _MEM_H_
#define _MEM_H_
#include <stdio.h>
#include "debug.h"

#define IS_NULL(p)			(p == NULL)
#define P_VALID_CHECK_ACT(p, act)	{if (IS_NULL(p)) {DEBUG(#p" is NULL\n");act;}}
#define P_VALID_CHECK_RET(p, ret)     	P_VALID_CHECK_ACT(p, return ret) 

#define P_VALID(p)                	(p!=NULL)
#define P_VALID_ACT(p, act)       	{if (!P_VALID(p)){DEBUG("param "#p" is NULL!\n");act;}}
#define P_VALID_RET(p, ret)       	P_VALID_ACT(p, return ret)
#define P_VALID_GOTO(p, label)		P_VALID_ACT(p, goto label)
#define P_VALID_GOTO_SET(p, err, label)	{if (!P_VALID(p)){DEBUG("param "#p" is NULL!\n");ret=err;goto label;}}

#define BOOL_CK_GOTO_SET(v, err, label) {if (v){DEBUG(""#v" is True!\n");ret=err;goto label;}}
#define BOOL_CK_GOTO(v, label) 		{if (v){DEBUG(""#v" is True!\n");goto label;}}

#define SAFE_FREE(p)			{if (!IS_NULL(p)){ free(p);p = NULL;}}
#define ARRAY_SIZE_GET(a)		(sizeof(a)/sizeof(a[0]))

#endif	// _MEM_H



