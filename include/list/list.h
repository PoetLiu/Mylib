#ifndef _LIST_H
#define _LIST_H
#include <stdio.h>

#define list_for_each_node(head, node)		\
	for (node = (head)->next; node != (head); node = node->next)

#define list_for_each_node_safe(head, node, p)	\
	for (node = (head)->next, p = node->next; node != (head); node = p, p = p->next)

#define list_from_start_safe(head, start, node, p)	\
	for (node = start, p = node->next; node != (head); node = p, p = p->next)


struct _Node;
typedef struct _Node* PNode;
typedef struct _Node Node;
typedef struct _Node Dlist;

enum {
	DLIST_SORT_ASC, 	// 升序排列
	DLIST_SORT_DESC,	// 降序排列
}DLIST_SORT_ORDER;

typedef int(*NODE_FILTER)(void *);
typedef int(*NODE_HANDLE)(void *, void *);
typedef int(*NODE_SORT_HANDLE)(void *, void *, const int);
typedef NODE_HANDLE NODE_VISIT_HANDLE;

extern PNode dlist_create(void);
extern PNode dlist_head_init(PNode, Locker *);
extern PNode dlist_add_new(const PNode, void *data);
extern PNode dlist_add_tail_new(const PNode, void *data);
extern int dlist_append(const PNode, void *data);
extern int dlist_prepend(const PNode, void *data);
extern int dlist_empty(const PNode );
extern int dlist_length(const PNode );
extern int dlist_destroy(const PNode, NODE_HANDLE, void *);
extern int dlist_sort(const PNode, const NODE_SORT_HANDLE, const int);
extern int dlist_find_max(const PNode , NODE_VISIT_HANDLE, void *);
extern int dlist_sum(const PNode , NODE_VISIT_HANDLE, void *);
extern int dlist_print(const PNode , NODE_VISIT_HANDLE);
extern int dlist_foreach(const PNode , NODE_VISIT_HANDLE, void *);
extern int dlist_del_by_filter(PNode, NODE_HANDLE, void *, NODE_FILTER);
extern PNode dlist_find(const PNode head, NODE_HANDLE cmp, void *ctx);
#endif	// _LIST_H
