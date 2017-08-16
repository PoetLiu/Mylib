#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "mylib.h"

typedef struct _Node
{
	int dlen;		// 数据长度
	void *data;		// 数据
	struct _Node *pNext;	// 下一个节点
	struct _Node *pPre;	// 上一个节点
}Node;

struct _Queue
{
	Node *front;		// 队列中第一个元素
	Node *rear;		// 队列中最后一个元素
	unsigned int length;	// 队列长度
	pthread_mutex_t lock;	// 互斥锁
};


/*--------------------------------------------
 * Node1.pNext->Node2.pNext->Node3.pNext->NULL
 *   |	 		       | 		
 *  rear 		     front
 *--------------------------------------------
*/

Queue *init_queue()
{
	Queue *new_q = NULL;
	new_q	= (Queue *)malloc(sizeof(Queue));
	P_VALID_RET(new_q, NULL);

	new_q->front	= NULL;
	new_q->rear	= NULL;
	new_q->length	= 0;
	pthread_mutex_init(&new_q->lock, NULL);

	return new_q;
}

int empty_queue(Queue *pQueue)
{
	unsigned int len = 0;

	P_VALID_RET(pQueue, 1);
	pthread_mutex_lock(&pQueue->lock);
	len	= pQueue->length;
	pthread_mutex_unlock(&pQueue->lock);

	return len == 0;
}

static int _empty_queue(Queue *pQueue)
{
	return pQueue->length == 0;
}

// 入队， 从队列末尾添加一个节点
int en_queue(Queue *pQueue, void *data, int dlen)
{
	Node *new_node = NULL;
	// param check
	P_VALID_RET(pQueue, -1);
	P_VALID_RET(data, -1);

	// get new_node
	new_node	= (Node *)malloc(sizeof(Node));
	P_VALID_RET(new_node, -1);
	new_node->data	= (void *)malloc(dlen);
	if (new_node->data == NULL) {
		SAFE_FREE(new_node);
		return -1;
	}
	memcpy(new_node->data, data, dlen);
	new_node->dlen	= dlen;
	new_node->pPre	= NULL;
	new_node->pNext	= NULL;

	pthread_mutex_lock(&pQueue->lock);
	// add to queue
	if (!pQueue->rear) {
		pQueue->rear	= new_node;
	} else {
		new_node->pNext		= pQueue->rear;
		pQueue->rear->pPre	= new_node;
		pQueue->rear		= new_node;
	}

	if (!pQueue->front)
		pQueue->front	= new_node;

	pQueue->length++;
	pthread_mutex_unlock(&pQueue->lock);

	return 0;
}

// node->date maybe NULL, if user used cp_flag=0 when call de_queue
static int free_node(Node *node)
{
	P_VALID_RET(node, -1);
	SAFE_FREE(node->data);
	SAFE_FREE(node);
	return 0;
}

// 如果copy 值为1， Node出队时， 其Node->data将会被拷贝至data实参
// 调用者应该保证data所指向的空间足够大
// 如果copy 值为0， NOde出队时， 仅仅复制Node->data的指针给data实参
// 调用者应该负责data的内存释放
int de_queue(Queue *pQueue, void *data, int *dlen, int cp_flag)
{
	Node *de_node = NULL;
	int ret = 0;
	P_VALID_RET(pQueue, -1);
	
	pthread_mutex_lock(&pQueue->lock);
	if (_empty_queue(pQueue)) {
		ret	= -2;
		goto ret_l;
	}

	de_node	= pQueue->front;
	if (data) {
		if (cp_flag) {
			memcpy(data, de_node->data, de_node->dlen);
		} else {
			*(void **)data	= de_node->data;
			de_node->data	= NULL;
		}
	}
	if (dlen)
		*dlen	= de_node->dlen;
	if (de_node->pPre)
		de_node->pPre->pNext = NULL;
	if (pQueue->rear == de_node)
		pQueue->rear	= NULL;

	pQueue->front	= de_node->pPre;
	pQueue->length--;
	ret		= free_node(de_node);

ret_l:
	pthread_mutex_unlock(&pQueue->lock);
	return ret;
}

// fmt:
// d	十进制整数输出	
// s	字符串输出
static void print_data(void *buf, int blen, const char fmt)
{
	int i;

	switch (fmt) {
		case 'd':
			for (i = 0; i < blen; i+=sizeof(int))
				printf("%d ", *((int *)((char *)buf + i)));
			break;
		case 's':
			printf("%s", (char *)buf);
			break;
		default:
			break;
	}
	printf(" len:%d\n", blen);
}

// print Node data from queue front to rear
void travel_queue(Queue *pQueue, const char fmt)
{

	Node *p_node = NULL;
	printf("Queue:\n");
	if (empty_queue(pQueue))
		printf("empty\n");

	pthread_mutex_lock(&pQueue->lock);
	p_node	= pQueue->front;
	while (p_node) {
		print_data(p_node->data, p_node->dlen, fmt);		
		p_node	= p_node->pPre;	
	}
	pthread_mutex_unlock(&pQueue->lock);
}

int destroy_queue(Queue *pQueue)
{
	Node *de_node = NULL, *de_node_pre = NULL;
	P_VALID_RET(pQueue, -1);
	if (empty_queue(pQueue)) 
		goto free_out;

	pthread_mutex_lock(&pQueue->lock);
	de_node	= pQueue->front;
	while (de_node) {
		de_node_pre	= de_node->pPre ? de_node->pPre : NULL;
		free_node(de_node);
		de_node		= de_node_pre;
	}
	pthread_mutex_unlock(&pQueue->lock);

free_out:
	pthread_mutex_destroy(&pQueue->lock);
	SAFE_FREE(pQueue);
	return 0;
}

