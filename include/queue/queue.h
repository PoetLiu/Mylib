#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

struct _Queue;
typedef struct _Queue Queue;
Queue *init_queue();
int empty_queue(Queue *);
int en_queue(Queue *, void *, int );
int de_queue(Queue *, void *, int *, int);
int destroy_queue(Queue *);
void travel_queue(Queue *, const char);

#endif // __QUEUE_H__
