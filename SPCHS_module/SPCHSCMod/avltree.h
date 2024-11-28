//
//  Searchable Public-Key Ciphertexts with Hidden Structures
//  Coding: Shuanghong he, CS School of HUST
//  E-mail: 740310627@qq.com
//  Date  : 2016-4-18
//  Copyright (c) 2016 Render. All Rights Reserved.
//
#include <linux/types.h>
#ifndef HEADER_AVLTREE_
#define HEADER_AVLTREE_

#define PRE_TRS 0 // pre  order traverse
#define MID_TRS 1 // mid  order traverse
#define BCK_TRS 2 // back order traverse

#define max_int(a, b) ((a)>(b) ? (a) : (b))


/* tree node */
typedef struct _Pri_data
{
  unsigned char sha_W[32];
  unsigned char Pt_u_W[512];
	unsigned int Pt_u_W_len;
//this attr just using in case 1
	unsigned char Pt_u_W_n[512];
	unsigned int Pt_u_W_n_len;
} Pri_data;
typedef struct _avl_node
{
	struct _avl_node* left;
	struct _avl_node* right;
	struct _avl_node* parent;
	int               height; // height of node, used to balance the avl tree
	Pri_data * 		  data;   // point to the buffer where data is stored
} avl_node;

typedef int  (*_avl_cmp) (void*, void*); // data compare function
typedef void (*_avl_trs) (void*, int  ); // tree traverse function

/* tree handle */
typedef struct _avl_Handle
{
	avl_node* root;      // tree root node
	unsigned int    data_size; // data buffer size
	_avl_cmp  avl_cmp;   // data compare function
} avl_handle;

extern avl_handle* avl_init    ( unsigned int data_size, _avl_cmp acmp );
extern void        avl_free    ( avl_handle* handle );
extern int         avl_add     ( avl_handle* handle, void* data );
extern int         avl_delete  ( avl_handle* handle, void* key );
extern void*       avl_find    ( avl_handle* handle, void* key );
extern void        avl_traverse( avl_handle* handle,
								 int order, _avl_trs avl_trs );

#endif
