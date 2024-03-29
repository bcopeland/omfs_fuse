#ifndef _OMFS_H
#define _OMFS_H

#include "config.h"
#include <stdio.h>

#define OMFS_MAGIC 0xC2993D87
#define OMFS_IMAGIC 0xD2

#define OMFS_DIR 'D'
#define OMFS_FILE 'F'
#define OMFS_INODE_NORMAL 'e'
#define OMFS_INODE_CONTINUATION 'c'
#define OMFS_INODE_SYSTEM 's'
#define OMFS_SUPER_NAMELEN 64
#define OMFS_NAMELEN 256
#define OMFS_DIR_START 0x1b8
#define OMFS_EXTENT_START 0x1d0
#define OMFS_EXTENT_CONT 0x40
#define OMFS_XOR_COUNT 19


struct omfs_info {
	FILE *dev;
	struct omfs_super_block *super;
	struct omfs_root_block *root;
    struct omfs_bitmap *bitmap;
	int swap;
    pthread_mutex_t dev_mutex;
};

struct omfs_super_block {
	char fill1[192];
	char name[OMFS_SUPER_NAMELEN];
	u64 root_block;
	u64 num_blocks;
	u32 magic;
	u32 blocksize;
	u32 mirrors;
	u32 sys_blocksize;
};

struct omfs_header {
	u64 self;
	u32 body_size;
	u16 crc;
	char fill1[2];
	u8 version;
	char type;
	u8 magic;
	u8 check_xor;
	u32 fill2;
};

struct omfs_root_block {
	struct omfs_header head;
	u64 fill1;
	u64 num_blocks;
	u64 root_dir;
	u64 bitmap;
	u32 blocksize;
	u32 clustersize;
	u64 mirrors;
	char name[OMFS_NAMELEN];
	u64 fill2;
};

struct omfs_inode {
	struct omfs_header head;
	u64 parent;
	u64 sibling;
	u64 ctime;
	char fill1[35];
	char type;
	u32 one_goes_here;
	char fill3[64];
	char name[OMFS_NAMELEN];
	u64 size;
};

struct omfs_extent_entry {
	u64 cluster;
	u64 blocks;
};
	
struct omfs_extent {
	u64 next;
	u32 extent_count;
	u32 fill;
	struct omfs_extent_entry entry;
};

struct omfs_bitmap {
    u8 *dirty;
    u8 *bmap;
};

typedef struct omfs_info omfs_info_t;
typedef struct omfs_header omfs_header_t;
typedef struct omfs_super_block omfs_super_t;
typedef struct omfs_root_block omfs_root_t;
typedef struct omfs_inode omfs_inode_t;

int omfs_read_super(omfs_info_t *info);
int omfs_write_super(omfs_info_t *info);
int omfs_read_root_block(omfs_info_t *info);
int omfs_write_root_block(omfs_info_t *info);
u8 *omfs_get_block(omfs_info_t *info, u64 block);
int omfs_write_block(omfs_info_t *info, u64 block, u8* buf);
void omfs_release_block(u8 *buf);
int omfs_check_crc(u8 *blk);
omfs_inode_t *omfs_get_inode(omfs_info_t *info, u64 block);
int omfs_write_inode(omfs_info_t *info, omfs_inode_t *inode);
void omfs_release_inode(omfs_inode_t *inode);
void omfs_sync(omfs_info_t *info);
int omfs_load_bitmap(omfs_info_t *info);
int omfs_flush_bitmap(omfs_info_t *info);
int omfs_compute_hash(omfs_info_t *info, char *filename);
omfs_inode_t *omfs_new_inode(omfs_info_t *info, u64 block, char *name, 
    char type);
void omfs_clear_data(omfs_info_t *info, u64 block, int count);

/* bitmap.c */
int omfs_allocate_one_block(omfs_info_t *info, u64 block);
int omfs_allocate_block(omfs_info_t *info, int size, u64 *return_block);
int omfs_clear_range(omfs_info_t *info, u64 start, int count);
unsigned long omfs_count_free(omfs_info_t *info);

#endif
