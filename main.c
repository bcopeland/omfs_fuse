/* 
 * OMFS in Fuse 
 * (c) 2007 Bob Copeland
 * Released under GPL
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fuse.h>
#include "omfs.h"

static omfs_info_t omfs_info;

#define min(a,b) ((a)<(b)?(a):(b))

static inline void set_handle(struct fuse_file_info *fi, omfs_inode_t *inode)
{
    fi->fh = (uint64_t) inode;
}

static inline omfs_inode_t *get_handle(struct fuse_file_info *fi)
{
    return (omfs_inode_t *) fi->fh;
}

static omfs_inode_t *omfs_find_by_name(omfs_inode_t *parent, char *name)
{
    omfs_inode_t *inode = NULL;
    u64 ino;
    int hash = omfs_compute_hash(&omfs_info, name);
    u64 *table = (u64*) ((u8*) parent + OMFS_DIR_START);

    ino = swap_be64(table[hash]);
    while (ino != ~0)
    {
        inode = omfs_get_inode(&omfs_info, ino);
        if (strcmp(inode->name,name) == 0)
            break;
        ino = swap_be64(inode->sibling);
    }
    return inode;
}

static omfs_inode_t *omfs_lookup(const char *path)
{
    char *tmp, *p;
    omfs_inode_t *inode = NULL;

    // starting at the root, find the inode of path
    p = strdup(path + 1);
    if (!p) 
        return NULL;

    inode = omfs_get_inode(&omfs_info, swap_be64(omfs_info.root->root_dir));

    tmp = strtok(p, "/");
    while (tmp && inode)
    {
        printf ("lu: %s\n", tmp);
        inode = omfs_find_by_name(inode, tmp);
        tmp = strtok(NULL, "/");
    }
    free(p);
    return inode;
}

static int omfs_getattr(const char *path, struct stat *stbuf)
{
    omfs_inode_t *inode = omfs_lookup(path);
    if (!inode)
        return -ENOENT;

    memset(stbuf, 0, sizeof (struct stat));
    if (inode->type == OMFS_DIR) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = swap_be64(inode->size);
    }
    return 0;
}

static int omfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    int num_entries, i;
    u64 *ptr;
    omfs_inode_t *dir, *tmp;

    dir = omfs_lookup(path);
    if (!dir)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
   
    num_entries = (swap_be32(dir->head.body_size) + 
        sizeof(omfs_header_t) - OMFS_DIR_START) / 8;
    ptr = (u64*) ((u8*) dir + OMFS_DIR_START);

    for (i=0; i<num_entries; i++, ptr++)
    {
        u64 inum = swap_be64(*ptr);
        if (inum != ~0)
        {
            u64 sibling;

            tmp = omfs_get_inode(&omfs_info, inum);
            if (!tmp)
                return -ENOENT;

            filler(buf, tmp->name, NULL, 0);
            sibling = tmp->sibling;
            omfs_release_inode(tmp);

            while (sibling != ~0)
            {
                tmp = omfs_get_inode(&omfs_info, swap_be64(sibling));
                if (!tmp)
                    return -ENOENT;

                filler(buf, tmp->name, NULL, 0);
                sibling = tmp->sibling;
                omfs_release_inode(tmp);
            }
        }
    }
    omfs_release_inode(dir);
    return 0;
}

static int omfs_open (const char *path, struct fuse_file_info *fi)
{
    omfs_inode_t *inode = omfs_lookup(path);

    if (!inode)
        return -ENOENT;

    set_handle(fi, inode);
    return 0;
}

static u64 find_block(struct omfs_extent_entry *entry, u64 block, int count)
{
    u64 searched = 0;
    for (; count > 1; count--)
    {
        u64 numblocks = swap_be64(entry->blocks);
        if (block >= searched && block < searched + numblocks) 
            return swap_be64(entry->cluster) + block - searched;
        
        searched += numblocks;
        entry++;
    }
    return 0;
}

static u8 *omfs_get_data_n(u64 requested, struct fuse_file_info *fi)
{
    omfs_inode_t *inode = get_handle(fi);

    struct omfs_extent_entry *entry;
    struct omfs_extent *oe;

    oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_START);

    for (;;)
    {
        int extent_count = swap_be32(oe->extent_count);
        u64 next = swap_be64(oe->next);
        entry = &oe->entry;

        u64 block = find_block(entry, requested, extent_count);
        if (block == 0)
            return NULL;

        return omfs_get_block(omfs_info.dev, omfs_info.super, block);

        if (next == ~0)
            break;

        inode = omfs_get_inode(&omfs_info, next);
        oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_CONT);
    }
    return NULL;
}

static int omfs_read (const char *path, char *buf, size_t size, off_t offset, 
          struct fuse_file_info *fi)
{
    int blocksize = swap_be32(omfs_info.super->blocksize);
    u64 requested = offset / blocksize;
    int start = offset % blocksize;
    int count;
    int copied = 0;

    for (; copied < size ; copied += count, requested++)
    {
        count = min(size, blocksize-start);
        u8 *block = omfs_get_data_n(requested, fi);
        if (!block)
            return -EIO;
    
        memcpy(&buf[copied], block, count);
        free(block);
        start = 0;
    }
    return copied;
}


static struct fuse_operations omfs_op = {
    .getattr    = omfs_getattr,
    .readdir    = omfs_readdir,
    .open       = omfs_open,
    .read       = omfs_read,
};

int main(int argc, char *argv[])
{
    omfs_super_t super;
    omfs_root_t root;
    char *device = NULL;
    int i, fuse_argc=0;

    char **fuse_argv = malloc(argc * sizeof(char));

    for (i=0; i < argc; i++)
    {
        if ((strcmp(argv[i], "-a") == 0) && i + 1 < argc)
        {   
            i++;
            device = argv[i];
        }
        else 
            fuse_argv[fuse_argc++] = argv[i];
    }
    fuse_argv[fuse_argc] = NULL;

    if (!device)
    {
        fprintf(stderr, "Usage: %s -a <device_file> <mount_point>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(device, "rb");
    if (!fp)
    {
        perror("fuse_omfs");
        return 2;
    }

    if (omfs_read_super(fp, &super))
    {
        printf ("Could not read super block\n");
        return 3;
    }
    if (omfs_read_root_block(fp, &super, &root))
    {
        printf ("Could not read root block\n");
        return 4;
    }

    omfs_info.dev = fp;
    omfs_info.super = &super;
    omfs_info.root = &root;

    return fuse_main(fuse_argc, fuse_argv, &omfs_op);
}
