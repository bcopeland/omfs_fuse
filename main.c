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
        omfs_release_inode(inode);
    }
    if (ino == ~0)
        return NULL;
    return inode;
}

/*
 * Split path into directory and filename portions.
 * Caller must free the returned pointer.
 */
static char *split_path(const char *path, char **basename, char **dirname)
{
    char *p, *dir, *file;

    p = strdup(path);
    if (!p) 
        return NULL;

    dir = p;
    file = strrchr(p, '/');

    if (file) {
        *file++ = 0;
    } else {
        file = p;
        dir = file + strlen(file);
    }
    *basename = dir;
    *dirname = file;
    return p;
}

static omfs_inode_t *omfs_lookup(const char *path)
{
    char *tmp, *p;
    omfs_inode_t *inode = NULL;

    // starting at the root, find the inode of path
    if (path[0] == '/')
        path++;

    p = strdup(path);
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
    u64 ctime;
    struct fuse_context *ctx;

    omfs_inode_t *inode = omfs_lookup(path);
    if (!inode)
        return -ENOENT;

    ctx = fuse_get_context();
    memset(stbuf, 0, sizeof (struct stat));
    if (inode->type == OMFS_DIR) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = swap_be64(inode->size);
    }
   
    ctime = swap_be64(inode->ctime) / 1000L; 
    stbuf->st_ctime = stbuf->st_mtime = ctime;
    stbuf->st_uid = ctx->uid;
    stbuf->st_gid = ctx->gid;
   
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

static int _add_inode(const char *path, char type)
{
    char *dir, *file, *tmp;
    u64 block, *table;
    omfs_inode_t *parent, *new_inode;
    int hash;
    int err = 0;

    tmp = split_path(path, &dir, &file);
    if (!tmp)
        return -ENOMEM;

    parent = omfs_lookup(dir);
    if (!parent) {
        err = -ENOENT;
        goto out2;
    }

    err = omfs_allocate_block(&omfs_info, &block);
    if (err)
        goto out1;

    new_inode = omfs_new_inode(&omfs_info, block, file, type);
    if (!new_inode) {
        err = -ENOMEM;
        goto out1;
    }

    table = (u64*) ((u8*) parent + OMFS_DIR_START);
    hash = omfs_compute_hash(&omfs_info, file);

    new_inode->parent = parent->head.self;
    new_inode->sibling = table[hash];
    table[hash] = swap_be64(block);
    
    omfs_write_inode(&omfs_info, new_inode);
    omfs_write_inode(&omfs_info, parent);
    
    omfs_release_inode(new_inode);
out1:
    omfs_release_inode(parent);
out2:
    free(tmp);
    return err;
}

static int omfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    return _add_inode(path, OMFS_FILE);
}

static int omfs_mkdir(const char *path, mode_t mode)
{
    return _add_inode(path, OMFS_DIR);
}


static int omfs_rename(const char *old, const char *new)
{
    omfs_inode_t *inode = omfs_lookup(old);
    char *tmp, *dir, *file;

    if (!inode)
        return -ENOENT;

    tmp = split_path(new, &dir, &file);

    // FIXME - add cross dir rename
    strncpy(inode->name, file, OMFS_NAMELEN);
    inode->name[OMFS_NAMELEN-1] = 0;
    omfs_write_inode(&omfs_info, inode);
    omfs_release_inode(inode);
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

static int find_block(struct omfs_extent_entry **entry, u64 block, int count)
{
    u64 searched = 0;
    for (; count > 1; count--)
    {
        u64 numblocks = swap_be64((*entry)->blocks);
        if (block >= searched && block < searched + numblocks) 
            return swap_be64((*entry)->cluster) + block - searched;
        
        searched += numblocks;
        (*entry)++;
    }
    return 0;
}

/*
 *  Given an offset into a file, find the extent table and entry 
 *  containing the location.  Return the fs block of the location.
 */
static u64 omfs_find_location(u64 requested, omfs_inode_t *inode, 
            struct omfs_extent **ret_oe, struct omfs_extent_entry **ret_entry)
{
    struct omfs_extent_entry *entry;
    struct omfs_extent *oe;
    u64 found_block = 0;

    oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_START);

    for (;;)
    {
        int extent_count = swap_be32(oe->extent_count);
        u64 next = swap_be64(oe->next);
        entry = &oe->entry;

        found_block = find_block(&entry, requested, extent_count);
        if (found_block > 0)
            goto out;

        if (next == ~0)
            break;

        inode = omfs_get_inode(&omfs_info, next);
        oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_CONT);
    }
out:
    *ret_entry = entry;
    *ret_oe = oe;
    return found_block;
}

static u8 *omfs_get_data_n(u64 requested, struct fuse_file_info *fi)
{
    struct omfs_extent *oe;
    struct omfs_extent_entry *entry;

    omfs_inode_t *inode = get_handle(fi);

    u64 block = omfs_find_location(requested, inode, &oe, &entry);

    if (block > 0)
        return omfs_get_block(omfs_info.dev, omfs_info.super, block);

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

static int omfs_utimens(const char *path, const struct timespec tv[2])
{
    omfs_inode_t *inode = omfs_lookup(path);

    if (!inode)
        return -ENOENT;

    u64 ctime = tv[1].tv_sec * 1000LL + tv[1].tv_nsec/1000;

    inode->ctime = swap_be64(ctime);
    omfs_write_inode(&omfs_info, inode);
    omfs_release_inode(inode);
    return 0;
}

#if 0
static int truncate(const char *path, off_t new_size)
{
    u8 *buf;
    u64 old_size;
    omfs_inode_t *inode = omfs_lookup(path);

    if (!inode)
        return -ENOENT;

    old_size = swap_be64(inode->size);
    buf = (u8*) inode;

    if (old_size < new_size)
    {
        grow_file(inode, new_size);
    }
    else
    {
        inode->size = swap_be64(new_size);
    }
}

// purge any empty rows and rewrite terminator
static void update_extent_table(omfs_extent *oe)
{
    struct omfs_extent_entry *entry;
    int count = 0, total_extents = 1, remaining;

    entry = &oe->entry;
    remaining = swap_be32(oe->extent_count);

    for (; remaining > 1; remaining--)
    {
        u64 num_blocks = swap_be64(entry->blocks);
        count += num_blocks;
        if (num_blocks == 0)
            memcpy(entry, entry + 1, 
                sizeof(struct omfs_extent_entry) * remaining);
        else {
            total_extents++;
            entry++;
        }
    }
    // entry points at terminator
    entry->blocks = swap_be64(~count);
    oe->extent_count = swap_be32(total_extents);
}

static int shrink_file(struct inode *inode, u64 size)
{
    struct omfs_extent *oe;
    struct omfs_extent_entry *entry;
    int blocksize = swap_be32(omfs_info.super->blocksize);
    u64 requested = offset / blocksize;
    int start = offset % blocksize;
    int count;
    int copied = 0;

    if (!omfs_find_location(requested, inode, &oe, &entry))
        return -ENOENT;

}
#endif


static struct fuse_operations omfs_op = {
    .getattr    = omfs_getattr,
    .readdir    = omfs_readdir,
    .open       = omfs_open,
    .read       = omfs_read,
    .rename     = omfs_rename,
    .mknod      = omfs_mknod,
    .mkdir      = omfs_mkdir,
    .utimens    = omfs_utimens,
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

    FILE *fp = fopen(device, "rb+");
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

    return fuse_main(fuse_argc, fuse_argv, &omfs_op, NULL);
}
