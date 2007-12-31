/* 
 * OMFS in Fuse
 * (c) 2007 Bob Copeland
 * Released under GPL
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fuse.h>
#include <glib.h>
#include "omfs.h"

static omfs_info_t omfs_info;
static GHashTable *inode_cache;

#define min(a,b) ((a)<(b)?(a):(b))

struct inode_ref
{
    int refcount;
    omfs_inode_t *inode;
};

static inline void set_handle(struct fuse_file_info *fi, omfs_inode_t *inode)
{
    fi->fh = (long) inode;
}

static inline omfs_inode_t *get_handle(struct fuse_file_info *fi)
{
    return (omfs_inode_t *) (long) fi->fh;
}

static guint inode_cache_hash(gconstpointer key)
{
    return (int) *((u64*) key);
}

static gboolean inode_cache_compare(gconstpointer key, gconstpointer key2)
{
    return *((u64*)key) == *((u64*) key2);
}

static void cache_save_inode(omfs_inode_t *inode)
{
    omfs_write_inode(&omfs_info, inode);
}

static void cache_put_inode(omfs_inode_t *inode)
{
    struct inode_ref *ref;

    ref = g_hash_table_lookup(inode_cache, &inode->head.self);
    if (!ref)
        return;

    ref->refcount--;
    if (!ref->refcount)
    {
        g_hash_table_remove(inode_cache, &inode->head.self);
        omfs_release_inode(inode);
        free(ref);
    }
}

static struct inode_ref *cache_add_new_entry(omfs_inode_t *inode)
{
    struct inode_ref *ref;

    ref = malloc(sizeof(struct inode_ref));

    ref->refcount = 0;
    ref->inode = inode;
    g_hash_table_replace(inode_cache, &inode->head.self, ref);

    return ref;
}

static omfs_inode_t *cache_get_inode(u64 ino)
{
    struct inode_ref *ref;
    omfs_inode_t *inode = NULL;
    u64 tmp = swap_be64(ino);

    ref = g_hash_table_lookup(inode_cache, &tmp);
    if (!ref)
    {
        inode = omfs_get_inode(&omfs_info, ino);
        if (!inode) 
            goto out;

        ref = cache_add_new_entry(inode);
        if (!ref)
            goto out;
    }
    ref->refcount++;
    inode = ref->inode;
out:
    return inode;
}

static omfs_inode_t *cache_new_inode(omfs_info_t *info, u64 block, char *name, 
        char type)
{
    omfs_inode_t *new_inode = omfs_new_inode(info, block, name, type);
    if (!new_inode)
        return NULL;

    cache_add_new_entry(new_inode);
    return new_inode;
}


static omfs_inode_t *omfs_find_by_name(omfs_inode_t *parent, char *name)
{
    u64 next;
    omfs_inode_t *inode;
    u64 *chain_ptr = (u64*) ((u8*) parent + OMFS_DIR_START);

    chain_ptr += omfs_compute_hash(&omfs_info, name);
    next = swap_be64(*chain_ptr);
    while (next != ~0)
    {
        inode = cache_get_inode(next);
        if (!inode) 
            goto out;
        
        if (strcmp(inode->name,name) == 0)
            break;

        next = swap_be64(inode->sibling);
        cache_put_inode(inode);
    }

    if (next == ~0) 
        inode = NULL;
out:
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
    omfs_inode_t *inode = NULL, *tmp_inode;

    // starting at the root, find the inode of path
    if (path[0] == '/')
        path++;

    p = strdup(path);
    if (!p) 
        return NULL;

    inode = cache_get_inode(swap_be64(omfs_info.root->root_dir));

    tmp = strtok(p, "/");
    while (tmp && inode)
    {
        tmp_inode = omfs_find_by_name(inode, tmp);
        cache_put_inode(inode);
        inode = tmp_inode;
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
        stbuf->st_mode = S_IFREG | 0644;
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

            tmp = cache_get_inode(inum);
            if (!tmp)
                return -ENOENT;

            filler(buf, tmp->name, NULL, 0);
            sibling = tmp->sibling;

            cache_put_inode(tmp);
            while (sibling != ~0)
            {
                tmp = cache_get_inode(swap_be64(sibling));
                if (!tmp)
                    return -ENOENT;

                filler(buf, tmp->name, NULL, 0);
                sibling = tmp->sibling;
                cache_put_inode(tmp);
            }
        }
    }
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

    err = omfs_allocate_block(&omfs_info, swap_be32(omfs_info.super->mirrors), 
        &block);
    if (err)
        goto out1;

    new_inode = cache_new_inode(&omfs_info, block, file, type);
    if (!new_inode) {
        err = -ENOMEM;
        goto out1;
    }

    table = (u64*) ((u8*) parent + OMFS_DIR_START);
    hash = omfs_compute_hash(&omfs_info, file);

    new_inode->parent = parent->head.self;
    new_inode->sibling = table[hash];
    table[hash] = swap_be64(block);
    
    cache_save_inode(new_inode);
    cache_save_inode(parent);
    
out1:
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
    cache_save_inode(inode);
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

static u64 find_block(struct omfs_extent_entry **entry, u64 block, int count)
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

        inode = cache_get_inode(next);
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
        return omfs_get_block(&omfs_info, block);

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
        count = min(size-copied, blocksize-start);
        u8 *block = omfs_get_data_n(requested, fi);
        if (!block)
            goto out;
    
        memcpy(&buf[copied], block + start, count);
        free(block);
        start = 0;
    }
out:
    return copied;
}

static int omfs_utimens(const char *path, const struct timespec tv[2])
{
    omfs_inode_t *inode = omfs_lookup(path);

    if (!inode)
        return -ENOENT;

    u64 ctime = tv[1].tv_sec * 1000LL + tv[1].tv_nsec/1000;

    inode->ctime = swap_be64(ctime);
    cache_save_inode(inode);
    return 0;
}

// purge any empty rows and rewrite terminator
static void update_extent_table(struct omfs_extent *oe)
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

static int shrink_file(struct omfs_inode *inode, u64 size)
{
    struct omfs_extent *oe;
    struct omfs_extent_entry *entry, *term;
    int blocksize = swap_be32(omfs_info.super->blocksize);
    u64 requested = (size + blocksize-1)/ blocksize;
    u64 block;

    if (swap_be64(inode->size) == size) 
        goto out;

    block = omfs_find_location(requested, inode, &oe, &entry);

    inode->size = swap_be64(size);

    // already truncated...
    if (!block)
    {
        // FIXME fsx hits this case
        cache_save_inode(inode);
        goto out;
    }

    // entry points to the last valid extent, with num_blocks-(block-cluster)
    // blocks to free.  Then we free everything else and rebuild the current
    // terminator. 
    
    u64 to_delete = swap_be64(entry->blocks);
    entry->blocks = swap_be64(block - swap_be64(entry->cluster));
    to_delete -= swap_be64(entry->blocks);
    omfs_clear_range(&omfs_info, block, to_delete);
    entry++;

    for (;;) 
    {
        u64 next = swap_be64(oe->next);
        term = &oe->entry + swap_be32(oe->extent_count) - 1;
        while (entry != term) {
            omfs_clear_range(&omfs_info, swap_be64(entry->cluster), 
                swap_be64(entry->blocks));
            entry->blocks = 0;
            entry++;
        }
        
        // FIXME clear inode allocation bits here if needed...
        update_extent_table(oe);
        cache_save_inode(inode);

        if (next == ~0)
            break;

        cache_put_inode(inode);
        inode = cache_get_inode(next);
        if (!inode)
            goto out;
        oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_CONT);
    }
out:
    if (inode)
        cache_put_inode(inode); 
    return 0;
}

static int grow_extent(struct omfs_inode *inode, struct omfs_extent *oe,
                       struct omfs_extent_entry *entry, int *num_added)
{
    struct omfs_extent_entry *term;
    int ret=0, max_count, to_alloc;
    u64 new_block;
    term = &oe->entry + swap_be32(oe->extent_count) - 1;

    if (entry != term)
    {
        // try extending current extent
        new_block = swap_be64(entry->cluster) + swap_be64(entry->blocks);

        if (omfs_allocate_one_block(&omfs_info, new_block))
        {
            *num_added = 1;
            entry->blocks = swap_be64(swap_be64(entry->blocks) + 1);
            term->blocks = ~(swap_be64(swap_be64(~term->blocks) + 1));
            omfs_clear_data(&omfs_info, new_block, 1);
            goto out;
        }
    }
    max_count = swap_be32(omfs_info.super->sys_blocksize) - 
        OMFS_EXTENT_START - sizeof(struct omfs_extent) /
        sizeof(struct omfs_extent_entry) + 1; 

    if (swap_be32(oe->extent_count) > max_count-1) {
        // no more room, add to next ptr...
        ret = -EIO;
        goto out_fail;
    }

    to_alloc = swap_be32(omfs_info.root->clustersize);
    ret = omfs_allocate_block(&omfs_info, to_alloc, &new_block);

    if (ret)
        goto out_fail;

    omfs_clear_data(&omfs_info, new_block, to_alloc);
    oe->extent_count = swap_be32(1 + swap_be32(oe->extent_count));

    entry = term;
    term++;
    memcpy(term, entry, sizeof(struct omfs_extent_entry));

    *num_added = to_alloc;
    entry->cluster = swap_be64(new_block);
    entry->blocks = swap_be64(*num_added);

    term->blocks = ~(swap_be64(swap_be64(~term->blocks) + *num_added));
    
    cache_save_inode(inode);
out:
out_fail:
    return ret;
}

static int grow_file(struct omfs_inode *inode, u64 size)
{
    struct omfs_extent *oe;
    struct omfs_extent_entry *entry;
    int ret, i;
    int num_added;

    int blocksize = swap_be32(omfs_info.super->blocksize);
    u64 cur_blks = (swap_be64(inode->size) + blocksize-1) / blocksize;
    u64 requested = (size + blocksize-1) / blocksize;

    assert (size > swap_be64(inode->size));
    
    omfs_find_location(requested, inode, &oe, &entry);

    // entry points to terminator after last valid extent
    if (entry != &oe->entry)
        entry--;

    for (i=0; i < requested - cur_blks; i += num_added)
    {
        ret = grow_extent(inode, oe, entry, &num_added);
        if (ret)
            return ret;
    }
    
    inode->size = swap_be64(size);
    cache_save_inode(inode);

    return 0;
}

static int _truncate(omfs_inode_t *inode, off_t new_size)
{
    u64 old_size = swap_be64(inode->size);

    if (new_size <= old_size)
        return shrink_file(inode, new_size);

    return grow_file(inode, new_size);
}

static int omfs_truncate(const char *path, off_t new_size)
{
    omfs_inode_t *inode = omfs_lookup(path);

    if (!inode)
        return -ENOENT;

    return _truncate(inode, new_size);
}

static int omfs_ftruncate(const char *path, off_t new_size, 
      struct fuse_file_info *fi)
{
    omfs_inode_t *inode = get_handle(fi);
    if (!inode)
        return -ENOENT;

    return _truncate(inode, new_size);
}

static int omfs_unlink (const char *path)
{
    omfs_inode_t *last, *next;
    u64 *chain_ptr;
    u64 to_clear;
    omfs_inode_t *inode = omfs_lookup(path);
    int ret = 0;

    if (!inode)
        return -ENOENT;

    next = cache_get_inode(swap_be64(inode->parent));
    if (!next)
        return -ENOENT;

    chain_ptr = (u64*) ((u8*) next + OMFS_DIR_START);
    chain_ptr += omfs_compute_hash(&omfs_info, inode->name);

    last = next;
    while (*chain_ptr != ~0)
    {
        next = cache_get_inode(swap_be64(*chain_ptr));
        if (!next) {
            ret = -ENOENT;
            goto out;
        }
        if (strcmp(next->name,inode->name) == 0)
        {
            *chain_ptr = next->sibling;
            cache_save_inode(last);
            cache_put_inode(last);
            break;
        }
        chain_ptr = &next->sibling;
        cache_put_inode(last);
        last = next;
    }
    cache_put_inode(next);

    to_clear = swap_be64(inode->head.self);
    shrink_file(inode, 0);

    omfs_clear_range(&omfs_info, to_clear,
        swap_be32(omfs_info.super->mirrors));
out:
    return ret;
}

static int omfs_statfs(const char *path, struct statvfs *buf)
{
    buf->f_fsid = OMFS_MAGIC;
    buf->f_bsize = swap_be32(omfs_info.super->blocksize);
    buf->f_frsize = buf->f_bsize;
    buf->f_blocks = swap_be64(omfs_info.super->num_blocks);
    buf->f_files = buf->f_blocks;
    buf->f_namemax = OMFS_NAMELEN;

    buf->f_bfree = buf->f_bavail = buf->f_ffree = 
        omfs_count_free(&omfs_info);

    return 0;
}

static int omfs_write(const char *path, const char *buf, size_t size, 
          off_t offset, struct fuse_file_info *fi)
{
    struct omfs_extent *oe;
    struct omfs_extent_entry *entry;
    int blocksize = swap_be32(omfs_info.super->blocksize);
    u64 requested = offset / blocksize;
    int start = offset % blocksize;
    int count;
    int copied = 0;
    u8 *data;

    omfs_inode_t *inode = get_handle(fi);
    if (!inode)
        return -ENOENT;

    for (; copied < size ; copied += count, requested++)
    {
        count = min(size-copied, blocksize-start);

        u64 block = omfs_find_location(requested, inode, &oe, &entry);
        if (!block) {
            u64 new_size = size + offset;
            if (new_size < swap_be64(inode->size))
                goto out;

            if (grow_file(inode, new_size))
                goto out;

            block = omfs_find_location(requested, inode, &oe, &entry);
            if (!block)
                goto out;
        }

        data = omfs_get_block(&omfs_info, block);
        if (!data)
            goto out;
    
        memcpy(data + start, buf + copied, count);
        omfs_write_block(&omfs_info, block, data);
        free(data);
        start = 0;
    }
out:
    if (copied + offset > swap_be64(inode->size))
    {
        inode->size = swap_be64(copied + offset);
        cache_save_inode(inode);
    }
    return copied;
}

static struct fuse_operations omfs_op = {
    .getattr    = omfs_getattr,
    .readdir    = omfs_readdir,
    .open       = omfs_open,
    .read       = omfs_read,
    .write      = omfs_write,
    .rename     = omfs_rename,
    .mknod      = omfs_mknod,
    .mkdir      = omfs_mkdir,
    .utimens    = omfs_utimens,
    .statfs     = omfs_statfs,
    .truncate   = omfs_truncate,
    .ftruncate  = omfs_ftruncate,
    .unlink     = omfs_unlink,
};

int main(int argc, char *argv[])
{
    omfs_super_t super;
    omfs_root_t root;
    char *device = NULL;
    int i, is_swapped, fuse_argc=0;

    char **fuse_argv = malloc(argc * sizeof(char *));

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

    if (omfs_read_super(fp, &super, &is_swapped))
    {
        printf ("Could not read super block\n");
        return 3;
    }

    if (omfs_read_root_block(fp, &super, is_swapped, &root))
    {
        printf ("Could not read root block\n");
        return 4;
    }

    omfs_info.dev = fp;
    omfs_info.super = &super;
    omfs_info.root = &root;
    omfs_info.swap = is_swapped;

    inode_cache = g_hash_table_new(inode_cache_hash, inode_cache_compare);

    return fuse_main(fuse_argc, fuse_argv, &omfs_op, NULL);
}
