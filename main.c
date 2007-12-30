/* 
 * Released under GPL
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fuse.h>
#include "omfs.h"

static omfs_info_t omfs_info;

#define min(a,b) ((a)<(b)?(a):(b))

static inline void set_handle(struct fuse_file_info *fi, omfs_inode_t *inode)
{
    fi->fh = (long) inode;
}

static inline omfs_inode_t *get_handle(struct fuse_file_info *fi)
{
    return (omfs_inode_t *) (long) fi->fh;
}

/*
 *  Caller must free returned pointer.
 */
static omfs_inode_t *omfs_find_node_ptr(u64 parent_ino, char *name, 
        omfs_inode_t **owner, u64 **entry)
{
    omfs_inode_t *last, *inode = omfs_get_inode(&omfs_info, parent_ino);
    u64 *chain_ptr = (u64*) ((u8*) inode + OMFS_DIR_START);

    *owner = NULL;
    *entry = NULL;

    last = inode;
    if (!inode)
        return NULL;

    chain_ptr += omfs_compute_hash(&omfs_info, name);
    while (*chain_ptr != ~0)
    {
        inode = omfs_get_inode(&omfs_info, swap_be64(*chain_ptr));
        if (!inode) 
            goto out;
        
        if (strcmp(inode->name,name) == 0)
            break;

        chain_ptr = &inode->sibling;
        omfs_release_inode(last);
        last = inode;
    }

    if (*chain_ptr == ~0) {
        inode = NULL;
        goto out;
    }

    *owner = last;
    *entry = chain_ptr;
out:
    if (!inode)
        omfs_release_inode(last);
    
    return inode;
}

static omfs_inode_t *omfs_find_by_name(omfs_inode_t *parent, char *name)
{
    omfs_inode_t *inode, *owner;
    u64 *entry;

    inode = omfs_find_node_ptr(swap_be64(parent->head.self), name, 
        &owner, &entry);

    if (owner)
        omfs_release_inode(owner);

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
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = swap_be64(inode->size);
    }
   
    ctime = swap_be64(inode->ctime) / 1000L; 
    stbuf->st_ctime = stbuf->st_mtime = ctime;
    stbuf->st_uid = ctx->uid;
    stbuf->st_gid = ctx->gid;

    omfs_release_inode(inode);   
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

    err = omfs_allocate_block(&omfs_info, swap_be32(omfs_info.super->mirrors), 
        &block);
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
// FIXME: return the inode so it can be freed
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
    omfs_write_inode(&omfs_info, inode);
    omfs_release_inode(inode);
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
        omfs_write_inode(&omfs_info, inode);
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
        omfs_write_inode(&omfs_info, inode);

        if (next == ~0)
            break;

        // omfs_release_inode(inode);
        inode = omfs_get_inode(&omfs_info, next);
        if (!inode)
            goto out;
        oe = (struct omfs_extent *) ((u8*) inode + OMFS_EXTENT_CONT);
    }
out:
/*
    if (inode)
        omfs_release_inode(inode); 
*/
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
    
    omfs_write_inode(&omfs_info, inode);
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
    omfs_write_inode(&omfs_info, inode);

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
    omfs_inode_t *owner, *tmp;
    omfs_inode_t *inode = omfs_lookup(path);
    u64 *entry;
    u64 to_clear;

    if (!inode)
        return -ENOENT;

    tmp = omfs_find_node_ptr(swap_be64(inode->parent), inode->name,
            &owner, &entry);

    if (!tmp)
        return -ENOENT;

    *entry = inode->sibling;
    omfs_write_inode(&omfs_info, owner);

    to_clear = swap_be64(inode->head.self);
    shrink_file(inode, 0);

    omfs_clear_range(&omfs_info, to_clear,
        swap_be32(omfs_info.super->mirrors));

    //omfs_release_inode(inode);
    omfs_release_inode(tmp);
    return 0;
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
        omfs_write_inode(&omfs_info, inode);
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

    return fuse_main(fuse_argc, fuse_argv, &omfs_op, NULL);
}
