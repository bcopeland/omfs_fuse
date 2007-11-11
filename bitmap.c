/* Routines for bitmap allocation */
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include "omfs.h"
#include "bits.h"


static int nibblemap[] = {4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0};

unsigned long omfs_count_free(omfs_info_t *info)
{
    unsigned int i;
    unsigned long sum = 0;
    size_t bsize = (swap_be64(info->super->num_blocks) + 7) / 8;

    u8 *map = omfs_get_bitmap(info);

    for (i = 0; i < bsize; i++)
        sum += nibblemap[map[i] & 0xf] + nibblemap[(map[i] >> 4) & 0xf];

    free(map);
    return sum;
}
/* 
 * Scan through a bitmap for power-of-two sized region (max 8).  This 
 * should help to keep down fragmentation as mirrors will generally 
 * align to 2 blocks and clusters to 8.
 */
static int scan(u8* buf, int bsize, int bits)
{
    int shift = 1 << bits;
    int mask = shift - 1;
    int m, i;

    for (i=0; i < bsize * 8; i += bits)
    {
        m = mask << (i & 7);
        if (!(buf[ i >> 3 ] & m))
        {
            buf[ i >> 3 ] |= m;
            break;
        }
    }
    return i;
}

int omfs_clear_range(omfs_info_t *info, u64 start, int count)
{
    int i;
    u8 *bitmap = omfs_get_bitmap(info);
    if (!bitmap)
        return -ENOMEM;

    for (i=0; i < count; i++)
        clear_bit(bitmap, i + start);

    omfs_write_bitmap(info, bitmap);
    free(bitmap);
    return 0;
}

int omfs_allocate_one_block(omfs_info_t *info, u64 block)
{
    int ok = 0;
    u8 *bitmap = omfs_get_bitmap(info);
    if (!bitmap)
        return -ENOMEM;

    if (!test_bit(bitmap, block))
    {
        set_bit(bitmap, block);
        omfs_write_bitmap(info, bitmap);
        ok = 1;
    }
    free(bitmap);
    return ok;
}

int omfs_allocate_block(omfs_info_t *info, int size, u64 *return_block)
{
    size_t bsize;
    int ret = 0;
    int block;

    u8 *bitmap = omfs_get_bitmap(info);
    if (!bitmap)
        return -ENOMEM;

    bsize = (swap_be64(info->super->num_blocks) + 7) / 8;

    assert(is_power_of_two(size));

    block = scan(bitmap, bsize, size);
    if (block == bsize * 8) {
        ret = -ENOSPC;
        goto out;
    }
    *return_block = block;
    omfs_write_bitmap(info, bitmap);
out:
    free(bitmap);
    return ret;
}

