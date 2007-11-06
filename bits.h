#ifndef _BITS_H
#define _BITS_H

inline int test_bit(u8* buf, u64 offset)
{
	return buf[offset >> 3] & (1<<(offset & 7));
}

inline void init_bit(u8* buf, u64 offset, int value)
{
	int mask = ((value & 1) << (offset & 7));
	buf[offset >> 3] &= ~mask;
	buf[offset >> 3] |= mask;
}
	
inline void clear_bit(u8* buf, u64 offset)
{
	buf[offset >> 3] &= ~(1 << (offset & 7));
}

inline void set_bit(u8* buf, u64 offset)
{
	buf[offset >> 3] |= 1 << (offset & 7);
}

inline int is_power_of_two(int i)
{
    return !(i & (i-1));
}

inline int log_2(int i)
{
    int count = 0;

    for (i>>=1;i;i>>=1)
        count++;
    return count;
}

#endif
