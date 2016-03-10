
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CRC32_H_INCLUDED_
#define _NGX_CRC32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if __aarch64__

#define CRC_INST() asm(".cpu generic+crc");

#define PRFM(x,y) asm("prfm pldl1strm, [%x[a], "  y  "]" : : [a]"r"(x))
#define LDP(x,y,p) asm("ldp %x[a], %x[b], [%x[c]], #16" : [a]"=r"(x),[b]"=r"(y),[c]"+r"(p))
#define CRC32CX(crc,value) asm("crc32cx %w[c], %w[c], %x[v]" : [c]"+r"(*&crc) : [v]"r"(+value))
#define CRC32CW(crc,value) asm("crc32cw %w[c], %w[c], %w[v]" : [c]"+r"(*&crc) : [v]"r"(+value))
#define CRC32CB(crc,value) asm("crc32cb %w[c], %w[c], %w[v]" : [c]"+r"(*&crc) : [v]"r"(+value))

#define CRC32ZX(crc,value) asm("crc32x %w[c], %w[c], %x[v]" : [c]"+r"(crc) : [v]"r"(value))
#define CRC32ZW(crc,value) asm("crc32w %w[c], %w[c], %w[v]" : [c]"+r"(crc) : [v]"r"(value))
#define CRC32ZB(crc,value) asm("crc32b %w[c], %w[c], %w[v]" : [c]"+r"(crc) : [v]"r"(value))

static inline uint32_t crc32_128(uint32_t crc, const uint8_t *data)
{
    uint64_t s0, s1, s2, s3, s4, s5;

    CRC_INST();
    PRFM(data, "384");
    LDP(s0, s1, data);
    LDP(s2, s3, data);
    CRC32ZX(crc, s0);
    CRC32ZX(crc, s1);
    LDP(s4, s5, data);
    CRC32ZX(crc, s2);
    CRC32ZX(crc, s3);
    LDP(s0, s1, data);
    CRC32ZX(crc, s4);
    CRC32ZX(crc, s5);
    LDP(s2, s3, data);
    CRC32ZX(crc, s0);
    CRC32ZX(crc, s1);
    LDP(s4, s5, data);
    CRC32ZX(crc, s2);
    CRC32ZX(crc, s3);
    LDP(s0, s1, data);
    CRC32ZX(crc, s4);
    CRC32ZX(crc, s5);
    LDP(s2, s3, data);
    CRC32ZX(crc, s0);
    CRC32ZX(crc, s1);
    CRC32ZX(crc, s2);
    CRC32ZX(crc, s3); 

    return crc;
}
static inline uint32_t crc32_block(uint32_t crc, const uint8_t *data, int len)
{
    uint8_t *c;
    uint32_t *d;

    crc = crc;
    CRC_INST();
    while (len > 128) {
	crc = crc32_128(crc, data);
	data += 128;
	len -= 128;
    }

    d = (uint32_t*) data;
    while (len > 4) {
	CRC32ZW(crc, *(d++));
	len -= 4;
	data += 4;
    }

    c = (uint8_t*) data;
    while (len--) {
	CRC32ZB(crc, *(c++));
    }
    return crc;
}

#else

static inline uint32_t crc32_block(uint32_t crc, const void *data, int len)
{
}

#endif

extern uint32_t  *ngx_crc32_table_short;
extern uint32_t   ngx_crc32_table256[];
extern uint32_t   ngx_crc32_use_hw;

static ngx_inline uint32_t
ngx_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;
    if (ngx_crc32_use_hw) return crc32_block(crc, (const void*)p, len);

    while (len--) {
        c = *p++;
        crc = ngx_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = ngx_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static ngx_inline uint32_t
ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    if (ngx_crc32_use_hw) return crc32_block(crc, (uint8_t*)p, len);

    while (len--) {
        crc = ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#define ngx_crc32_init(crc)                                                   \
    crc = 0xffffffff


static ngx_inline void
ngx_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;
    if (ngx_crc32_use_hw) { *crc = crc32_block(c, (const void*)p, len); return; }

    while (len--) {
        c = ngx_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define ngx_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


ngx_int_t ngx_crc32_table_init(void);


#endif /* _NGX_CRC32_H_INCLUDED_ */
