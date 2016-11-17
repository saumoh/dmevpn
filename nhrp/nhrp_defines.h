/* nhrp_defines.h - NHRP definitions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef NHRP_DEFINES_H
#define NHRP_DEFINES_H

#include <stdint.h>
#include <byteswap.h>
#include <sys/param.h>
#include <linux/version.h>

#ifndef NULL
#define NULL 0L
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef __bswap_constant_16
#define __bswap_constant_16(x) \
	((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#endif
#ifndef __bswap_constant_32
#define __bswap_constant_32(x) \
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	 (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define constant_ntohl(x) (x)
#define constant_ntohs(x) (x)
#define constant_htonl(x) (x)
#define constant_htons(x) (x)
#else
#define constant_ntohl(x) __bswap_constant_32(x)
#define constant_ntohs(x) __bswap_constant_16(x)
#define constant_htonl(x) __bswap_constant_32(x)
#define constant_htons(x) __bswap_constant_16(x)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

#define BIT(x) (1 << (x))

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#if __GNUC__ >= 3
#define NHRP_EMPTY_ARRAY
#else
#define NHRP_EMPTY_ARRAY		0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define NHRP_NO_NBMA_GRE
#endif

#define NHRP_DEFAULT_HOLDING_TIME	(2 * 60 * 60)

#endif
