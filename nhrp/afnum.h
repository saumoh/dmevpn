/* afnum.h - RFC 1700 Address Family Number and
 *           ethernet protocol number definitions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef AFNUM_H
#define AFNUM_H

#include <linux/if_ether.h>
#include "nhrp_defines.h"

#define AFNUM_RESERVED		constant_htons(0)
#define AFNUM_INET		constant_htons(1)
#define AFNUM_INET6		constant_htons(2)

#define ETH_P_NHRP		0x2001

#define ETHPROTO_IP		constant_htons(ETH_P_IP)
#define ETHPROTO_NHRP		constant_htons(ETH_P_NHRP)
#define ETHPROTO_DOT1Q		constant_htons(ETH_P_8021Q)

#endif
