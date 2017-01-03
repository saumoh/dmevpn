/* nhrp_address.c - NHRP address conversion functions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <linux/ip.h>
#include <net/ethernet.h>

#include <ares.h>
#include <ares_version.h>

#include "afnum.h"
#include "nhrp_address.h"
#include "nhrp_packet.h"
#include "nhrp_common.h"

struct nhrp_resolver {
	ares_channel channel;
	struct ev_prepare prepare;
	struct ev_timer timeout;
	struct ev_io fds[4];
};

static struct nhrp_resolver resolver;

static void ares_timeout_cb(struct ev_timer *w, int revents)
{
	struct nhrp_resolver *r =
		container_of(w, struct nhrp_resolver, timeout);

	ares_process(r->channel, NULL, NULL);
}

static void ares_prepare_cb(struct ev_prepare *w, int revents)
{
	struct nhrp_resolver *r =
		container_of(w, struct nhrp_resolver, prepare);
	struct timeval *tv, tvbuf;

	tv = ares_timeout(r->channel, NULL, &tvbuf);
	if (tv != NULL) {
		r->timeout.repeat = tv->tv_sec + tv->tv_usec * 1e-6;
		ev_timer_again(&r->timeout);
	} else {
		ev_timer_stop(&r->timeout);
	}
}

static void ares_io_cb(struct ev_io *w, int revents)
{
	ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;

	if (revents & EV_READ)
		rfd = w->fd;
	if (revents & EV_WRITE)
		wfd = w->fd;

	ares_process_fd(resolver.channel, rfd, wfd);
}

static void ares_socket_cb(void *data, ares_socket_t fd,
			   int readable, int writable)
{
	struct nhrp_resolver *r = (struct nhrp_resolver *) data;
	int i, fi = -1, events = 0;

	if (readable)
		events |= EV_READ;
	if (writable)
		events |= EV_WRITE;

	for (i = 0; i < ARRAY_SIZE(r->fds); i++) {
		if (r->fds[i].fd == fd)
			break;
		if (fi < 0 && r->fds[i].fd == 0)
			fi = i;
	}

	if (events) {
		if (i >= ARRAY_SIZE(r->fds)) {
			NHRP_BUG_ON(fi == -1);
			i = fi;
		} else {
			ev_io_stop(&r->fds[fi]);
		}
		ev_io_set(&r->fds[i], fd, events);
		ev_io_start(&r->fds[i]);
	} else if (i < ARRAY_SIZE(r->fds)) {
		ev_io_stop(&r->fds[i]);
		ev_io_set(&r->fds[i], 0, 0);
	}
}

static int bitcmp(const uint8_t *a, const uint8_t *b, int len)
{
	int bytes, bits, mask, r;

	bytes = len / 8;
	bits  = len % 8;

	if (bytes != 0) {
		r = memcmp(a, b, bytes);
		if (r != 0)
			return r;
	}
	if (bits != 0) {
		mask = (0xff << (8 - bits)) & 0xff;
		return ((int) (a[bytes] & mask)) - ((int) (b[bytes] & mask));
	}
	return 0;
}

uint16_t nhrp_protocol_from_pf(uint16_t pf)
{
	switch (pf) {
	case PF_INET:
		return ETHPROTO_IP;
	case PF_BRIDGE:
		return ETHPROTO_DOT1Q;
	}
	return 0;
}

uint16_t nhrp_pf_from_protocol(uint16_t protocol)
{
	switch (protocol) {
	case ETHPROTO_IP:
		return PF_INET;
	case ETHPROTO_DOT1Q:
		return PF_BRIDGE;
	}
	return PF_UNSPEC;
}

uint16_t nhrp_afnum_from_pf(uint16_t pf)
{
	switch (pf) {
	case PF_INET:
		return AFNUM_INET;
	}
	return AFNUM_RESERVED;
}

uint16_t nhrp_pf_from_afnum(uint16_t afnum)
{
#if 0
	nhrp_debug("afnum: 0x%x/0x%x\n", afnum, ntohs(afnum));
#endif
	switch (afnum) {
	case AFNUM_INET:
		return PF_INET;
	}
	return PF_UNSPEC;
}

int nhrp_address_parse(const char *string,
		       struct nhrp_address *addr,
		       uint8_t *prefix_len)
{
	uint8_t tmp;
	int r;

	/* Try IP address format */
	r = sscanf(string, "%hhd.%hhd.%hhd.%hhd/%hhd",
		   &addr->addr[0], &addr->addr[1],
		   &addr->addr[2], &addr->addr[3],
		   prefix_len ? prefix_len : &tmp);
	if ((r == 4) || (r == 5 && prefix_len != NULL)) {
		addr->type = PF_INET;
		addr->addr_len = 4;
		addr->subaddr_len = 0;
		if (r == 4 && prefix_len != NULL)
			*prefix_len = 32;
		return TRUE;
	}
	/* Try mac address */
	r = sscanf(string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &addr->addr[0], &addr->addr[1], &addr->addr[2],
		   &addr->addr[3], &addr->addr[4], &addr->addr[5]);
	if ((r == 6)) {
		addr->type = PF_BRIDGE;
		addr->addr_len = ETH_ALEN;
		addr->subaddr_len = 0;
		if ( prefix_len != NULL)
			*prefix_len = 0;
		return TRUE;
	}

	return FALSE;
}

int nhrp_vni_id_parse(const char *string,
		      struct nhrp_address *addr,
		      uint8_t *prefix_len)
{
	uint32_t *vni = (uint32_t *)addr->addr;
	addr->type = PF_BRIDGE;
	addr->addr_len = 4;
	*vni = atoi(string);
	return TRUE;
}

int nhrp_address_parse_packet(uint16_t protocol, size_t len, uint8_t *packet,
			      struct nhrp_address *src, struct nhrp_address *dst)
{
	int pf;
	struct iphdr *iph;

	pf = nhrp_pf_from_protocol(protocol);
	switch (protocol) {
	case ETHPROTO_IP:
		if (len < sizeof(struct iphdr))
			return FALSE;

		iph = (struct iphdr *) packet;
		if (src != NULL)
			nhrp_address_set(src, pf, 4, (uint8_t *) &iph->saddr);
		if (dst != NULL)
			nhrp_address_set(dst, pf, 4, (uint8_t *) &iph->daddr);
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

#if ARES_VERSION_MAJOR > 1 || ARES_VERSION_MINOR > 4
static void ares_address_cb(void *arg, int status, int timeouts,
			    struct hostent *he)
#else
static void ares_address_cb(void *arg, int status, struct hostent *he)
#endif
{
	struct nhrp_address_query *query =
		(struct nhrp_address_query *) arg;
	struct nhrp_address addr[16];
	int i;

	if (status == ARES_SUCCESS) {
		for (i = 0; he->h_addr_list[i] != NULL &&
			    i < ARRAY_SIZE(addr); i++)
			nhrp_address_set(&addr[i], AF_INET, he->h_length,
					 (uint8_t *) he->h_addr_list[i]);
	} else
		i = -1;

	NHRP_BUG_ON(query->callback == NULL);

	query->callback(query, i, &addr[0]);
	query->callback = NULL;
}

void nhrp_address_resolve(struct nhrp_address_query *query,
			  const char *hostname,
			  nhrp_address_query_callback callback)
{
	if (query->callback != NULL) {
		nhrp_error("Trying to resolve '%s', but previous query "
			   "was not finished yet", hostname);
		return;
	}

	query->callback = callback;
	ares_gethostbyname(resolver.channel, hostname, AF_INET,
			   ares_address_cb, query);
}

void nhrp_address_resolve_cancel(struct nhrp_address_query *query)
{
	/* The kills all active queries; not just the one
	 * given as parameter. But as those will be retried later
	 * anyway, it is not a problem for now. */

	if (query->callback != NULL)
		ares_cancel(resolver.channel);
}

void nhrp_address_set_type(struct nhrp_address *addr, uint16_t type)
{
	addr->type = type;
	addr->addr_len = addr->subaddr_len = 0;
}

int nhrp_address_set(struct nhrp_address *addr, uint16_t type, uint8_t len, uint8_t *bytes)
{
	if (len > NHRP_MAX_ADDRESS_LEN)
		return FALSE;

	addr->type = type;
	addr->addr_len = len;
	addr->subaddr_len = 0;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	return TRUE;
}

int nhrp_address_set_full(struct nhrp_address *addr, uint16_t type,
			  uint8_t len, uint8_t *bytes,
			  uint8_t sublen, uint8_t *subbytes)
{
	char tmp[64];
	if (len + sublen > NHRP_MAX_ADDRESS_LEN)
		return FALSE;

	addr->type = type;
	addr->addr_len = len;
	addr->subaddr_len = sublen;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	if (sublen != 0)
		memcpy(&addr->addr[len], subbytes, sublen);
	nhrp_debug("Addres set to %s\n", nhrp_address_format(addr, sizeof(tmp),
		   tmp));
	return TRUE;
}

uint32_t nhrp_address_extract_subaddr(struct nhrp_address *src)
{
	uint32_t *val;
	if (src->type == PF_UNSPEC ||src->subaddr_len == 0)
		return 0;
	if (src->subaddr_len != sizeof(*val))
		return -1;
	val = (uint32_t *)&src->addr[src->addr_len];

	nhrp_debug("extract subaddr: 0x%x\n", *val);
	src->subaddr_len = 0;
	return *val;
}

int nhrp_address_cmp(const struct nhrp_address *a, const struct nhrp_address *b)
{
	if (a->type > b->type)
		return 1;
	if (a->type < b->type)
		return -1;
	if (a->addr_len > b->addr_len || a->subaddr_len > b->subaddr_len)
		return 1;
	if (a->addr_len < b->addr_len || a->subaddr_len < b->subaddr_len)
		return -1;
	return memcmp(a->addr, b->addr, a->addr_len + a->subaddr_len);
}

int nhrp_address_only_cmp(const struct nhrp_address *a,
			  const struct nhrp_address *b)
{
	if (a->type > b->type)
		return 1;
	if (a->type < b->type)
		return -1;
	if (a->addr_len != b->addr_len)
		return 1;
	return memcmp(a->addr, b->addr, a->addr_len);
}

int nhrp_address_prefix_cmp(const struct nhrp_address *a,
			    const struct nhrp_address *b, int prefix)
{
	if (!prefix && a->type == PF_BRIDGE)
		prefix = ETH_ALEN * 8 ;
	if (a->type > b->type)
		return 1;
	if (a->type < b->type)
		return -1;
	if (a->addr_len * 8 < prefix)
		return 1;
	if (b->addr_len * 8 < prefix)
		return 1;
	return bitcmp(a->addr, b->addr, prefix);
}

int nhrp_address_is_multicast(const struct nhrp_address *addr)
{
	switch (addr->type) {
	case PF_INET:
		if ((addr->addr[0] & 0xf0) == 0xe0)
			return TRUE;
		break;
	}
	return FALSE;
}

int nhrp_address_is_any_addr(const struct nhrp_address *addr)
{
	switch (addr->type) {
	case PF_UNSPEC:
		return TRUE;
	case PF_INET:
		if (memcmp(addr->addr, "\x00\x00\x00\x00", 4) == 0)
			return TRUE;
		break;
	}
	return FALSE;
}

unsigned int nhrp_address_hash(const struct nhrp_address *addr)
{
	unsigned int hash = 5381;
	int i;

	for (i = 0; i < addr->addr_len; i++)
		hash = hash * 33 + addr->addr[i];

	return hash;
}

void nhrp_address_set_network(struct nhrp_address *addr, int prefix)
{
	int i, bits = 8 * addr->addr_len;

	for (i = prefix; i < bits; i++)
		addr->addr[i / 8] &= ~(0x80 >> (i % 8));
}

void nhrp_address_set_broadcast(struct nhrp_address *addr, int prefix)
{
	int i, bits = 8 * addr->addr_len;

	for (i = prefix; i < bits; i++)
		addr->addr[i / 8] |= 0x80 >> (i % 8);
}

int nhrp_address_is_network(const struct nhrp_address *addr, int prefix)
{
	int i, bits = 8 * addr->addr_len;

	for (i = prefix; i < bits; i++)
		if (addr->addr[i / 8] & (0x80 >> (i % 8)))
			return FALSE;
	return TRUE;
}

const char *nhrp_address_format(const struct nhrp_address *addr,
				size_t buflen, char *buffer)
{
	switch (addr->type) {
	case PF_UNSPEC:
		snprintf(buffer, buflen, "(unspecified)");
		break;
	case PF_INET:
		snprintf(buffer, buflen, "%d.%d.%d.%d",
			 addr->addr[0], addr->addr[1],
			 addr->addr[2], addr->addr[3]);
		break;
	case PF_BRIDGE:
		snprintf(buffer, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
			 addr->addr[0],addr->addr[1],addr->addr[2],
			 addr->addr[3],addr->addr[4],addr->addr[5]);
		break;
	default:
		snprintf(buffer, buflen, "(proto 0x%04x)",
			 addr->type);
		break;
	}

	return buffer;
}

int nhrp_address_match_cie_list(struct nhrp_address *nbma_address,
				struct nhrp_address *protocol_address,
				struct list_head *cie_list)
{
	struct nhrp_cie *cie;

	list_for_each_entry(cie, cie_list, cie_list_entry) {
		if (nhrp_address_cmp(&cie->nbma_address, nbma_address) == 0 &&
		    nhrp_address_cmp(&cie->protocol_address, protocol_address) == 0)
			return TRUE;
	}

	return FALSE;
}

int nhrp_address_init(void)
{
	struct ares_options ares_opts;
	int i;

	memset(&ares_opts, 0, sizeof(ares_opts));
	ares_opts.sock_state_cb = &ares_socket_cb;
	ares_opts.sock_state_cb_data = &resolver;
	ares_opts.timeout = 2;
	ares_opts.tries = 3;
	if (ares_init_options(&resolver.channel, &ares_opts,
			      ARES_OPT_SOCK_STATE_CB | ARES_OPT_TIMEOUT |
			      ARES_OPT_TRIES) != ARES_SUCCESS)
		return FALSE;

	ev_timer_init(&resolver.timeout, ares_timeout_cb, 0.0, 0.0);
	ev_prepare_init(&resolver.prepare, ares_prepare_cb);
	ev_prepare_start(&resolver.prepare);
	for (i = 0; i < ARRAY_SIZE(resolver.fds); i++)
		ev_init(&resolver.fds[i], ares_io_cb);

	return TRUE;
}

void nhrp_address_cleanup(void)
{
	int i;

	ev_timer_stop(&resolver.timeout);
	ev_prepare_stop(&resolver.prepare);
	for (i = 0; i < ARRAY_SIZE(resolver.fds); i++)
		ev_io_stop(&resolver.fds[i]);
	ares_destroy(resolver.channel);
}

struct nhrp_address_slist_t {
	int	n_buckets;
	uint8_t data[0];
};

void *nhrp_address_slist_init(int bsize)
{
	struct nhrp_address_slist_t *slist;
	if (bsize == 0)
		bsize = 1024;
	slist = calloc(1, sizeof(*slist)+(sizeof(void *)* bsize));
	if (!slist)
		return NULL;
	slist->n_buckets = bsize;
	return slist;
}

static int slist_hash(uint8_t *a, uint8_t l)
{
	int i;
	int h;
	for (i = 0, h = 0; i < l; i++)
		h ^= a[i];
	return h;
}

static int _nhrp_address_slist_exists(struct nhrp_address_slist_t *list, struct nhrp_address *ref)
{
	int bucket = slist_hash(ref->addr, ref->addr_len) % list->n_buckets;
	int cindex = bucket;
	struct nhrp_address **hbuck = (struct nhrp_address **)list->data;
	do {
		struct nhrp_address *cmp_a = hbuck[cindex];
		if (!cmp_a)
			break;
		if (ref->addr_len != cmp_a->addr_len ||
		    memcmp(ref->addr, cmp_a->addr, ref->addr_len)) {
			cindex = (cindex + 1) % 1024;
			if (cindex == bucket)
				break;
		} else
			return cindex;
	} while (list->data[cindex]);
	return -1;
}

int nhrp_address_slist_exists(struct nhrp_address_slist_t *list, struct nhrp_address *ref)
{
	int cindex = _nhrp_address_slist_exists(list, ref);
	if (cindex < 0)
		return 0;
	return 1;
}

void nhrp_address_slist_add(struct nhrp_address_slist_t *list, struct nhrp_address *ref)
{
	int bucket = slist_hash(ref->addr, ref->addr_len) % list->n_buckets;
	int cindex = bucket;
	struct nhrp_address **hbuck = (struct nhrp_address **)list->data;
	if (nhrp_address_slist_exists(list, ref))
		return;
	do {
		struct nhrp_address *cmp_a = hbuck[cindex];
		if (cmp_a)
			cindex = (cindex + 1) % 1024;
		else {
			hbuck[cindex] = ref;
			return;
		}
	} while (cindex != bucket);
}

void nhrp_address_slist_del(struct nhrp_address_slist_t *list, struct nhrp_address *ref)
{
	int cindex = _nhrp_address_slist_exists(list, ref);
	struct nhrp_address **hbuck = (struct nhrp_address **)list->data;
	if (cindex < 0)
		return;
	hbuck[cindex] = NULL;
}

void nhrp_address_slist_rm(struct nhrp_address_slist_t *list)
{
	free(list);
}
