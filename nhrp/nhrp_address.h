/* nhrp_address.h - NHRP address structures and helpers
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef NHRP_ADDRESS_H
#define NHRP_ADDRESS_H

#include <stdint.h>
#include <sys/socket.h>
#include "list.h"

#define NHRP_MAX_ADDRESS_LEN            8

struct nhrp_cie_list_head;
struct nhrp_address;
struct nhrp_address_query;

typedef void (*nhrp_address_query_callback)(struct nhrp_address_query *query,
					    int num_addr,
					    struct nhrp_address *addrs);

struct nhrp_address {
	uint16_t type;
	uint8_t addr_len;
	uint8_t subaddr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
};

struct nhrp_address_query {
	nhrp_address_query_callback callback;
};

uint16_t nhrp_protocol_from_pf(uint16_t pf);
uint16_t nhrp_pf_from_protocol(uint16_t protocol);
uint16_t nhrp_afnum_from_pf(uint16_t pf);
uint16_t nhrp_pf_from_afnum(uint16_t afnum);

int nhrp_address_init(void);
void nhrp_address_cleanup(void);
int nhrp_address_parse_packet(uint16_t protocol, size_t len, uint8_t *packet,
			      struct nhrp_address *src,
			      struct nhrp_address *dst);
int nhrp_address_parse(const char *string, struct nhrp_address *addr,
		       uint8_t *prefix_len);
void nhrp_address_resolve(struct nhrp_address_query *query,
			  const char *hostname,
			  nhrp_address_query_callback callback);
void nhrp_address_resolve_cancel(struct nhrp_address_query *query);
void nhrp_address_set_type(struct nhrp_address *addr, uint16_t type);
int nhrp_address_set(struct nhrp_address *addr, uint16_t type,
		     uint8_t len, uint8_t *bytes);
int nhrp_address_set_full(struct nhrp_address *addr, uint16_t type,
			  uint8_t len, uint8_t *bytes,
			  uint8_t sublen, uint8_t *subbytes);
int nhrp_address_cmp(const struct nhrp_address *a, const struct nhrp_address *b);
int nhrp_address_prefix_cmp(const struct nhrp_address *a, const struct nhrp_address *b,
			    int prefix);
extern int nhrp_address_only_cmp(const struct nhrp_address *a, const struct nhrp_address *b);
unsigned int nhrp_address_hash(const struct nhrp_address *addr);
void nhrp_address_set_network(struct nhrp_address *addr, int prefix);
void nhrp_address_set_broadcast(struct nhrp_address *addr, int prefix);
int nhrp_address_is_network(const struct nhrp_address *addr, int prefix);
int nhrp_address_is_broadcast(const struct nhrp_address *addr, int prefix);
int nhrp_address_is_multicast(const struct nhrp_address *addr);
int nhrp_address_is_any_addr(const struct nhrp_address *addr);
const char *nhrp_address_format(const struct nhrp_address *addr,
				size_t buflen, char *buffer);

int nhrp_address_match_cie_list(struct nhrp_address *nbma_address,
				struct nhrp_address *protocol_address,
				struct list_head *cie_list);
extern int nhrp_vni_id_parse(const char *string, struct nhrp_address *addr, uint8_t *prefix_len);
extern uint32_t nhrp_address_extract_subaddr(struct nhrp_address *src);

#endif
