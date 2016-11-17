/* nhrp_packet.h - In-memory NHRP packet definitions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef NHRP_PACKET_H
#define NHRP_PACKET_H

#include "libev.h"
#include "list.h"
#include "nhrp_protocol.h"
#include "nhrp_address.h"

#define NHRP_MAX_EXTENSIONS		10

#define NHRP_PACKET_DEFAULT_HOP_COUNT	16

struct nhrp_interface;

struct nhrp_buffer {
	uint32_t length;
	uint8_t data[NHRP_EMPTY_ARRAY];
};

struct nhrp_cie {
	struct list_head	cie_list_entry;
	struct nhrp_cie_header	hdr;
	struct nhrp_address	nbma_address;
	struct nhrp_address	protocol_address;
};

#define NHRP_PAYLOAD_TYPE_ANY		-1
#define NHRP_PAYLOAD_TYPE_NONE		0
#define NHRP_PAYLOAD_TYPE_RAW		1
#define NHRP_PAYLOAD_TYPE_CIE_LIST	2
#define NHRP_PAYLOAD_TYPE_VPN		8

struct nhrp_payload {
	uint16_t extension_type;
	uint16_t payload_type;
	union {
		struct nhrp_buffer *raw;
		struct list_head cie_list;
	} u;
};

struct nhrp_packet {
	int ref;

	struct nhrp_packet_header	hdr;
	struct nhrp_address		src_nbma_address;
	struct nhrp_address		src_protocol_address;
	struct nhrp_address		dst_protocol_address;

	int				num_extensions;
	struct nhrp_payload		extension_by_order[NHRP_MAX_EXTENSIONS];
	struct nhrp_payload *		extension_by_type[NHRP_MAX_EXTENSIONS];

	struct list_head		request_list_entry;
	struct ev_timer			timeout;
	void				(*handler)(void *ctx, struct nhrp_packet *packet);
	void *				handler_ctx;
	int				retry;

	uint8_t *			req_pdu;
	size_t				req_pdulen;

	struct nhrp_interface *		src_iface;
	struct nhrp_address		src_linklayer_address;
	struct nhrp_interface *		dst_iface;
	struct nhrp_peer *		dst_peer;
	uint32_t			vpn_id;
	uint32_t			vn_id;
};

#define NHRP_EXTENSION_FLAG_NOCREATE	0x00010000

int nhrp_rate_limit_clear(struct nhrp_address *addr, int prefix_len);

struct nhrp_buffer *nhrp_buffer_alloc(uint32_t size);
struct nhrp_buffer *nhrp_buffer_copy(struct nhrp_buffer *buffer);
int nhrp_buffer_cmp(struct nhrp_buffer *a, struct nhrp_buffer *b);
void nhrp_buffer_free(struct nhrp_buffer *buffer);

struct nhrp_cie *nhrp_cie_alloc(void);
void nhrp_cie_free(struct nhrp_cie *cie);
void nhrp_cie_reset(struct nhrp_cie *cie);

void nhrp_payload_set_type(struct nhrp_payload *payload, int type);
void nhrp_payload_set_raw(struct nhrp_payload *payload, struct nhrp_buffer *buf);
void nhrp_payload_add_cie(struct nhrp_payload *payload, struct nhrp_cie *cie);
struct nhrp_cie *nhrp_payload_get_cie(struct nhrp_payload *payload, int index);
void nhrp_payload_free(struct nhrp_payload *payload);

struct nhrp_packet *nhrp_packet_alloc(void);
struct nhrp_packet *nhrp_packet_get(struct nhrp_packet *packet);
void nhrp_packet_put(struct nhrp_packet *packet);

struct nhrp_payload *nhrp_packet_payload(struct nhrp_packet *packet, int payload_type);
struct nhrp_payload *nhrp_packet_extension(struct nhrp_packet *packet,
					   uint32_t extension, int payload_type);
int nhrp_packet_receive(uint8_t *pdu, size_t pdulen,
			struct nhrp_interface *iface,
			struct nhrp_address *from);
int nhrp_packet_route(struct nhrp_packet *packet);
int nhrp_packet_reroute(struct nhrp_packet *packet, struct nhrp_peer *dst_peer);
int nhrp_packet_marshall_and_send(struct nhrp_packet *packet);
int nhrp_packet_route_and_send(struct nhrp_packet *packet);
int nhrp_packet_send(struct nhrp_packet *packet);
int nhrp_packet_send_request(struct nhrp_packet *packet,
			     void (*handler)(void *ctx, struct nhrp_packet *packet),
			     void *ctx);
int nhrp_packet_send_error(struct nhrp_packet *error_packet,
			   uint16_t indication_code, uint16_t offset);
int nhrp_packet_send_traffic(struct nhrp_interface *iface,
			     struct nhrp_address *nbma_src,
			     struct nhrp_address *protocol_src,
			     struct nhrp_address *protocol_dst,
			     int protocol_type, uint8_t *pdu, size_t pdulen);

void nhrp_packet_hook_request(int request,
			      int (*handler)(struct nhrp_packet *packet));

#endif
