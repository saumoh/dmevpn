/* nhrp_server.c - NHRP request handling
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <string.h>
#include <netinet/in.h>

#include "nhrp_common.h"
#include "nhrp_packet.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define NHRP_MAX_PENDING_REQUESTS 16

struct nhrp_pending_request {
	struct list_head request_list_entry;
	int natted;
	int num_ok, num_error;
	struct nhrp_packet *packet;
	struct nhrp_cie *cie;
	struct nhrp_payload *payload;
	struct nhrp_peer *peer, *rpeer;
	ev_tstamp now;
};

static struct list_head request_list = LIST_INITIALIZER(request_list);
static int num_pending_requests = 0;

static void nhrp_server_start_cie_reg(struct nhrp_pending_request *pr);

static struct nhrp_pending_request *
nhrp_server_record_request(struct nhrp_packet *packet)
{
	struct nhrp_pending_request *pr;

	pr = calloc(1, sizeof(struct nhrp_pending_request));
	list_init(&pr->request_list_entry);
	if (pr != NULL) {
		num_pending_requests++;
		list_add(&pr->request_list_entry, &request_list);
		pr->packet = nhrp_packet_get(packet);
		pr->now = ev_now();
	}
	return pr;
}

void nhrp_server_finish_request(struct nhrp_pending_request *pr)
{
	list_del(&pr->request_list_entry);
	if (pr->rpeer != NULL) {
		struct nhrp_peer *peer = pr->rpeer;
		if (peer->flags & NHRP_PEER_FLAG_REPLACED) {
			/* The route peer entry was not accepted. We still
			 * send the replies here, and cancel anything pending
			 * so it'll get deleted cleanly on next put(). */
			nhrp_peer_send_packet_queue(peer);
			nhrp_peer_cancel_async(peer);
		}
		nhrp_peer_put(pr->rpeer);
	}
	if (pr->peer != NULL)
		nhrp_peer_put(pr->peer);
	if (pr->packet != NULL)
		nhrp_packet_put(pr->packet);
	free(pr);
	num_pending_requests--;
}

static int nhrp_server_request_pending(struct nhrp_packet *packet)
{
	struct nhrp_pending_request *r;

	list_for_each_entry(r, &request_list, request_list_entry) {
		if (nhrp_address_cmp(&packet->src_nbma_address,
				     &r->packet->src_nbma_address) != 0)
			continue;
		if (nhrp_address_cmp(&packet->src_protocol_address,
				     &r->packet->src_protocol_address) != 0)
			continue;
		if (nhrp_address_cmp(&packet->dst_protocol_address,
				     &r->packet->dst_protocol_address) != 0)
			continue;

		/* Request from the same address being already processed */
		return TRUE;
	}

	return FALSE;
}

static struct nhrp_interface *nhrp_get_packet_intf(struct nhrp_packet *packet,
						   int create)
{
	struct nhrp_interface *intf;

	intf = packet->src_iface;
	if (intf->vpnid != packet->vpn_id)
		intf = nhrp_interface_get_child(packet->src_iface,
						packet->vpn_id, create);
	return intf;
}

static int nhrp_handle_resolution_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64], tmp3[64];
	struct nhrp_payload *payload;
	struct nhrp_peer *peer = packet->dst_peer;
	struct nhrp_peer_selector sel;
	struct nhrp_cie *cie;
	struct nhrp_interface *intf;

	nhrp_info("Received Resolution Request from proto src %s (nbma %s) to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->src_nbma_address,
				      sizeof(tmp2), tmp2),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp3), tmp3));

	intf = nhrp_get_packet_intf(packet, FALSE);
	/* As first thing, flush all negative entries for the
	 * requestor */
	memset(&sel, 0, sizeof(sel));
	sel.flags = NHRP_PEER_FIND_EXACT_VPN;
	sel.type_mask = BIT(NHRP_PEER_TYPE_NEGATIVE);
	sel.interface = intf;
	sel.protocol_address = packet->src_protocol_address;
	sel.vpnid = intf->vpnid;
	nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);

	/* Send reply */
	packet->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
	packet->hdr.hop_count = NHRP_PACKET_DEFAULT_HOP_COUNT;
	packet->hdr.flags &= NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			     NHRP_FLAG_RESOLUTION_SOURCE_STABLE |
			     NHRP_FLAG_RESOLUTION_UNIQUE |
			     NHRP_FLAG_RESOLUTION_NAT;
	packet->hdr.flags |= NHRP_FLAG_RESOLUTION_DESTINATION_STABLE |
			     NHRP_FLAG_RESOLUTION_AUTHORATIVE;

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		return FALSE;

	cie->hdr = (struct nhrp_cie_header) {
		.code = NHRP_CODE_SUCCESS,
		.prefix_length = peer->prefix_length,
	};
	if (peer->holding_time)
		cie->hdr.holding_time = htons(peer->holding_time);
	else if (peer->interface != NULL)
		cie->hdr.holding_time = htons(peer->interface->holding_time);
	else
		cie->hdr.holding_time = NHRP_DEFAULT_HOLDING_TIME;

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_ANY);
	nhrp_payload_free(payload);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	peer = packet->dst_peer;
	if (peer) {
		cie->hdr.mtu = htons(peer->my_nbma_mtu);
		cie->nbma_address = peer->my_nbma_address;
		cie->protocol_address = peer->protocol_address;
		packet->vn_id = peer->vnid;
	}

	if (!nhrp_packet_reroute(packet, NULL)) {
		packet->dst_peer = nhrp_peer_route(packet->src_iface,
						   &packet->src_protocol_address,
						   NHRP_PEER_FIND_DEFAULT,
						   ~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE));
		if (!packet->dst_peer)
			return FALSE;
		/* get a reference */
		packet->dst_peer = nhrp_peer_get(packet->dst_peer);
	}
#if 0
	cie->protocol_address = packet->dst_iface->protocol_address;
#endif


	nhrp_info("Sending Resolution Reply %s/%d is-at %s (%d) (holdtime %d)",
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp), tmp),
		  cie->hdr.prefix_length,
		  nhrp_address_format(&cie->nbma_address,
				      sizeof(tmp2), tmp2),
		  packet->vn_id,
		  ntohs(cie->hdr.holding_time));

	/* Reset NAT header to regenerate it for reply */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_ANY);
	if (payload != NULL) {
		nhrp_payload_free(payload);
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	}

	return nhrp_packet_send(packet);
}

static int find_one(void *ctx, struct nhrp_peer *p)
{
	return 1;
}

static int remove_old_registrations(void *ctx, struct nhrp_peer *p)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;

	/* If re-registration, mark the new connection up */
	if (nhrp_address_cmp(&peer->protocol_address,
			     &p->protocol_address) == 0 &&
	    nhrp_address_cmp(&peer->next_hop_address,
			     &p->next_hop_address) == 0 &&
	    peer->prefix_length == p->prefix_length)
		peer->flags |= p->flags & (NHRP_PEER_FLAG_UP |
					   NHRP_PEER_FLAG_LOWER_UP);

	p->flags |= NHRP_PEER_FLAG_REPLACED;
	nhrp_peer_remove(p);
	return 0;
}

static void nhrp_server_finish_reg(struct nhrp_pending_request *pr)
{
	char tmp[64], tmp2[64];
	struct nhrp_packet *packet = pr->packet;

	if (pr->rpeer != NULL &&
	    nhrp_packet_reroute(packet, pr->rpeer)) {
		nhrp_info("Sending Registration Reply from proto src %s to %s (%d bindings accepted, %d rejected)",
			  nhrp_address_format(&packet->dst_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp2), tmp2),
			  pr->num_ok, pr->num_error);

		nhrp_packet_send(packet);
	} else {
		/* We could not create route peer entry (likely out of memory),
		 * so we can't do much more here. */
		nhrp_info("Dropping Registration Reply from proto src %s to %s",
			  nhrp_address_format(&packet->dst_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp2), tmp2));
	}

	nhrp_server_finish_request(pr);
}

static void nhrp_server_finish_cie_reg_cb(union nhrp_peer_event e, int revents)
{
	struct nhrp_peer *peer;
	struct nhrp_pending_request *pr;
	struct nhrp_packet *packet;
	struct nhrp_cie *cie;
	struct nhrp_peer_selector sel;
	char tmp[64], reason[32];

	peer = nhrp_peer_from_event(e, revents);
	pr = peer->request;
	packet = pr->packet;
	cie = pr->cie;

	peer->request = NULL;
	nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp);
	if (revents != 0 && nhrp_peer_event_ok(e, revents)) {
		nhrp_debug("[%s] Peer registration authorized", tmp);

		/* Remove all old stuff and accept registration */
		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT_VPN;
		sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = packet->src_iface;
		sel.protocol_address = peer->protocol_address;
		sel.prefix_length = peer->prefix_length;
		nhrp_peer_foreach(remove_old_registrations, peer, &sel);

		pr->num_ok++;
		cie->hdr.code = NHRP_CODE_SUCCESS;
		nhrp_peer_insert(peer);
	} else {
		if (revents == 0)
			nhrp_error("[%s] Peer registration failed: "
				   "static entry exists", tmp);
		else
			nhrp_error("[%s] Peer registration failed: %s",
				   tmp,
				   nhrp_peer_event_reason(e, revents,
							  sizeof(reason),
							  reason));
		pr->num_error++;
		cie->hdr.code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
		peer->flags |= NHRP_PEER_FLAG_REPLACED;
	}
	if (pr->rpeer == NULL)
		pr->rpeer = nhrp_peer_get(peer);

	nhrp_peer_put(peer);
	pr->peer = NULL;

	/* Process next CIE or finish registration handling */
	if (cie->cie_list_entry.next != &pr->payload->u.cie_list) {
		pr->cie = list_next(&cie->cie_list_entry, struct nhrp_cie, cie_list_entry);
		nhrp_server_start_cie_reg(pr);
	} else {
		nhrp_server_finish_reg(pr);
	}

}

static void nhrp_server_start_cie_reg(struct nhrp_pending_request *pr)
{
	struct nhrp_cie *cie = pr->cie;
	struct nhrp_packet *packet = pr->packet;
	struct nhrp_peer *peer;
	struct nhrp_peer_selector sel;
	struct nhrp_interface *intf;

	intf = nhrp_get_packet_intf(packet, TRUE);

	peer = nhrp_peer_alloc(intf);
	if (peer == NULL) {
		/* Mark all remaining registration requests as failed
		 * due to lack of memory, and send reply */
		for (; cie->cie_list_entry.next != &pr->payload->u.cie_list;
		     cie = list_next(&cie->cie_list_entry, struct nhrp_cie, cie_list_entry)) {
			pr->num_error++;
			cie->hdr.code = NHRP_CODE_INSUFFICIENT_RESOURCES;
		}
		pr->num_error++;
		cie->hdr.code = NHRP_CODE_INSUFFICIENT_RESOURCES;
		nhrp_server_finish_reg(pr);
		return;
	}

	peer->type = NHRP_PEER_TYPE_DYNAMIC;
	peer->afnum = packet->hdr.afnum;
	peer->protocol_type = packet->hdr.protocol_type;
	peer->expire_time = pr->now + ntohs(cie->hdr.holding_time);
	peer->mtu = ntohs(cie->hdr.mtu);
	peer->vnid = packet->vn_id;
	if (cie->nbma_address.addr_len != 0)
		peer->next_hop_address = cie->nbma_address;
	else
		peer->next_hop_address = packet->src_nbma_address;

	if (pr->natted) {
		peer->next_hop_nat_oa  = peer->next_hop_address;
		peer->next_hop_address = packet->src_linklayer_address;
	}

	if (cie->protocol_address.addr_len != 0)
		peer->protocol_address = cie->protocol_address;
	else
		peer->protocol_address = packet->src_protocol_address;

	peer->prefix_length = cie->hdr.prefix_length;
	if (peer->prefix_length == 0xff)
		peer->prefix_length = peer->protocol_address.addr_len * 8;

	memset(&sel, 0, sizeof(sel));
	sel.flags = NHRP_PEER_FIND_EXACT_VPN;
	sel.type_mask = ~NHRP_PEER_TYPEMASK_REMOVABLE;
	sel.interface = intf;
	sel.protocol_address = peer->protocol_address;
	sel.prefix_length = peer->prefix_length;

	/* Link the created peer and pending request structures */
	pr->peer = peer;
	peer->request = pr;

	/* Check that there is no conflicting peers */
	if (nhrp_peer_foreach(find_one, peer, &sel) != 0) {
		cie->hdr.code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
		peer->flags |= NHRP_PEER_FLAG_REPLACED;
		nhrp_server_finish_cie_reg_cb(&peer->child, 0);
	} else {
		nhrp_peer_run_script(peer, "peer-register",
				     nhrp_server_finish_cie_reg_cb);
	}
}

static int nhrp_handle_registration_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_pending_request *pr;
	int natted = 0;

	nhrp_info("Received Registration Request from proto src %s to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp2), tmp2));

	if (nhrp_server_request_pending(packet)) {
		nhrp_info("Already processing: resent packet ignored.");
		return TRUE;
	}

	if (num_pending_requests >= NHRP_MAX_PENDING_REQUESTS) {
		/* We should probably send Registration Reply with CIE
		 * error NHRP_CODE_INSUFFICIENT_RESOURCES, or an Error
		 * Indication. However, we do not have a direct peer entry
		 * nor can we make sure that the lower layer is up, so
		 * we just lamely drop the packet for now. */
		nhrp_info("Too many pending requests: dropping this one");
		return TRUE;
	}

	/* Cisco NAT extension, CIE added IF all of the following is true:
	 * 1. We are the first hop registration server
	 *    (=no entries in forward transit CIE list)
	 * 2. NAT is detected (link layer address != announced address)
	 * 3. NAT extension is requested */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL && list_empty(&payload->u.cie_list) &&
	    packet->src_linklayer_address.type != PF_UNSPEC &&
	    nhrp_address_cmp(&packet->src_nbma_address,
			     &packet->src_linklayer_address) != 0) {
		natted = 1;
		payload = nhrp_packet_extension(packet,
						NHRP_EXTENSION_NAT_ADDRESS |
						NHRP_EXTENSION_FLAG_NOCREATE,
						NHRP_PAYLOAD_TYPE_CIE_LIST);
		if (payload != NULL) {
			cie = nhrp_cie_alloc();
			if (cie != NULL) {
				cie->nbma_address = packet->src_linklayer_address;
				cie->protocol_address = packet->src_protocol_address;
				nhrp_payload_add_cie(payload, cie);
			}
		}
	}

	packet->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
	packet->hdr.hop_count = NHRP_PACKET_DEFAULT_HOP_COUNT;
	packet->hdr.flags &= NHRP_FLAG_REGISTRATION_UNIQUE |
			     NHRP_FLAG_REGISTRATION_NAT;

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (list_empty(&payload->u.cie_list)) {
		nhrp_error("Received registration request has no CIEs");
		return TRUE;
	}

	/* Start processing the CIEs */
	pr = nhrp_server_record_request(packet);
	pr->natted = natted;
	pr->payload = payload;

	pr->cie = nhrp_payload_get_cie(payload, 1);
	nhrp_server_start_cie_reg(pr);

	return TRUE;
}

static int remove_peer_by_nbma(void *ctx, struct nhrp_peer *peer)
{
	struct nhrp_address *nbma = ctx;
	struct nhrp_address *peer_nbma = NULL;

	if (!nhrp_address_is_any_addr(nbma)) {
		if (peer->type == NHRP_PEER_TYPE_SHORTCUT_ROUTE) {
			struct nhrp_peer *nexthop;

			nexthop = nhrp_peer_route(peer->interface,
				&peer->next_hop_address,
				NHRP_PEER_FIND_EXACT_VPN,
				NHRP_PEER_TYPEMASK_ADJACENT);
			if (nexthop != NULL)
				peer_nbma = &nexthop->next_hop_address;
		} else {
			peer_nbma = &peer->next_hop_address;
		}
	} else {
		peer_nbma = nbma;
	}

	if (peer_nbma != NULL &&
	    nhrp_address_cmp(peer_nbma, nbma) == 0)
		nhrp_peer_remove(peer);

	return 0;
}

static int nhrp_handle_purge_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_peer_selector sel;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	int flags, ret = TRUE;
	struct nhrp_interface *intf = nhrp_get_packet_intf(packet, FALSE);

	nhrp_info("Received Purge Request from proto src %s to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp2), tmp2));

	flags = packet->hdr.flags;
	packet->hdr.type = NHRP_PACKET_PURGE_REPLY;
	packet->hdr.hop_count = NHRP_PACKET_DEFAULT_HOP_COUNT;
	packet->hdr.flags = 0;

	if (!(flags & NHRP_FLAG_PURGE_NO_REPLY)) {
		if (nhrp_packet_reroute(packet, NULL))
			ret = nhrp_packet_send(packet);
		else
			ret = FALSE;
	}

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	list_for_each_entry(cie, &payload->u.cie_list, cie_list_entry) {
		nhrp_info("Purge proto %s/%d nbma %s",
			nhrp_address_format(&cie->protocol_address,
					    sizeof(tmp), tmp),
			cie->hdr.prefix_length,
			nhrp_address_format(&cie->nbma_address,
					    sizeof(tmp2), tmp2));

		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT_VPN;
		sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = intf;
		sel.protocol_address = cie->protocol_address;
		sel.prefix_length = cie->hdr.prefix_length;
		nhrp_peer_foreach(remove_peer_by_nbma,
				  &cie->nbma_address, &sel);
		nhrp_rate_limit_clear(&cie->protocol_address,
				      cie->hdr.prefix_length);
	}

	return ret;
}

static int nhrp_handle_traffic_indication(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_address dst;
	struct nhrp_payload *pl;
	struct nhrp_interface *intf = nhrp_get_packet_intf(packet, FALSE);

	pl = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_RAW);
	if (pl == NULL)
		return FALSE;

	if (!nhrp_address_parse_packet(packet->hdr.protocol_type,
				       pl->u.raw->length, pl->u.raw->data,
				       NULL, &dst))
		return FALSE;

	/* Shortcuts enabled? */
	if (intf->flags & NHRP_INTERFACE_FLAG_SHORTCUT) {
		nhrp_info("Traffic Indication from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));

		nhrp_peer_traffic_indication(packet->src_iface,
					     packet->hdr.afnum, &dst);
	} else {
		nhrp_info("Traffic Indication ignored from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));
	}

	return TRUE;
}

void server_init(void)
{
	nhrp_packet_hook_request(NHRP_PACKET_RESOLUTION_REQUEST,
				 nhrp_handle_resolution_request);
	nhrp_packet_hook_request(NHRP_PACKET_REGISTRATION_REQUEST,
				 nhrp_handle_registration_request);
	nhrp_packet_hook_request(NHRP_PACKET_PURGE_REQUEST,
				 nhrp_handle_purge_request);
	nhrp_packet_hook_request(NHRP_PACKET_TRAFFIC_INDICATION,
				 nhrp_handle_traffic_indication);
}
