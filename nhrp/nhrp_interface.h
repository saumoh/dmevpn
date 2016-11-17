/* nhrp_interface.h - NHRP configuration per interface definitions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef NHRP_INTERFACE_H
#define NHRP_INTERFACE_H

#include "nhrp_packet.h"
#include "nhrp_peer.h"

#define NHRP_INTERFACE_FLAG_NON_CACHING		0x0001	/* Do not cache entries */
#define NHRP_INTERFACE_FLAG_SHORTCUT		0x0002	/* Create shortcut routes */
#define NHRP_INTERFACE_FLAG_REDIRECT		0x0004	/* Send redirects */
#define NHRP_INTERFACE_FLAG_SHORTCUT_DEST	0x0008	/* Advertise routes */
#define NHRP_INTERFACE_FLAG_CONFIGURED		0x0010	/* Found in config file */
#define NHRP_INTERFACE_FLAG_L2LEARNONLY 	0x0020	/* Layer2 learning only
*/

#define NHRP_INTERFACE_NBMA_HASH_SIZE		256

struct nhrp_interface {
	struct list_head name_list_entry;
	struct hlist_node index_list_entry;

	struct list_head child_intf_list;
	struct list_head sibling_list_entry;
	struct nhrp_interface *parent;	/* base intf for vpn interfaces */

	struct list_head dp_intf_list;
	struct list_head dp_list_entry;
	struct nhrp_interface *controlif; /* nhrp protocol interface for this
intf */

	/* Configured information */
	char name[16];
	unsigned int flags;
	unsigned int holding_time;
	struct nhrp_buffer *auth_token;
	unsigned int route_table;
	uint32_t	vpnid;
	uint32_t	default_vnid;

	/* Cached from kernel interface */
	unsigned int index, link_index;
	uint32_t gre_key;
	uint16_t afnum;
	uint16_t mtu, nbma_mtu;
	struct nhrp_address nbma_address;
	struct nhrp_cie nat_cie;

	/* Actually, we should have list of protocol addresses;
	 * we might have multiple address and multiple protocol types */
	struct nhrp_address protocol_address;
	int protocol_address_prefix;

        /* Peer cache is interface specific */
	struct list_head peer_list;
	struct hlist_head nbma_hash[NHRP_INTERFACE_NBMA_HASH_SIZE];

	/* Multicast related stuff */
	struct list_head mcast_list;
	int mcast_mask;
	int mcast_numaddr;
	struct nhrp_address *mcast_addr;
};

typedef int (*nhrp_interface_enumerator)(void *ctx, struct nhrp_interface *iface);

void nhrp_interface_cleanup(void);
void nhrp_interface_hash(struct nhrp_interface *iface);
int nhrp_interface_foreach(nhrp_interface_enumerator enumerator, void *ctx);
struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create);
struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index, int create);
struct nhrp_interface *nhrp_interface_get_by_nbma(struct nhrp_address *addr);
struct nhrp_interface *nhrp_interface_get_by_protocol(struct nhrp_address *addr);
struct nhrp_interface *nhrp_interface_get_by_vpn(uint32_t vpnid);
int nhrp_interface_run_script(struct nhrp_interface *iface, char *action);
struct nhrp_peer *nhrp_interface_find_peer(struct nhrp_interface *iface, const struct nhrp_address *nbma);

void nhrp_interface_resolve_nbma(struct nhrp_interface *iface,
				 struct nhrp_address *nbmadest,
				 struct nhrp_address *nbma);

struct nhrp_interface *nhrp_interface_get_child(
				struct nhrp_interface *parent, uint32_t vpnid,
				int create);
#endif
