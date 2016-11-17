/* nhrp_interface.c - NHRP configuration per interface
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include "nhrp_common.h"
#include "nhrp_interface.h"
#include "nhrp_address.h"

#define NHRP_INDEX_HASH_SIZE		(1 << 6)

static struct list_head name_list = LIST_INITIALIZER(name_list);
static struct hlist_head index_hash[NHRP_INDEX_HASH_SIZE];

static char *env(const char *key, const char *value)
{
	char *buf;
	buf = malloc(strlen(key)+strlen(value)+2);
	if (buf == NULL)
		return NULL;
	sprintf(buf, "%s=%s", key, value);
	return buf;
}

static char *envu32(const char *key, uint32_t value)
{
	char *buf;
	buf = malloc(strlen(key)+16);
	if (buf == NULL)
		return NULL;
	sprintf(buf, "%s=%u", key, value);
	return buf;
}

void nhrp_interface_cleanup_children(struct nhrp_interface *parent)
{
	struct nhrp_interface *ciface, *n;
	list_for_each_entry_safe(ciface, n,
				 &parent->child_intf_list,
				 sibling_list_entry) {
		list_del(&ciface->sibling_list_entry);
		free(ciface);
	}
}

void nhrp_interface_cleanup(void)
{
	struct nhrp_interface *iface, *n;

	list_for_each_entry_safe(iface, n, &name_list, name_list_entry) {
		list_del(&iface->name_list_entry);
		hlist_del(&iface->index_list_entry);
		nhrp_interface_cleanup_children(iface);
		free(iface);
	}
}

void nhrp_interface_hash(struct nhrp_interface *iface)
{
	int iidx = iface->index & (NHRP_INDEX_HASH_SIZE - 1);

	list_del(&iface->name_list_entry);
	list_add(&iface->name_list_entry, &name_list);

	hlist_del(&iface->index_list_entry);
	hlist_add_head(&iface->index_list_entry, &index_hash[iidx]);
}

int nhrp_interface_foreach(nhrp_interface_enumerator enumerator, void *ctx)
{
	struct nhrp_interface *iface, *iface2;
	int rc;

	list_for_each_entry(iface, &name_list, name_list_entry) {
		rc = enumerator(ctx, iface);
		if (rc != 0)
			return rc;
		list_for_each_entry(iface2, &iface->child_intf_list,
				    sibling_list_entry) {
			rc = enumerator(ctx, iface2);
			if (rc != 0)
				return rc;
		}
	}
	return 0;
}

struct nhrp_interface *nhrp_interface_get_by_name(const char *name, int create)
{
	struct nhrp_interface *iface;

	list_for_each_entry(iface, &name_list, name_list_entry) {
		if (strcmp(iface->name, name) == 0)
			return iface;
	}

	if (!create)
		return NULL;

	iface = calloc(1, sizeof(struct nhrp_interface));
	iface->holding_time = NHRP_DEFAULT_HOLDING_TIME;
	iface->route_table = RT_TABLE_MAIN;
	strncpy(iface->name, name, sizeof(iface->name));

	list_init(&iface->peer_list);
	list_init(&iface->mcast_list);
	list_init(&iface->child_intf_list);
	list_init(&iface->dp_intf_list);
	list_add(&iface->name_list_entry, &name_list);
	hlist_add_head(&iface->index_list_entry, &index_hash[0]);

	return iface;
}

struct nhrp_interface *nhrp_interface_get_child(
				struct nhrp_interface *parent, uint32_t vpnid,
				int create)
{
	struct nhrp_interface *iface;

	list_for_each_entry(iface, &parent->child_intf_list,
			    sibling_list_entry) {
		if (iface->vpnid == vpnid)
			return iface;
	}

	if (!create)
		return NULL;

	iface = calloc(1, sizeof(struct nhrp_interface));
	iface->holding_time = parent->holding_time;
	iface->route_table = parent->route_table;
	iface->flags = parent->flags;
	iface->vpnid = vpnid;
	iface->parent = parent;
	strncpy(iface->name, parent->name, sizeof(parent->name));

	iface->index = parent->index;
	iface->link_index = parent->link_index;
	iface->gre_key = parent->gre_key;
	iface->afnum = parent->afnum;
	iface->mtu = parent->mtu;
	iface->nbma_mtu = parent->nbma_mtu;
	iface->nbma_address = parent->nbma_address;

	list_init(&iface->peer_list);
	list_init(&iface->mcast_list);
	list_init(&iface->child_intf_list);
	list_init(&iface->dp_intf_list);
	list_add(&iface->sibling_list_entry, &parent->child_intf_list);

	return iface;
}

struct nhrp_interface *nhrp_interface_get_by_index(unsigned int index, int create)
{
	struct nhrp_interface *iface;
	struct hlist_node *n;
	int iidx = index & (NHRP_INDEX_HASH_SIZE - 1);

	hlist_for_each_entry(iface, n, &index_hash[iidx], index_list_entry) {
		if (iface->index == index)
			return iface;
	}

	return NULL;
}

struct nhrp_interface *nhrp_interface_get_by_nbma(struct nhrp_address *addr)
{
	struct nhrp_interface *match = NULL;
	struct nhrp_interface *iface;

	list_for_each_entry(iface, &name_list, name_list_entry) {
		if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
			continue;

		if ((nhrp_address_cmp(addr, &iface->nbma_address) == 0) ||
		    (iface->nbma_address.type == PF_UNSPEC && !iface->link_index)) {
			/* ambiguous match - return null */
			if (match != NULL)
				return NULL;
			match = iface;
		}
	}

	return match;
}

struct nhrp_interface *nhrp_interface_get_by_protocol(struct nhrp_address *addr)
{
	struct nhrp_interface *iface;

	list_for_each_entry(iface, &name_list, name_list_entry) {
		if (nhrp_address_cmp(addr, &iface->protocol_address) == 0)
			return iface;
	}

	return NULL;
}

static struct nhrp_interface *nhrp_interface_get_child_by_vpnid(
					struct nhrp_interface *parent,
					uint32_t vpnid)
{
	struct nhrp_interface *iface;
	list_for_each_entry(iface, &parent->child_intf_list,
			    sibling_list_entry) {
		if (iface->vpnid == vpnid || vpnid == 0)
			return iface;
	}
	return NULL;
}

struct nhrp_interface *nhrp_interface_get_by_vpn(uint32_t vpnid)
{
	struct nhrp_interface *iface, *riface;

	list_for_each_entry(iface, &name_list, name_list_entry) {
		if (iface->vpnid == vpnid)
			return iface;
		riface = nhrp_interface_get_child_by_vpnid(iface, vpnid);
		if (riface)
			return riface;
	}

	return NULL;
}

int nhrp_interface_run_script(struct nhrp_interface *iface, char *action)
{
	const char *argv[] = { nhrp_script_file, action, NULL };
	char *envp[6];
	pid_t pid;
	int i = 0;

	pid = fork();
	if (pid == -1)
		return FALSE;
	if (pid > 0)
		return TRUE;

	envp[i++] = "NHRP_TYPE=INTERFACE";
	envp[i++] = env("NHRP_INTERFACE", iface->name);
	envp[i++] = envu32("NHRP_GRE_KEY", iface->gre_key);
	envp[i++] = NULL;

	execve(nhrp_script_file, (char **) argv, envp);
	exit(1);
}

struct nhrp_peer *nhrp_interface_find_peer(struct nhrp_interface *iface,
					   const struct nhrp_address *nbma)
{
	unsigned int key = nhrp_address_hash(nbma) % NHRP_INTERFACE_NBMA_HASH_SIZE;
	struct nhrp_peer *peer;
	struct hlist_node *n;

	hlist_for_each_entry(peer, n, &iface->nbma_hash[key], nbma_hash_entry) {
		if (nhrp_address_cmp(nbma, &peer->next_hop_address) == 0)
			return peer;
	}
	return NULL;
}
