/* admin.c - OpenNHRP administrative interface implementation
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_address.h"
#include "nhrp_interface.h"

static struct ev_io accept_io;

struct admin_remote {
	struct ev_timer timeout;
	struct ev_io io;
	int num_read;
	char cmd[512];
};

static int parse_word(const char **bufptr, size_t len, char *word)
{
	const char *buf = *bufptr;
	int i, pos = 0;

	while (isspace(buf[pos]) && buf[pos] != '\n' && buf[pos])
		pos++;

	if (buf[pos] == '\n' || buf[pos] == 0)
		return FALSE;

	for (i = 0; i < len-1 && !isspace(buf[pos+i]); i++)
		word[i] = buf[pos+i];
	word[i] = 0;

	*bufptr += i + pos;
	return TRUE;
}

static void admin_raw_write(void *ctx, const void *buf, size_t len)
{
	struct admin_remote *rmt = (struct admin_remote *) ctx;

	if (write(rmt->io.fd, buf, len) != len) {
	}
}

static void admin_write(void *ctx, const char *format, ...)
{
	char msg[1024];
	va_list ap;
	size_t len;

	va_start(ap, format);
	len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	admin_raw_write(ctx, msg, len);
}

static void admin_free_remote(struct admin_remote *rm)
{
	int fd = rm->io.fd;

	ev_io_stop(&rm->io);
	ev_timer_stop(&rm->timeout);
	shutdown(fd, SHUT_RDWR);
	close(fd);
	free(rm);
}

static int admin_show_peer(void *ctx, struct nhrp_peer *peer)
{
	char buf[512], tmp[32];
	char *str;
	size_t len = sizeof(buf);
	int i = 0, rel;

	if (peer->interface != NULL)
		i += snprintf(&buf[i], len - i,
			"Interface: %s Vpn: %d vnid: %d\n",
			peer->interface->name,
			peer->interface->default_vnid,
			peer->vnid);

	i += snprintf(&buf[i], len - i,
		"Type: %s\n"
		"Protocol-Address: %s/%d\n"
		"vni: %d\n",
		nhrp_peer_type[peer->type],
		nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp),
		peer->prefix_length, peer->vnid);

	if (peer->next_hop_address.type != PF_UNSPEC) {
		switch (peer->type) {
		case NHRP_PEER_TYPE_SHORTCUT_ROUTE:
		case NHRP_PEER_TYPE_LOCAL_ROUTE:
			str = "Next-hop-Address";
			break;
		case NHRP_PEER_TYPE_LOCAL_ADDR:
			str = "Alias-Address";
			break;
		default:
			str = "NBMA-Address";
			break;
		}
		i += snprintf(&buf[i], len - i, "%s: %s\n",
			str,
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(tmp), tmp));
	}
	if (peer->nbma_hostname) {
		i += snprintf(&buf[i], len - i, "Hostname: %s\n",
			      peer->nbma_hostname);
	}
	if (peer->next_hop_nat_oa.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "NBMA-NAT-OA-Address: %s\n",
			nhrp_address_format(&peer->next_hop_nat_oa,
					    sizeof(tmp), tmp));
	}
	if (peer->flags & (NHRP_PEER_FLAG_USED | NHRP_PEER_FLAG_UNIQUE |
			   NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP)) {
		i += snprintf(&buf[i], len - i, "Flags:");
		if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
			i += snprintf(&buf[i], len - i, " unique");

		if (peer->flags & NHRP_PEER_FLAG_USED)
			i += snprintf(&buf[i], len - i, " used");
		if (peer->flags & NHRP_PEER_FLAG_UP)
			i += snprintf(&buf[i], len - i, " up");
		else if (peer->flags & NHRP_PEER_FLAG_LOWER_UP)
			i += snprintf(&buf[i], len - i, " lower-up");
		i += snprintf(&buf[i], len - i, "\n");
	}
	if (peer->expire_time) {
		rel = (int) (peer->expire_time - ev_now());
		if (rel >= 0) {
			i += snprintf(&buf[i], len - i, "Expires-In: %d:%02d\n",
				      rel / 60, rel % 60);
		}
	}
	i += snprintf(&buf[i], len - i, "\n");
	admin_raw_write(ctx, buf, i);
	return 0;
}

static void admin_free_selector(struct nhrp_peer_selector *sel)
{
	if (sel->hostname != NULL) {
		free((void *) sel->hostname);
		sel->hostname = NULL;
	}
}

static int admin_parse_selector(void *ctx, const char *cmd,
				struct nhrp_peer_selector *sel)
{
	char keyword[64], tmp[64];
	struct nhrp_address address;
	uint8_t prefix_length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(tmp), tmp)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: missing-argument\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}

		if (strcmp(keyword, "interface") == 0 ||
		    strcmp(keyword, "iface") == 0 ||
		    strcmp(keyword, "dev") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_name(tmp, FALSE);
			if (sel->interface == NULL)
				goto err_noiface;
			continue;
		} else if (strcmp(keyword, "host") == 0 ||
			   strcmp(keyword, "hostname") == 0) {
			if (sel->hostname != NULL)
				goto err_conflict;
			sel->hostname = strdup(tmp);
			continue;
		}

		if (!nhrp_address_parse(tmp, &address, &prefix_length)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				   keyword);
			return FALSE;
		}

		if (strcmp(keyword, "protocol") == 0) {
			if (sel->protocol_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->protocol_address = address;
			sel->prefix_length = prefix_length;
		} else if (strcmp(keyword, "nbma") == 0) {
			if (sel->next_hop_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->type_mask &= ~BIT(NHRP_PEER_TYPE_SHORTCUT_ROUTE);
			sel->next_hop_address = address;
		} else if (strcmp(keyword, "local-protocol") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_protocol(&address);
			if (sel->interface == NULL)
				goto err_noiface;
		} else if (strcmp(keyword, "local-nbma") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->local_nbma_address = address;
			if (sel->interface == NULL)
				sel->interface = nhrp_interface_get_by_nbma(&address);
		} else {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: syntax-error\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}
	}
	return TRUE;

err_conflict:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: conflicting-keyword\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	goto err;
err_noiface:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: interface-not-found\n"
		    "Near-Keyword: '%s'\n"
		    "Argument: '%s'\n",
		    keyword, tmp);
err:
	admin_free_selector(sel);
	return FALSE;
}

static void admin_route_show(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ROUTE);
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	admin_write(ctx, "Status: ok\n\n");
	nhrp_peer_foreach(admin_show_peer, ctx, &sel);
	admin_free_selector(&sel);
}

static void admin_cache_show(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_ALL &
		~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE);
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	admin_write(ctx, "Status: ok\n\n");
	nhrp_peer_foreach(admin_show_peer, ctx, &sel);
	admin_free_selector(&sel);
}

static void admin_cache_purge(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_purge_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_lower_down(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_lowerdown_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_flush(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_remove_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static int admin_show_interface(void *ctx, struct nhrp_interface *iface)
{
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0;

	i += snprintf(&buf[i], len - i,
		"Interface: %s\n"
		"Index: %d "
		"Vpn: %d Vnid: %d\n",
		iface->name,
		iface->index,
		iface->vpnid, iface->default_vnid);

	if (iface->protocol_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"Protocol-Address: %s/%d\n",
			nhrp_address_format(&iface->protocol_address, sizeof(tmp), tmp),
			iface->protocol_address_prefix);
	}

	if (iface->flags) {
		i += snprintf(&buf[i], len - i,
			"Flags:%s%s%s%s%s\n",
			(iface->flags & NHRP_INTERFACE_FLAG_NON_CACHING) ? " non-caching" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT) ? " shortcut" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_REDIRECT) ? " redirect" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST) ? " shortcut-dest" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED) ? " configured" : "");
	}

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		goto done;

	i += snprintf(&buf[i], len - i,
		"Holding-Time: %u\n"
		"Route-Table: %u\n"
		"GRE-Key: %u\n"
		"MTU: %u\n",
		iface->holding_time,
		iface->route_table,
		iface->gre_key,
		iface->mtu);

	if (iface->link_index) {
		struct nhrp_interface *link;

		i += snprintf(&buf[i], len - i, "Link-Index: %d\n", iface->link_index);
		link = nhrp_interface_get_by_index(iface->link_index, FALSE);
		if (link != NULL)
			i += snprintf(&buf[i], len - i, "Link-Name: %s\n", link->name);
	}

	if (iface->nbma_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"NBMA-MTU: %u\n"
			"NBMA-Address: %s\n",
			iface->nbma_mtu,
			nhrp_address_format(&iface->nbma_address, sizeof(tmp), tmp));
	}
	if (iface->nat_cie.nbma_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"NBMA-NAT-OA: %s\n",
			nhrp_address_format(&iface->nat_cie.nbma_address, sizeof(tmp), tmp));
	}
done:
	i += snprintf(&buf[i], len - i, "\n");
	admin_raw_write(ctx, buf, i);
	return 0;
}

static void admin_interface_show(void *ctx, const char *cmd)
{
	admin_write(ctx, "Status: ok\n\n");
	nhrp_interface_foreach(admin_show_interface, ctx);
}

static void admin_redirect_purge(void *ctx, const char *cmd)
{
	char keyword[64];
	struct nhrp_address addr;
	uint8_t prefix = 0;
	int count;

	nhrp_address_set_type(&addr, PF_UNSPEC);

	if (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!nhrp_address_parse(keyword, &addr, &prefix)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return;
		}
	}

	count = nhrp_rate_limit_clear(&addr, prefix);
	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

struct update_nbma {
	struct nhrp_address addr;
	int count;
};

static int update_nbma(void *ctx, struct nhrp_peer *p)
{
	struct update_nbma *un = (struct update_nbma *) ctx;

	nhrp_peer_discover_nhs(p, &un->addr);
	un->count++;

	return 0;
}

static void admin_update_nbma(void *ctx, const char *cmd)
{
	char keyword[64];
	struct nhrp_peer_selector sel;
	struct update_nbma un;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC_NHS);

	if (!parse_word(&cmd, sizeof(keyword), keyword))
		goto err;
	if (!nhrp_address_parse(keyword, &sel.next_hop_address, NULL))
		goto err;
	if (!parse_word(&cmd, sizeof(keyword), keyword))
		goto err;
	if (!nhrp_address_parse(keyword, &un.addr, NULL))
		goto err;

	un.count = 0;
	nhrp_peer_foreach(update_nbma, &un, &sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    un.count);
	return;
err:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: syntax-error\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	return;
}

static struct {
	const char *command;
	void (*handler)(void *ctx, const char *cmd);
} admin_handler[] = {
	{ "route show",		admin_route_show },
	{ "show",		admin_cache_show },
	{ "cache show",		admin_cache_show },
	{ "flush",		admin_cache_flush },
	{ "cache flush",	admin_cache_flush },
	{ "purge",		admin_cache_purge },
	{ "cache purge",	admin_cache_purge },
	{ "cache lowerdown",	admin_cache_lower_down },
	{ "interface show",	admin_interface_show },
	{ "redirect purge",	admin_redirect_purge },
	{ "update nbma",	admin_update_nbma },
};

static void admin_receive_cb(struct ev_io *w, int revents)
{
	struct admin_remote *rm = container_of(w, struct admin_remote, io);
	int fd = rm->io.fd;
	ssize_t len;
	int i, cmdlen;

	len = recv(fd, rm->cmd, sizeof(rm->cmd) - rm->num_read, MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return;
	if (len <= 0)
		goto err;

	rm->num_read += len;
	if (rm->num_read >= sizeof(rm->cmd))
		goto err;

	if (rm->cmd[rm->num_read-1] != '\n')
		return;
	rm->cmd[--rm->num_read] = 0;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		cmdlen = strlen(admin_handler[i].command);
		if (rm->num_read >= cmdlen &&
		    strncasecmp(rm->cmd, admin_handler[i].command, cmdlen) == 0) {
			nhrp_debug("Admin: %s", rm->cmd);
			admin_handler[i].handler(rm, &rm->cmd[cmdlen]);
			break;
		}
	}
	if (i >= ARRAY_SIZE(admin_handler)) {
		admin_write(rm,
			    "Status: error\n"
			    "Reason: unrecognized command\n");
	}

err:
	admin_free_remote(rm);
}

static void admin_timeout_cb(struct ev_timer *t, int revents)
{
	admin_free_remote(container_of(t, struct admin_remote, timeout));
}

static void admin_accept_cb(ev_io *w, int revents)
{
	struct admin_remote *rm;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	int cnx;

	cnx = accept(w->fd, (struct sockaddr *) &from, &fromlen);
	if (cnx < 0)
		return;
	fcntl(cnx, F_SETFD, FD_CLOEXEC);

	rm = calloc(1, sizeof(struct admin_remote));

	ev_io_init(&rm->io, admin_receive_cb, cnx, EV_READ);
	ev_io_start(&rm->io);
	ev_timer_init(&rm->timeout, admin_timeout_cb, 10.0, 0.);
	ev_timer_start(&rm->timeout);
}

int admin_init(const char *opennhrp_socket)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, opennhrp_socket, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	unlink(opennhrp_socket);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) != 0)
		goto err_close;

	if (listen(fd, 5) != 0)
		goto err_close;

	ev_io_init(&accept_io, admin_accept_cb, fd, EV_READ);
	ev_io_start(&accept_io);

	return 1;

err_close:
	nhrp_error("Failed initialize admin socket [%s]: %s",
		   opennhrp_socket, strerror(errno));
	close(fd);
	return 0;
}
