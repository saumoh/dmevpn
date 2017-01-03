/* sysdep_netlink.c - Linux netlink glue
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>

#include "libev.h"
#include "nhrp_common.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define NETLINK_KERNEL_BUFFER	(256 * 1024)
#define NETLINK_RECV_BUFFER	(8 * 1024)

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg);

static void netlink_get_vxlaninfo(struct nhrp_interface *iface,
				  struct rtattr **rta);

struct netlink_fd {
	int fd;
	__u32 seq;
	struct ev_io io;

	int dispatch_size;
	const netlink_dispatch_f *dispatch;
};

static const int netlink_groups[] = {
	0,
	RTMGRP_NEIGH,
	RTMGRP_LINK,
	RTMGRP_IPV4_IFADDR,
	RTMGRP_IPV4_ROUTE,
};
static struct netlink_fd netlink_fds[ARRAY_SIZE(netlink_groups)];
#define talk_fd netlink_fds[0]

static struct ev_io packet_io;

static u_int16_t translate_mtu(u_int16_t mtu)
{
	/* if mtu is ethernet standard, do not advertise it
	 * pmtu should be working */
	if (mtu == 1500)
		return 0;
	return mtu;
}

static void netlink_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

static int netlink_add_rtattr_l(struct nlmsghdr *n, int maxlen, int type,
				const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return FALSE;

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
#ifdef VALGRIND
	/* Clear the padding area to avoid spurious warnings */
	memset(RTA_DATA(rta) + alen, 0, RTA_ALIGN(len) - alen);
#endif
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return TRUE;
}

static int netlink_receive(struct netlink_fd *fd, struct nlmsghdr *reply)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int got_reply = FALSE, len;
	char buf[NETLINK_RECV_BUFFER];

	iov.iov_base = buf;
	while (!got_reply) {
		int status;
		struct nlmsghdr *h;

		iov.iov_len = sizeof(buf);
		status = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return reply == NULL;
			nhrp_perror("Netlink overrun");
			continue;
		}

		if (status == 0) {
			nhrp_error("Netlink returned EOF");
			return FALSE;
		}

		h = (struct nlmsghdr *) buf;
		while (NLMSG_OK(h, status)) {
			if (reply != NULL &&
			    h->nlmsg_seq == reply->nlmsg_seq) {
				len = h->nlmsg_len;
				if (len > reply->nlmsg_len) {
					nhrp_error("Netlink message truncated");
					len = reply->nlmsg_len;
				}
				memcpy(reply, h, len);
				got_reply = TRUE;
			} else if (h->nlmsg_type <= fd->dispatch_size &&
				fd->dispatch[h->nlmsg_type] != NULL) {
				fd->dispatch[h->nlmsg_type](h);
			} else if (h->nlmsg_type != NLMSG_DONE) {
				nhrp_info("Unknown NLmsg: 0x%08x, len %d",
					  h->nlmsg_type, h->nlmsg_len);
			}
			h = NLMSG_NEXT(h, status);
		}
	}

	return TRUE;
}

static int netlink_send(struct netlink_fd *fd, struct nlmsghdr *req)
{
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) req,
		.iov_len = req->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int status;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	req->nlmsg_seq = ++fd->seq;

	status = sendmsg(fd->fd, &msg, 0);
	if (status < 0) {
		nhrp_perror("Cannot talk to rtnetlink");
		return FALSE;
	}
	return TRUE;
}

static int netlink_talk(struct netlink_fd *fd, struct nlmsghdr *req,
		 size_t replysize, struct nlmsghdr *reply)
{
	if (reply == NULL)
		req->nlmsg_flags |= NLM_F_ACK;

	if (!netlink_send(fd, req))
		return FALSE;

	if (reply == NULL)
		return TRUE;

	reply->nlmsg_len = replysize;
	return netlink_receive(fd, reply);
}

static int netlink_enumerate(struct netlink_fd *fd, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl addr;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = ++fd->seq;
	req.g.rtgen_family = family;

	return sendto(fd->fd, (void *) &req, sizeof(req), 0,
		      (struct sockaddr *) &addr, sizeof(addr)) >= 0;
}

static void netlink_read_cb(struct ev_io *w, int revents)
{
	struct netlink_fd *nfd = container_of(w, struct netlink_fd, io);

	if (revents & EV_READ)
		netlink_receive(nfd, NULL);
}

static int do_get_ioctl(const char *basedev, struct ip_tunnel_parm *p)
{
	struct ifreq ifr;
	char *data;

#ifdef VALGRIND
	/* Valgrind does not have SIOCGETTUNNEL description, so clear
	 * the memory structs to avoid spurious warnings */
	memset(&ifr, 0, sizeof(ifr));
	memset(p, 0, sizeof(*p));
#endif
	data = calloc(1, sizeof(*p)+512);

	strncpy(ifr.ifr_name, basedev, IFNAMSIZ);
	ifr.ifr_ifru.ifru_data = (void *) data;
	if (ioctl(packet_io.fd, SIOCGETTUNNEL, &ifr)) {
		nhrp_perror("ioctl(SIOCGETTUNNEL)");
		return FALSE;
	}
	memcpy(p, data, sizeof(*p));
	return TRUE;
}

#ifndef NHRP_NO_NBMA_GRE

static int netlink_add_nested_rtattr_u32(struct rtattr *rta, int maxlen,
					 int type, uint32_t value)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen)
		return FALSE;

	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &value, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return TRUE;
}

static int netlink_configure_arp(struct nhrp_interface *iface, int pf)
{
	struct {
		struct nlmsghdr n;
		struct ndtmsg ndtm;
		char buf[256];
	} req;
	struct {
		struct rtattr rta;
		char buf[256];
	} parms;

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndtm, 0, sizeof(req.ndtm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
	req.n.nlmsg_type = RTM_SETNEIGHTBL;

	req.ndtm.ndtm_family = pf;

	netlink_add_rtattr_l(&req.n, sizeof(req), NDTA_NAME,
			     "arp_cache", 10);

	parms.rta.rta_type = NDTA_PARMS;
	parms.rta.rta_len = RTA_LENGTH(0);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_IFINDEX, iface->index);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_APP_PROBES, 1);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_MCAST_PROBES, 0);
	netlink_add_nested_rtattr_u32(&parms.rta, sizeof(parms),
				      NDTPA_UCAST_PROBES, 0);

	netlink_add_rtattr_l(&req.n, sizeof(req), NDTA_PARMS,
			     parms.buf, parms.rta.rta_len - RTA_LENGTH(0));

	return netlink_send(&talk_fd, &req.n);
}

static int netlink_link_arp_on(struct nhrp_interface *iface)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ);
	if (ioctl(packet_io.fd, SIOCGIFFLAGS, &ifr)) {
		nhrp_perror("ioctl(SIOCGIFFLAGS)");
		return FALSE;
	}
	if (ifr.ifr_flags & IFF_NOARP) {
		ifr.ifr_flags &= ~IFF_NOARP;
		if (ioctl(packet_io.fd, SIOCSIFFLAGS, &ifr)) {
			nhrp_perror("ioctl(SIOCSIFFLAGS)");
			return FALSE;
		}
	}
	return TRUE;
}

#else

static int netlink_configure_arp(struct nhrp_interface *iface, int pf)
{
	return TRUE;
}

static int netlink_link_arp_on(struct nhrp_interface *iface)
{
	return TRUE;
}

#endif

static int proc_icmp_redirect_off(const char *interface)
{
	char fname[256];
	int fd, ret = FALSE;

	sprintf(fname, "/proc/sys/net/ipv4/conf/%s/send_redirects", interface);
	fd = open(fname, O_WRONLY);
	if (fd < 0)
		return FALSE;
	if (write(fd, "0\n", 2) == 2)
		ret = TRUE;
	close(fd);

	return ret;
}

static void netlink_neigh_request(struct nlmsghdr *msg)
{
	struct ndmsg *ndm = NLMSG_DATA(msg);
	struct rtattr *rta[NDA_MAX+1];
	struct nhrp_peer *peer;
	struct nhrp_address addr;
	struct nhrp_interface *iface;
	char tmp[64];

	addr.type = PF_UNSPEC;
	netlink_parse_rtattr(rta, NDA_MAX, NDA_RTA(ndm), NDA_PAYLOAD(msg));

	iface = nhrp_interface_get_by_index(ndm->ndm_ifindex, 0);
	if (iface == NULL)
		return;

	if (rta[NDA_LLADDR] != NULL)
		nhrp_address_set(&addr, AF_BRIDGE,
				 RTA_PAYLOAD(rta[NDA_LLADDR]),
				 RTA_DATA(rta[NDA_LLADDR]));
	else
		nhrp_address_set(&addr, ndm->ndm_family,
				 RTA_PAYLOAD(rta[NDA_DST]),
				 RTA_DATA(rta[NDA_DST]));
	if (addr.type == PF_UNSPEC)
		return;

	nhrp_debug("NL-ARP(%s) who-has %s",
		   iface->name, nhrp_address_format(&addr, sizeof(tmp), tmp));

	peer = nhrp_peer_route(iface, &addr, 0, ~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE));
	if (peer == NULL) {
		/* see if there is a default peer */
		peer = nhrp_peer_route(iface, &addr, NHRP_PEER_FIND_DEFAULT, ~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE));
		if (peer == NULL)
			return;
	}

	if (peer->flags & NHRP_PEER_FLAG_UP) {
		switch (addr.type) {
			case AF_INET:
				kernel_inject_neighbor(&addr, &peer->next_hop_address, iface);
				break;
			case AF_BRIDGE:
				kernel_inject_brneighbor(&addr, &peer->next_hop_address, iface,
							 peer->vnid);
				break;
			default:
				return;
		}
	}

	if (peer->next_hop_address.type != PF_UNSPEC &&
	    nhrp_address_cmp(&addr, &peer->protocol_address) != 0)
		nhrp_peer_traffic_indication(iface, peer->afnum, &addr);
}

static void netlink_braddr_new(struct nhrp_interface *iface,
			       struct nhrp_peer_selector *sel,
			       uint32_t vni)
{
	struct nhrp_peer *peer;

	if (iface->flags & NHRP_INTERFACE_FLAG_L2LEARNONLY) {
		nhrp_peer_l2learn(TRUE, iface, sel, vni);
		return;
	}
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		return;
	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return;
	/* the interface is not a shortcut. */

	/* check if the address is routed...*/
	peer = nhrp_peer_route(iface, &sel->protocol_address,
			       NHRP_PEER_FIND_EXACT_VPN,
			       ~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE));
	if (!peer)
                nhrp_peer_traffic_indication(iface, AF_INET,
					     &sel->protocol_address);
}

static void netlink_neigh_update(struct nlmsghdr *msg)
{
	struct ndmsg *ndm = NLMSG_DATA(msg);
	struct rtattr *rta[NDA_MAX+1];
	struct nhrp_interface *iface;
	struct nhrp_peer_selector sel;
	int used = FALSE;
	int family = AF_INET;
	uint32_t vni_id = 0;

	netlink_parse_rtattr(rta, NDA_MAX, NDA_RTA(ndm), NDA_PAYLOAD(msg));
	if (rta[NDA_DST] == NULL)
		return;

	if (!(ndm->ndm_state &
	     (NUD_STALE | NUD_FAILED | NUD_REACHABLE | NUD_PERMANENT)))
		return;

	iface = nhrp_interface_get_by_index(ndm->ndm_ifindex, 0);
	if (iface == NULL)
		return;

	memset(&sel, 0, sizeof(sel));
	sel.flags = NHRP_PEER_FIND_EXACT_VPN;
	sel.interface = iface;
	sel.vpnid = iface->vpnid;
	switch (ndm->ndm_family) {
		case AF_BRIDGE:
			nhrp_address_set(&sel.protocol_address, ndm->ndm_family,
					 RTA_PAYLOAD(rta[NDA_LLADDR]),
					 RTA_DATA(rta[NDA_LLADDR]));
			if (RTA_PAYLOAD(rta[NDA_DST]) == sizeof(struct in6_addr))
				family = AF_INET6;
			nhrp_address_set(&sel.next_hop_address, family,
					 RTA_PAYLOAD(rta[NDA_DST]),
					 RTA_DATA(rta[NDA_DST]));
			if (rta[NDA_VNI])
				vni_id = *(uint32_t *)RTA_DATA(rta[NDA_VNI]);
			else
				vni_id = iface->default_vnid;
			break;

		default:
			nhrp_address_set(&sel.protocol_address, ndm->ndm_family,
					 RTA_PAYLOAD(rta[NDA_DST]),
			 		 RTA_DATA(rta[NDA_DST]));
			break;
	}

	if (msg->nlmsg_type == RTM_NEWNEIGH &&
	    (ndm->ndm_state & (NUD_REACHABLE | NUD_PERMANENT)))
		used = TRUE;

	nhrp_peer_foreach(nhrp_peer_set_used_matching,
			  (void*) (intptr_t) used, &sel);

	if (used == TRUE && ndm->ndm_family == AF_BRIDGE) {
		netlink_braddr_new(iface, &sel, vni_id);
	}
}

static void netlink_link_new(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;
	struct ip_tunnel_parm cfg;
	int configuration_changed = FALSE;

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = nhrp_interface_get_by_name(ifname, TRUE);
	if (iface == NULL)
		return;

	if (rta[IFLA_MTU])
		iface->mtu = *((unsigned*)RTA_DATA(rta[IFLA_MTU]));

	if (((ifi->ifi_change & IFF_UP) || (iface->index == 0)) &&
	    (ifi->ifi_flags & IFF_UP)) {
		nhrp_info("Interface %s: configured UP, mtu=%d",
			  ifname, iface->mtu);
		nhrp_interface_run_script(iface, "interface-up");
	} else {
		nhrp_info("Interface %s: config change, mtu=%d",
			  ifname, iface->mtu);
	}

	iface->index = ifi->ifi_index;
	nhrp_interface_hash(iface);

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return;

	switch (ifi->ifi_type) {
	case ARPHRD_IPGRE:
		iface->afnum = AFNUM_INET;
		/* try hard to get the interface nbma address */
		do_get_ioctl(ifname, &cfg);
		if (iface->gre_key != ntohl(cfg.i_key)) {
			configuration_changed = TRUE;
			iface->gre_key = ntohl(cfg.i_key);
		}
		if (cfg.iph.saddr) {
			struct nhrp_address saddr;
			nhrp_address_set(&saddr, PF_INET, 4, (uint8_t *) &cfg.iph.saddr);
			if (nhrp_address_cmp(&iface->nbma_address, &saddr) || iface->link_index) {
				configuration_changed = TRUE;
				iface->nbma_address = saddr;
				iface->link_index = 0;
			}
		} else if (cfg.link) {
			if (cfg.link != iface->link_index) {
				configuration_changed = TRUE;
				nhrp_address_set_type(&iface->nbma_address, PF_UNSPEC);
				iface->link_index = cfg.link;
			}
		} else {
			if (iface->link_index || iface->nbma_address.type != PF_UNSPEC) {
				configuration_changed = TRUE;
				/* Mark the interface as owning all NBMA addresses
				 * this works when there's only one GRE interface */
				iface->link_index = 0;
				nhrp_address_set_type(&iface->nbma_address, PF_UNSPEC);
				nhrp_info("WARNING: Cannot figure out NBMA address for "
					  "interface '%s'. Using route hints.", ifname);
			}
		}
		break;

	case ARPHRD_ETHER:
		netlink_get_vxlaninfo(iface, rta);
		break;

	default:
		nhrp_debug("Interface: %d type: 0x%x\n", iface->index,
			   ifi->ifi_type);
		break;
	}

	if (!(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)) {
		netlink_configure_arp(iface, PF_INET);
		netlink_link_arp_on(iface);
		proc_icmp_redirect_off(iface->name);
	}

	if (configuration_changed) {
		struct nhrp_peer_selector sel;
		int count = 0;

		/* Reset the interface values we detect later */
		memset(&iface->nat_cie, 0, sizeof(iface->nat_cie));
		iface->nbma_mtu = 0;
		if (iface->link_index) {
			/* Reenumerate addresses if needed */
			netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETADDR);
			netlink_read_cb(&talk_fd.io, EV_READ);
		}

		/* Purge all NHRP entries for this interface */
		memset(&sel, 0, sizeof(sel));
		sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
		sel.interface = iface;
		nhrp_peer_foreach(nhrp_peer_purge_matching, &count, &sel);
		nhrp_info("Interface %s: GRE configuration changed. Purged %d peers.",
			  ifname, count);
	}
}

static void netlink_link_del(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct ifinfomsg *ifi = NLMSG_DATA(msg);
	struct rtattr *rta[IFLA_MAX+1];
	const char *ifname;

	netlink_parse_rtattr(rta, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(msg));
	if (rta[IFLA_IFNAME] == NULL)
		return;

	ifname = RTA_DATA(rta[IFLA_IFNAME]);
	iface = nhrp_interface_get_by_name(ifname, FALSE);
	if (iface == NULL)
		return;

	nhrp_info("Interface '%s' deleted", ifname);
	iface->index = 0;
	iface->link_index = 0;
	nhrp_interface_hash(iface);

	nhrp_address_set_type(&iface->nbma_address, PF_UNSPEC);
	nhrp_address_set_type(&iface->protocol_address, PF_UNSPEC);
}

static int netlink_addr_new_nbma(void *ctx, struct nhrp_interface *iface)
{
	struct nlmsghdr *msg = (struct nlmsghdr *) ctx;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];
	struct nhrp_interface *nbma_iface;

	if (iface->link_index == ifa->ifa_index) {
		netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa),
				     IFA_PAYLOAD(msg));

		if (rta[IFA_LOCAL] == NULL)
			return 0;

		nhrp_address_set(&iface->nbma_address, ifa->ifa_family,
				 RTA_PAYLOAD(rta[IFA_LOCAL]),
				 RTA_DATA(rta[IFA_LOCAL]));

		nbma_iface = nhrp_interface_get_by_index(ifa->ifa_index, FALSE);
		if (nbma_iface != NULL) {
			iface->nbma_mtu = translate_mtu(nbma_iface->mtu);
		}
	}

	return 0;
}

static void netlink_addr_new(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct nhrp_peer *peer, *bcast;
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta[IFA_MAX+1];

	if (!(ifa->ifa_flags & IFA_F_SECONDARY))
		nhrp_interface_foreach(netlink_addr_new_nbma, msg);

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(msg));
	iface = nhrp_interface_get_by_index(ifa->ifa_index, FALSE);
	if (iface == NULL || rta[IFA_LOCAL] == NULL)
		return;

	/* Shortcut destination stuff is extracted from routes;
	 * not from local address information. */
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		return;
	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return;

	nhrp_address_set(&iface->protocol_address, ifa->ifa_family,
			 RTA_PAYLOAD(rta[IFA_LOCAL]),
			 RTA_DATA(rta[IFA_LOCAL]));
	iface->protocol_address_prefix = ifa->ifa_prefixlen;

	peer = nhrp_peer_alloc(iface);
	peer->type = NHRP_PEER_TYPE_LOCAL_ADDR;
	peer->afnum = AFNUM_RESERVED;
	nhrp_address_set(&peer->protocol_address, ifa->ifa_family,
			 RTA_PAYLOAD(rta[IFA_LOCAL]),
			 RTA_DATA(rta[IFA_LOCAL]));
	switch (ifa->ifa_family) {
	case PF_INET:
		peer->protocol_type = ETHPROTO_IP;
		peer->prefix_length = peer->protocol_address.addr_len * 8;
		nhrp_peer_insert(peer);
		break;
	default:
		nhrp_peer_put(peer);
		return;
	}

	bcast = nhrp_peer_alloc(iface);
	bcast->type = peer->type;
	bcast->afnum = peer->afnum;
	bcast->protocol_type = peer->protocol_type;
	bcast->prefix_length = peer->prefix_length;
	bcast->protocol_address = peer->protocol_address;
	nhrp_address_set_broadcast(&bcast->protocol_address,
				   ifa->ifa_prefixlen);
	bcast->next_hop_address = peer->protocol_address;
	nhrp_peer_insert(bcast);
	nhrp_peer_put(bcast);

	nhrp_peer_put(peer);
}

struct netlink_del_addr_msg {
	int interface_index;
	struct nhrp_address address;
};

static int netlink_addr_del_nbma(void *ctx, struct nhrp_interface *iface)
{
	struct netlink_del_addr_msg *msg = (struct netlink_del_addr_msg *) ctx;

	if (iface->link_index == msg->interface_index &&
	    nhrp_address_cmp(&msg->address, &iface->nbma_address) == 0)
		nhrp_address_set_type(&iface->nbma_address, PF_UNSPEC);

	return 0;
}

static int netlink_addr_purge_nbma(void *ctx, struct nhrp_peer *peer)
{
	struct netlink_del_addr_msg *msg = (struct netlink_del_addr_msg *) ctx;

	if (nhrp_address_cmp(&peer->my_nbma_address, &msg->address) == 0)
		nhrp_peer_purge(peer, "address-removed");

	return 0;
}

static void netlink_addr_del(struct nlmsghdr *nlmsg)
{
	struct netlink_del_addr_msg msg;
	struct nhrp_interface *iface;
	struct ifaddrmsg *ifa = NLMSG_DATA(nlmsg);
	struct rtattr *rta[IFA_MAX+1];
	struct nhrp_peer_selector sel;

	netlink_parse_rtattr(rta, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(nlmsg));
	if (rta[IFA_LOCAL] == NULL)
		return;

	msg.interface_index = ifa->ifa_index;
	nhrp_address_set(&msg.address, ifa->ifa_family,
			 RTA_PAYLOAD(rta[IFA_LOCAL]),
			 RTA_DATA(rta[IFA_LOCAL]));

	if (!(ifa->ifa_flags & IFA_F_SECONDARY))
		nhrp_interface_foreach(netlink_addr_del_nbma, &msg);
	nhrp_peer_foreach(netlink_addr_purge_nbma, &msg, NULL);

	iface = nhrp_interface_get_by_index(ifa->ifa_index, FALSE);
	if (iface == NULL)
		return;

	memset(&sel, 0, sizeof(sel));
	sel.flags = NHRP_PEER_FIND_EXACT_VPN;
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ADDR);
	sel.interface = iface;
	sel.protocol_address = msg.address;
	sel.prefix_length = sel.protocol_address.addr_len * 8;

	if (nhrp_address_cmp(&sel.protocol_address, &iface->protocol_address) == 0)
		nhrp_address_set_type(&iface->protocol_address, PF_UNSPEC);
	nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);

	nhrp_address_set_broadcast(&sel.protocol_address, ifa->ifa_prefixlen);
	sel.next_hop_address = msg.address;
	nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);
}

static void netlink_route_new(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct nhrp_peer *peer;
	struct rtmsg *rtm = NLMSG_DATA(msg);
	struct rtattr *rta[RTA_MAX+1];
	int type = 0;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));
	if (rta[RTA_OIF] == NULL || rta[RTA_DST] == NULL)
		return;

	if (rtm->rtm_family != PF_INET)
		return;

	iface = nhrp_interface_get_by_index(*(int*)RTA_DATA(rta[RTA_OIF]),
					    FALSE);
	if (iface == NULL)
		return;

	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST) {
		/* Local shortcut target routes */
		if (rtm->rtm_table != RT_TABLE_MAIN)
			return;
		type = NHRP_PEER_TYPE_LOCAL_ADDR;
	} else if (iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED) {
		/* Routes which might get additional outbound
		 * shortcuts */
		if (rtm->rtm_table != iface->route_table ||
		    rtm->rtm_protocol == RTPROT_KERNEL)
			return;
		type = NHRP_PEER_TYPE_LOCAL_ROUTE;
	}
	if (type == 0)
		return;

	peer = nhrp_peer_alloc(iface);
	peer->type = type;
	peer->afnum = AFNUM_RESERVED;
	nhrp_address_set(&peer->protocol_address, rtm->rtm_family,
			 RTA_PAYLOAD(rta[RTA_DST]),
			 RTA_DATA(rta[RTA_DST]));
	if (rta[RTA_GATEWAY] != NULL) {
		nhrp_address_set(&peer->next_hop_address,
				 rtm->rtm_family,
				 RTA_PAYLOAD(rta[RTA_GATEWAY]),
				 RTA_DATA(rta[RTA_GATEWAY]));
	}
	peer->protocol_type = nhrp_protocol_from_pf(rtm->rtm_family);
	peer->prefix_length = rtm->rtm_dst_len;
	nhrp_peer_insert(peer);
	nhrp_peer_put(peer);
}

static void netlink_route_del(struct nlmsghdr *msg)
{
	struct nhrp_interface *iface;
	struct rtmsg *rtm = NLMSG_DATA(msg);
	struct rtattr *rta[RTA_MAX+1];
	struct nhrp_peer_selector sel;
	int type = 0;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(msg));
	if (rta[RTA_OIF] == NULL || rta[RTA_DST] == NULL)
		return;

	if (rtm->rtm_family != PF_INET)
		return;

	iface = nhrp_interface_get_by_index(*(int*)RTA_DATA(rta[RTA_OIF]),
					    FALSE);
	if (iface == NULL)
		return;

	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST) {
		/* Local shortcut target routes */
		if (rtm->rtm_table != RT_TABLE_MAIN)
			return;
		type = NHRP_PEER_TYPE_LOCAL_ADDR;
	} else if (iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED) {
		/* Routes which might get additional outbound
		 * shortcuts */
		if (rtm->rtm_table != iface->route_table ||
		    rtm->rtm_protocol == RTPROT_KERNEL)
			return;
		type = NHRP_PEER_TYPE_LOCAL_ROUTE;
	}
	if (type == 0)
		return;

	memset(&sel, 0, sizeof(sel));
	sel.flags = NHRP_PEER_FIND_EXACT_VPN;
	sel.type_mask = BIT(type);
	sel.interface = iface;
	nhrp_address_set(&sel.protocol_address, rtm->rtm_family,
			 RTA_PAYLOAD(rta[RTA_DST]),
			 RTA_DATA(rta[RTA_DST]));
	if (rta[RTA_GATEWAY] != NULL) {
		nhrp_address_set(&sel.next_hop_address,
				 rtm->rtm_family,
				 RTA_PAYLOAD(rta[RTA_GATEWAY]),
				 RTA_DATA(rta[RTA_GATEWAY]));
	}
	sel.prefix_length = rtm->rtm_dst_len;
	nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);
}

static const netlink_dispatch_f route_dispatch[RTM_MAX] = {
	[RTM_GETNEIGH] = netlink_neigh_request,
	[RTM_NEWNEIGH] = netlink_neigh_update,
	[RTM_DELNEIGH] = netlink_neigh_update,
	[RTM_NEWLINK] = netlink_link_new,
	[RTM_DELLINK] = netlink_link_del,
	[RTM_NEWADDR] = netlink_addr_new,
	[RTM_DELADDR] = netlink_addr_del,
	[RTM_NEWROUTE] = netlink_route_new,
	[RTM_DELROUTE] = netlink_route_del,
};

static void netlink_stop_listening(struct netlink_fd *fd)
{
	ev_io_stop(&fd->io);
}

static void netlink_close(struct netlink_fd *fd)
{
	if (fd->fd >= 0) {
		netlink_stop_listening(fd);
		close(fd->fd);
		fd->fd = 0;
	}
}

static int netlink_open(struct netlink_fd *fd, int protocol, int groups)
{
	struct sockaddr_nl addr;
	int buf = NETLINK_KERNEL_BUFFER;

	fd->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	fd->seq = time(NULL);
	if (fd->fd < 0) {
		nhrp_perror("Cannot open netlink socket");
		return FALSE;
	}

	fcntl(fd->fd, F_SETFD, FD_CLOEXEC);
	if (setsockopt(fd->fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_SNDBUF");
		goto error;
	}

	if (setsockopt(fd->fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
		nhrp_perror("SO_RCVBUF");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = groups;
	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		nhrp_perror("Cannot bind netlink socket");
		goto error;
	}

	ev_io_init(&fd->io, netlink_read_cb, fd->fd, EV_READ);
	ev_io_start(&fd->io);

	return TRUE;

error:
	netlink_close(fd);
	return FALSE;
}

static void pfpacket_read_cb(struct ev_io *w, int revents)
{
	struct sockaddr_ll lladdr;
	struct nhrp_interface *iface;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	uint8_t buf[1500];
	struct nhrp_address from;
	int fd = w->fd;
	int i;

	iov.iov_base = buf;
	for (i = 0; i < 2; i++) {
		int status;

		iov.iov_len = sizeof(buf);
		status = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			nhrp_perror("PF_PACKET overrun");
			continue;
		}

		if (status == 0) {
			nhrp_error("PF_PACKET returned EOF");
			return;
		}

		iface = nhrp_interface_get_by_index(lladdr.sll_ifindex, FALSE);
		if (iface == NULL)
			continue;

		nhrp_address_set(&from, PF_INET, lladdr.sll_halen, lladdr.sll_addr);
		if (memcmp(lladdr.sll_addr, "\x00\x00\x00\x00", 4) == 0)
			nhrp_address_set_type(&from, PF_UNSPEC);
		nhrp_packet_receive(buf, status, iface, &from);
	}
}

int kernel_init(void)
{
	int fd, i;

	proc_icmp_redirect_off("all");

	fd = socket(PF_PACKET, SOCK_DGRAM, ETHPROTO_NHRP);
	if (fd < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	ev_io_init(&packet_io, pfpacket_read_cb, fd, EV_READ);
	ev_io_start(&packet_io);

	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++) {
		netlink_fds[i].dispatch_size = sizeof(route_dispatch) / sizeof(route_dispatch[0]);
		netlink_fds[i].dispatch = route_dispatch;
		if (!netlink_open(&netlink_fds[i], NETLINK_ROUTE,
				  netlink_groups[i]))
			goto err_close_all;
	}

	netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETLINK);
	netlink_read_cb(&talk_fd.io, EV_READ);

	netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETADDR);
	netlink_read_cb(&talk_fd.io, EV_READ);

	netlink_enumerate(&talk_fd, PF_UNSPEC, RTM_GETROUTE);
	netlink_read_cb(&talk_fd.io, EV_READ);

	return TRUE;

err_close_all:
	kernel_cleanup();
	return FALSE;
}

void kernel_stop_listening(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++)
		netlink_stop_listening(&netlink_fds[i]);
	ev_io_stop(&packet_io);
}

void kernel_cleanup(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netlink_groups); i++)
		netlink_close(&netlink_fds[i]);
	ev_io_stop(&packet_io);
	close(packet_io.fd);
}

int kernel_route(struct nhrp_interface *out_iface,
		 struct nhrp_address *dest,
		 struct nhrp_address *default_source,
		 struct nhrp_address *next_hop,
		 u_int16_t *mtu)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;
	struct rtmsg *r = NLMSG_DATA(&req.n);
	struct rtattr *rta[RTA_MAX+1];

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = dest->type;

	netlink_add_rtattr_l(&req.n, sizeof(req), RTA_DST,
			     dest->addr, dest->addr_len);
	req.r.rtm_dst_len = dest->addr_len * 8;

	if (default_source != NULL && default_source->type != PF_UNSPEC)
		netlink_add_rtattr_l(&req.n, sizeof(req), RTA_SRC,
				     default_source->addr,
				     default_source->addr_len);
	if (out_iface != NULL)
		netlink_add_rtattr_l(&req.n, sizeof(req), RTA_OIF,
				     &out_iface->index, sizeof(int));

	if (!netlink_talk(&talk_fd, &req.n, sizeof(req), &req.n))
		return FALSE;

	netlink_parse_rtattr(rta, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(&req.n));

	if (default_source != NULL && default_source->type == PF_UNSPEC &&
	    rta[RTA_PREFSRC] != NULL) {
		nhrp_address_set(default_source, dest->type,
				 RTA_PAYLOAD(rta[RTA_PREFSRC]),
				 RTA_DATA(rta[RTA_PREFSRC]));
	}

	if (next_hop != NULL) {
		if (rta[RTA_GATEWAY] != NULL) {
			nhrp_address_set(next_hop, dest->type,
					 RTA_PAYLOAD(rta[RTA_GATEWAY]),
					 RTA_DATA(rta[RTA_GATEWAY]));
		} else {
			*next_hop = *dest;
		}
	}

	if (mtu != NULL) {
		*mtu = 0;

		if (rta[RTA_OIF] != NULL) {
			struct nhrp_interface *nbma_iface;

			/* We use interface MTU here instead of the route
			 * cache MTU from RTA_METRICS/RTAX_MTU since we
			 * don't want to announce mtu if PMTU works */
			nbma_iface = nhrp_interface_get_by_index(
				*(int*)RTA_DATA(rta[RTA_OIF]),
				FALSE);
			if (nbma_iface != NULL)
				*mtu = translate_mtu(nbma_iface->mtu);
		}
	}

	return TRUE;
}

int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_address *to)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = (void*) packet,
		.iov_len = bytes
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int status;

	if (to->addr_len > sizeof(lladdr.sll_addr)) {
		nhrp_error("Destination NBMA address too long");
		return FALSE;
	}
	char tmp[64];
	nhrp_debug("Sending nhrp packet to index:%d %s\n", out->index,
		   nhrp_address_format(to, sizeof(tmp), tmp));

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = ETHPROTO_NHRP;
	lladdr.sll_ifindex = out->index;
	lladdr.sll_halen = to->addr_len;
	memcpy(lladdr.sll_addr, to->addr, to->addr_len);

	status = sendmsg(packet_io.fd, &msg, 0);
	if (status < 0) {
		nhrp_error("Cannot send packet to %s(%d): %s",
			   out->name, out->index, strerror(errno));
		return FALSE;
	}

	return TRUE;
}

int kernel_inject_neighbor(struct nhrp_address *neighbor,
			   struct nhrp_address *hwaddr,
			   struct nhrp_interface *dev)
{
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			buf[256];
	} req;
	char neigh[64], nbma[64];

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWNEIGH;
	req.ndm.ndm_family = neighbor->type;
	req.ndm.ndm_ifindex = dev->index;
	req.ndm.ndm_type = RTN_UNICAST;

	netlink_add_rtattr_l(&req.n, sizeof(req), NDA_DST,
			     neighbor->addr, neighbor->addr_len);

	if (hwaddr != NULL && hwaddr->type != PF_UNSPEC) {
		req.ndm.ndm_state = NUD_REACHABLE;

		netlink_add_rtattr_l(&req.n, sizeof(req), NDA_LLADDR,
				     hwaddr->addr, hwaddr->addr_len);

		nhrp_debug("NL-ARP(%s) %s is-at %s",
			   dev->name,
			   nhrp_address_format(neighbor, sizeof(neigh), neigh),
			   nhrp_address_format(hwaddr, sizeof(nbma), nbma));
	} else {
		req.ndm.ndm_state = NUD_FAILED;

		nhrp_debug("NL-ARP(%s) %s not-reachable",
			   dev->name,
			   nhrp_address_format(neighbor, sizeof(neigh), neigh));
	}

	return netlink_send(&talk_fd, &req.n);
}

int kernel_inject_brneighbor(struct nhrp_address *neighbor,
			     struct nhrp_address *hwaddr,
			     struct nhrp_interface *dev,
			     uint32_t vni)
{
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			buf[256];
	} req;
	char neigh[64], nbma[64];

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWNEIGH;
	req.ndm.ndm_family = neighbor->type;
	req.ndm.ndm_ifindex = dev->index;
	req.ndm.ndm_type = RTN_UNICAST;
	req.ndm.ndm_flags = NTF_SELF;

	if (hwaddr != NULL && hwaddr->type != PF_UNSPEC) {
		netlink_add_rtattr_l(&req.n, sizeof(req), NDA_LLADDR,
				     neighbor->addr, neighbor->addr_len);
		netlink_add_rtattr_l(&req.n, sizeof(req), NDA_DST,
				     hwaddr->addr, hwaddr->addr_len);
		netlink_add_rtattr_l(&req.n, sizeof(req), NDA_VNI,
				     &vni, sizeof(vni));
		nhrp_debug("NL-MAC(%s) %s is-at %s vni: %d",
		   	   dev->name,
		           nhrp_address_format(neighbor, sizeof(neigh),
					       neigh),
		           nhrp_address_format(hwaddr, sizeof(nbma),
			   nbma), vni);
	} else {
		req.ndm.ndm_state = NUD_FAILED;

		nhrp_debug("NL-MAC(%s) %s not-reachable",
			   dev->name,
			   nhrp_address_format(neighbor, sizeof(neigh), neigh));
		return 0;
	}

	/* NUD_NOARP: Don't replace this learned address.
	 * NUD_PERMANENT: No timeout of this entry.
	 */
	req.ndm.ndm_state = (NUD_REACHABLE | NUD_PERMANENT | NUD_NOARP);

	return netlink_send(&talk_fd, &req.n);
}

static void netlink_get_vxlaninfo(struct nhrp_interface *iface,
				  struct rtattr **rta)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	struct rtatrr *vxlaninfo[IFLA_VXLAN_MAX+1];
	char *kind;

	if (!rta[IFLA_LINKINFO])
		return;

	netlink_parse_rtattr(linkinfo, IFLA_INFO_MAX,
			     RTA_DATA(rta[IFLA_LINKINFO]),
			     RTA_PAYLOAD(rta[IFLA_LINKINFO]));
	if (!linkinfo[IFLA_INFO_KIND] || !linkinfo[IFLA_INFO_DATA])
		return;

	kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);
	nhrp_debug("Link kind %s\n", kind);
	if (strcmp(kind, "vxlan") != 0)
		return;

	netlink_parse_rtattr(vxlaninfo, IFLA_VXLAN_MAX,
			     RTA_DATA(linkinfo[IFLA_INFO_DATA]),
			     RTA_PAYLOAD(linkinfo[IFLA_INFO_DATA]));
	if (vxlaninfo[IFLA_VXLAN_ID]) {
		iface->default_vnid = *((uint32_t *)RTA_DATA(vxlaninfo[IFLA_VXLAN_ID]));
		nhrp_debug("Interface: %s vxlanid:0x%x\n", iface->name,
			   iface->default_vnid);
	}
}
