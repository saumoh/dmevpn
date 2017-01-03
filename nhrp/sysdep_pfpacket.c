/* sysdep_pfpacket.c - Tracing of forwarded packets using PF_PACKET
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "libev.h"
#include "nhrp_defines.h"
#include "nhrp_common.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

#define UDP_VXLAN_DEST 8472
struct vxlan_hdr {
	uint32_t vxlan_flags;
	uint32_t vnid;
};

struct multicast_packet {
	struct nhrp_interface *iface;
	struct sockaddr_ll lladdr;
	unsigned int pdulen;
	unsigned char pdu[1500];
};

static struct ev_io packet_io;
static struct ev_timer install_filter_timer;
static struct ev_idle mcast_route;

static struct multicast_packet mcast_queue[16];
static int mcast_head = 0, mcast_tail = 0;

/* bridge packet handlers */
struct l2_packet {
	struct nhrp_interface *iface;
	struct sockaddr_ll lladdr;
	unsigned int pdulen;
	unsigned char pdu[1500];
};
static struct ev_io bridge_io;
static struct ev_timer install_br_filter_timer;
static struct ev_idle bridge_fwd;

static struct l2_packet br_queue[16];
static int br_head = 0, br_tail = 0;

enum {
	LABEL_NEXT = 0,
	LABEL_SKIP1,
	LABEL_SKIPN,
	LABEL_DROP,
	LABEL_ACCEPT_IPv4_MULTICAST,
	LABEL_UNICAST_IPv4,
	LABEL_CHECK_NON_LOCAL_ADDRESS,
	LABEL_ACCEPT_L2,
	NUM_LABELS
};

struct filter {
	int pos[NUM_LABELS];
	int numops, numalloc;
	struct sock_filter *code;
};

static int checkfilter(struct filter *f)
{
	if (f->numops < f->numalloc)
		return 1;

	if (f->numalloc < 0)
		return 0;

	if (f->numalloc)
		f->numalloc *= 2;
	else
		f->numalloc = 128;

	f->code = realloc(f->code, f->numalloc * sizeof(struct sock_filter));
	if (f->code == NULL) {
		f->numalloc = -1;
		return 0;
	}

	return 1;
}

static void emit_stmt(struct filter *f, __u16 code, __u32 k)
{
	if (checkfilter(f)) {
		f->code[f->numops].code = code;
		f->code[f->numops].jt = 0;
		f->code[f->numops].jf = 0;
		f->code[f->numops].k = k;
	}
	f->numops++;
}

static void emit_jump(struct filter *f, __u16 code, __u32 k, __u8 jt, __u8 jf)
{
	if (checkfilter(f)) {
		f->code[f->numops].code = code;
		f->code[f->numops].jt = jt;
		f->code[f->numops].jf = jf;
		f->code[f->numops].k = k;
	}
	f->numops++;
}

static void mark(struct filter *f, int label)
{
	f->pos[label] = f->numops;
}

static int check_interface_multicast(void *ctx, struct nhrp_interface *iface)
{
	struct filter *f = (struct filter *) ctx;

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return 0;
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		return 0;

	if (iface->mcast_mask || iface->mcast_numaddr)
		emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, iface->index,
			  LABEL_ACCEPT_IPv4_MULTICAST, LABEL_NEXT);

	return 0;
}

static int check_interface_layer2(void *ctx, struct nhrp_interface *iface)
{
	struct filter *f = (struct filter *) ctx;

	if (!(iface->flags & NHRP_INTERFACE_FLAG_L2LEARNONLY &&
	      iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST))
		return 0;

	nhrp_debug("emit for %s\n", iface->name);
	emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, iface->index,
		  LABEL_ACCEPT_L2, LABEL_NEXT);

	return 0;
}

/* Check if this instance should be listening and filtering for
 * layer-2 broadcast traffic on datapath interface which carry
 * vxlan traffic.
 */
static int check_interface_l2_bcast(void *ctx, struct nhrp_interface *iface)
{
	uint32_t *check = ctx;

	if (!(iface->flags & NHRP_INTERFACE_FLAG_L2LEARNONLY &&
	      iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST))
		return 0;
	*check += 1;
	return 0;
}

static int drop_matching_address(void *ctx, struct nhrp_peer *peer)
{
	struct filter *f = (struct filter *) ctx;
	unsigned long addr, mask;

	if (peer->protocol_type != ETHPROTO_IP)
		return 0;

	addr = htonl(*((unsigned long *) peer->protocol_address.addr));
	if (peer->prefix_length != 32) {
		mask = 0xffffffff >> peer->prefix_length;
		emit_jump(f, BPF_JMP|BPF_JGE|BPF_K, addr & ~mask, LABEL_NEXT, LABEL_SKIP1);
		emit_jump(f, BPF_JMP|BPF_JGT|BPF_K, addr |  mask, LABEL_NEXT, LABEL_DROP);
	} else {
		emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, addr, LABEL_DROP, LABEL_NEXT);
	}

	return 0;
}

static int check_interface_traffic_indication(void *ctx, struct nhrp_interface *iface)
{
	struct filter *f = (struct filter *) ctx;

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return 0;
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		return 0;
	if (!(iface->flags & NHRP_INTERFACE_FLAG_REDIRECT))
		return 0;

	emit_jump(f, BPF_JMP|BPF_JEQ|BPF_K, iface->index,
		  LABEL_CHECK_NON_LOCAL_ADDRESS, LABEL_NEXT);

	return 0;
}

static void install_filter_cb(struct ev_timer *w, int revents)
{
	struct nhrp_peer_selector sel;
	struct sock_fprog prog;
	struct filter f;
	int i;

	memset(&prog, 0, sizeof(prog));
	memset(&f, 0, sizeof(f));

	/* Check for IPv4 */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_PROTOCOL);
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K,   ETH_P_IP, LABEL_NEXT, LABEL_DROP);

	/* Check for multicast IPv4 destination */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, offsetof(struct iphdr, daddr));
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xe0000000, LABEL_NEXT, LABEL_UNICAST_IPv4);
	emit_jump(&f, BPF_JMP|BPF_JGE|BPF_K, 0xf0000000, LABEL_UNICAST_IPv4, LABEL_NEXT);

	/* MULTICAST */
	/* 1. Check that it is outgoing packet */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_PKTTYPE);
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, PACKET_OUTGOING,  LABEL_NEXT, LABEL_DROP);
	/* 2. Check that we are on multicast enabled interface */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_IFINDEX);
	nhrp_interface_foreach(check_interface_multicast, &f);
	emit_stmt(&f, BPF_RET|BPF_K, 0);
	/* 3. Return the whole packet */
	mark(&f, LABEL_ACCEPT_IPv4_MULTICAST);
	emit_stmt(&f, BPF_RET|BPF_K, 65535);

	/* UNICAST */
	mark(&f, LABEL_UNICAST_IPv4);
	/* 1. Check that it is for us */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_PKTTYPE);
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, PACKET_HOST, LABEL_NEXT, LABEL_DROP);
	/* 2. Check that traffic indication enabled for the interface */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_IFINDEX);
	nhrp_interface_foreach(check_interface_traffic_indication, &f);
	emit_stmt(&f, BPF_RET|BPF_K, 0);
	/* 3. Check that it is a non-local IP address */
	mark(&f, LABEL_CHECK_NON_LOCAL_ADDRESS);
	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ADDR);
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, offsetof(struct iphdr, daddr));
	nhrp_peer_foreach(drop_matching_address, &f, &sel);
	/* 4. Return the header for Traffic Indication packet */
	emit_stmt(&f, BPF_RET|BPF_K, 68);

	mark(&f, LABEL_DROP);
	emit_stmt(&f, BPF_RET|BPF_K, 0);

	/* All ok so far? */
	if (f.numalloc < 0) {
		nhrp_error("Unable to construct filter code: out of memory (code actual length %d)",
			   f.numops);
		return;
	}

	/* Fixup jumps to be relative */
	for (i = 0; i < f.numops; i++) {
		if (BPF_CLASS(f.code[i].code) == BPF_JMP) {
			if (f.code[i].jt > LABEL_SKIPN)
				f.code[i].jt = f.pos[f.code[i].jt] - i - 1;
			if (f.code[i].jf > LABEL_SKIPN)
				f.code[i].jf = f.pos[f.code[i].jf] - i - 1;
		}
	}

	/* Attach filter */
	prog.len = f.numops;
	prog.filter = f.code;
	if (setsockopt(packet_io.fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &prog, sizeof(prog)))
		nhrp_perror("Failed to install filter code");
	else
		nhrp_info("Filter code installed (%d opcodes)", f.numops);

	free(f.code);
}

int forward_local_addresses_changed(void)
{
	if (install_filter_timer.cb != NULL)
		ev_timer_start(&install_filter_timer);
	return TRUE;
}

static void install_filter_l2_cb(struct ev_timer *w, int revents)
{
	struct sock_fprog prog;
	struct filter f;
	int i;

	memset(&prog, 0, sizeof(prog));
	memset(&f, 0, sizeof(f));

	/* Check for IPv4 */
	emit_stmt(&f, BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF+SKF_AD_PROTOCOL);
	emit_jump(&f, BPF_JMP| BPF_JEQ|BPF_K,   ETH_P_IP, LABEL_NEXT, LABEL_DROP);
	/* Check for UDP */
	emit_stmt(&f, BPF_LD| BPF_B | BPF_ABS, offsetof(struct iphdr, protocol));
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, LABEL_NEXT, LABEL_DROP);
	/* Check for dest=8472 */
	emit_stmt(&f, BPF_LD|BPF_H |BPF_ABS, sizeof(struct iphdr)+offsetof(struct udphdr, dest));
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, UDP_VXLAN_DEST, LABEL_NEXT, LABEL_DROP);
	/* Check for inside packet dest-mac = 0xffffffffff */
	emit_stmt(&f, BPF_LD|BPF_W |BPF_ABS,
		  sizeof(struct iphdr)+sizeof(struct udphdr)+
		  sizeof(struct vxlan_hdr)+offsetof(struct ethhdr, h_dest));
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, 0xffffffff, LABEL_NEXT, LABEL_DROP);
	emit_stmt(&f, BPF_LD|BPF_B |BPF_ABS,
		  sizeof(struct iphdr)+sizeof(struct udphdr)+
		  sizeof(struct vxlan_hdr)+offsetof(struct ethhdr, h_dest)+
		  sizeof(__u32));
	emit_jump(&f, BPF_JMP|BPF_JEQ|BPF_K, 0xff, LABEL_NEXT, LABEL_DROP);
	/* check for interface configuration */
	emit_stmt(&f, BPF_LD |BPF_W  |BPF_ABS, SKF_AD_OFF+SKF_AD_IFINDEX);
	nhrp_interface_foreach(check_interface_layer2, &f);
	emit_stmt(&f, BPF_RET|BPF_K, 0);

	mark(&f, LABEL_ACCEPT_L2);
	emit_stmt(&f, BPF_RET|BPF_K, 65535);

	mark(&f, LABEL_DROP);
	emit_stmt(&f, BPF_RET|BPF_K, 0);

	/* All ok so far? */
	if (f.numalloc < 0) {
		nhrp_error("Unable to construct filter code: out of memory (code actual length %d)",
			   f.numops);
		return;
	}

	/* Fixup jumps to be relative */
	for (i = 0; i < f.numops; i++) {
		if (BPF_CLASS(f.code[i].code) == BPF_JMP) {
			if (f.code[i].jt > LABEL_SKIPN)
				f.code[i].jt = f.pos[f.code[i].jt] - i - 1;
			if (f.code[i].jf > LABEL_SKIPN)
				f.code[i].jf = f.pos[f.code[i].jf] - i - 1;
		}
	}

	/* Attach filter */
	prog.len = f.numops;
	prog.filter = f.code;
	if (setsockopt(bridge_io.fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &prog, sizeof(prog)))
		nhrp_perror("Failed to install lfilter code");
	else
		nhrp_info("Filter code installed l2 (%d opcodes)", f.numops);

	free(f.code);
}

static void send_multicast(struct ev_idle *w, int revents)
{
	struct multicast_packet *pkt;
	struct nhrp_peer *peer;
	struct iovec iov;
	struct msghdr msg;

	if (mcast_head == mcast_tail) {
		ev_idle_stop(&mcast_route);
		return;
	}

	/* Pop a packet */
	pkt = &mcast_queue[mcast_tail];
	mcast_tail = (mcast_tail + 1) % ARRAY_SIZE(mcast_queue);

	/* And softroute it forward */
	iov.iov_base = pkt->pdu;
	iov.iov_len = pkt->pdulen;
	msg = (struct msghdr) {
		.msg_name = &pkt->lladdr,
		.msg_namelen = sizeof(pkt->lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	list_for_each_entry(peer, &pkt->iface->mcast_list, mcast_list_entry) {
		/* Update NBMA destination */
		pkt->lladdr.sll_halen = peer->next_hop_address.addr_len;
		memcpy(pkt->lladdr.sll_addr, peer->next_hop_address.addr,
		       pkt->lladdr.sll_halen);

		/* Best effort attempt to emulate multicast */
		(void) sendmsg(packet_io.fd, &msg, 0);
	}
}

static inline int16_t udp_src_hash(uint32_t *a, uint32_t *b)
{
	uint32_t hash = *a ^ *b;
	uint16_t h1;
	while (hash >> 16) {
		h1 = hash >> 16;
		hash = hash & ((1 << 16) -1);
		hash ^= h1;
	}
	if (hash < 49152) {
		hash = 49152 + (hash %(0xFFFF - 49152));
	}
	return htons(hash & 0xFFFF);
}

/* fill input buffer with udp + vxlan header */
static int fill_udp_vxlan_pkt(uint8_t *buf, size_t buflen,
			     struct nhrp_address *src,
			     struct nhrp_address *dst,
			     uint32_t vnid, size_t l_payload)
{
	struct udphdr *udph = (struct udphdr *) buf;

	struct vxlan_hdr *vxlanh = (struct vxlan_hdr *)&buf[sizeof(*udph)];

	if (buflen < (sizeof(*udph)+sizeof(*vxlanh)))
		return -1;

	memset(buf, 0, buflen);

	/* fill in the UDP header */
	udph->source = udp_src_hash((uint32_t *)src->addr, (uint32_t *)dst->addr);
	udph->dest = htons(8472);
	udph->len = htons(l_payload+sizeof(*vxlanh)+sizeof(*udph));
	udph->check = 0;

	/* fill in the vxlan header */
	vnid = (vnid & ((0x1 << 24)-1)) << 8;
	nhrp_debug("vnid host order: 0x%x, net: 0x%x\n", vnid, htonl(vnid));
	vxlanh->vnid = htonl(vnid);
	vxlanh->vxlan_flags = htonl(1<<27);
	nhrp_debug("vxlan flags net: 0x%x\n", vxlanh->vxlan_flags);
	return 0;
}

static void send_l2(struct ev_idle *w, int revents)
{
	struct l2_packet *pkt;
	struct iovec iov[2];
	struct msghdr msg;
	uint8_t udp_vxlan_hdr[16];
	struct nhrp_interface *iface, *controlif;
	struct nhrp_peer *p;
	int r;
	struct send_l2_fd {
		int init;
		int ip_sock;
	};
	static struct send_l2_fd txio;
	void *sent_list;
	uint32_t l2off = sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct vxlan_hdr);
	uint32_t *src_vxlan;

	if (br_head == br_tail) {
		ev_idle_stop(&bridge_fwd);
		return;
	}

	/* Pop a packet */
	pkt = &br_queue[br_tail];
	br_tail = (br_tail + 1) % ARRAY_SIZE(br_queue);

	iov[0].iov_base = &udp_vxlan_hdr;
	iov[0].iov_len = sizeof(udp_vxlan_hdr);
	iov[1].iov_base = pkt->pdu + l2off;
	iov[1].iov_len = pkt->pdulen - l2off;
	msg = (struct msghdr) {
		.msg_iov = iov,
		.msg_iovlen = 2,
	};

	if (txio.init == 0) {
		/* setup the socket now for sending vxlan traffic */
		txio.ip_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if (txio.ip_sock < 0) {
			nhrp_debug("No IP socket available.\n");
			return;
		}
		txio.init = 1;
	}

	controlif = pkt->iface->controlif;
	if (!controlif)
		return;
	sent_list = nhrp_address_slist_init(0);

	/* source of the vxlan packet. */
	src_vxlan = (uint32_t *)(pkt->pdu + offsetof(struct iphdr, saddr));

	list_for_each_entry(iface, &controlif->child_intf_list, sibling_list_entry) {
		list_for_each_entry(p, &iface->peer_list, peer_list_entry) {
			char src[32], dst[32];
			uint32_t *d = (uint32_t *)p->next_hop_address.addr;
			struct sockaddr_in dstsock = (struct sockaddr_in) {
				.sin_family = AF_INET,
				.sin_port = htons(IPPROTO_IP),
				/* already in net byte order */
				.sin_addr.s_addr = *d,
			};
			/* don't send packet back to the sender. */
			if (!memcmp(src_vxlan, p->next_hop_address.addr, sizeof(*src_vxlan)))
				continue;
			if (nhrp_address_slist_exists(sent_list, &p->next_hop_address))
				continue;
			msg.msg_name = &dstsock;
			msg.msg_namelen = sizeof(dstsock);
			nhrp_debug("Send bcast src %s dst %s vni: %d\n",
				   nhrp_address_format(&controlif->nbma_address, sizeof(src), src),
				   nhrp_address_format(&p->next_hop_address, sizeof(dst), dst),
				   p->vnid);
			r = fill_udp_vxlan_pkt(udp_vxlan_hdr, sizeof(udp_vxlan_hdr),
					       &controlif->nbma_address,
				              &p->next_hop_address,
				              p->vnid,
				              (size_t )(pkt->pdulen-l2off));
			if (r)
				continue;
			/* Best effort attempt to emulate multicast */
			r = sendmsg(txio.ip_sock, &msg, 0);
			if (r < 0)
				nhrp_debug("[%d] send msg err: %d/%s 0x%x\n",
					   txio.ip_sock, r, strerror(errno), *d);
			else
				nhrp_address_slist_add(sent_list, &p->next_hop_address);
		}
	}
	nhrp_address_slist_rm(sent_list);
}

static void pfp_read_cb(struct ev_io *w, int revents)
{
	struct nhrp_address nbma_src, src, dst;
	struct nhrp_interface *iface;
	struct sockaddr_ll *lladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char fr[32], to[32];
	int r, fd = w->fd;

	if (!(revents & EV_READ))
		return;

	while (TRUE) {
		/* Get a scracth buffer directly from mcast queue, so we do
		 * not need copy the data later. */
		msg.msg_name = &mcast_queue[mcast_head].lladdr;
		msg.msg_namelen = sizeof(mcast_queue[mcast_head].lladdr);
		iov.iov_base = mcast_queue[mcast_head].pdu;
		iov.iov_len = sizeof(mcast_queue[mcast_head].pdu);

		/* Receive */
		r = recvmsg(fd, &msg, MSG_DONTWAIT);
		mcast_queue[mcast_head].pdulen = r;

		/* Process */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			nhrp_perror("PF_PACKET overrun");
			continue;
		}

		if (r == 0) {
			nhrp_error("PF_PACKET returned EOF");
			return;
		}

		lladdr = &mcast_queue[mcast_head].lladdr;
		if (lladdr->sll_pkttype != PACKET_OUTGOING &&
		    lladdr->sll_pkttype != PACKET_HOST)
			continue;

		iface = nhrp_interface_get_by_index(lladdr->sll_ifindex, FALSE);
		if (iface == NULL)
			continue;
		if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
			continue;

		if (!nhrp_address_parse_packet(lladdr->sll_protocol,
					       r, iov.iov_base,
					       &src, &dst))
			return;

		if (nhrp_address_is_multicast(&dst)) {
			if (lladdr->sll_pkttype != PACKET_OUTGOING)
				continue;

			nhrp_debug("Multicast from %s to %s",
				   nhrp_address_format(&src, sizeof(fr), fr),
				   nhrp_address_format(&dst, sizeof(to), to));

			/* Queue packet for processing later (handle important
			 * stuff first) */
			mcast_queue[mcast_head].iface = iface;
			mcast_head = (mcast_head + 1) % ARRAY_SIZE(mcast_queue);

			/* Drop packets from queue tail, if we haven't processed
			 * them yet. */
			if (mcast_head == mcast_tail)
				mcast_tail = (mcast_tail + 1) %
					ARRAY_SIZE(mcast_queue);

			ev_idle_start(&mcast_route);
		} else {
			if (lladdr->sll_pkttype != PACKET_HOST)
				continue;

			nhrp_address_set(&nbma_src, PF_INET,
					 lladdr->sll_halen,
					 lladdr->sll_addr);
			nhrp_packet_send_traffic(iface,
						 &nbma_src, &src, &dst,
						 lladdr->sll_protocol,
						 iov.iov_base, r);
		}
	}
}

static void pfp_l2_cb(struct ev_io *w, int revents)
{
	struct nhrp_interface *iface;
	struct sockaddr_ll *lladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int r, fd = w->fd;

	if (!(revents & EV_READ))
		return;

	while (TRUE) {
		/* Get a scracth buffer directly from mcast queue, so we do
		 * not need copy the data later. */
		msg.msg_name = &br_queue[br_head].lladdr;
		msg.msg_namelen = sizeof(br_queue[br_head].lladdr);
		iov.iov_base = br_queue[br_head].pdu;
		iov.iov_len = sizeof(mcast_queue[br_head].pdu);

		/* Receive */
		r = recvmsg(fd, &msg, MSG_DONTWAIT);
		br_queue[br_head].pdulen = r;

		/* Process */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			nhrp_perror("PF_PACKET overrun");
			continue;
		}

		if (r == 0) {
			nhrp_error("PF_PACKET returned EOF");
			return;
		}

		nhrp_debug("[] L2 Broadcast rx'd");
		lladdr = &br_queue[br_head].lladdr;
		if (lladdr->sll_pkttype != PACKET_HOST)
			continue;

		iface = nhrp_interface_get_by_index(lladdr->sll_ifindex, FALSE);
		if (iface == NULL)
			continue;

		if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
			continue;

		nhrp_debug("[%s] L2 Broadcast rx'd",
			   iface->name);

		/* Queue packet for processing later (handle important
		* stuff first) */
		br_queue[br_head].iface = iface;
		br_head = (br_head + 1) % ARRAY_SIZE(br_queue);

		/* Drop packets from queue tail, if we haven't processed
		 * them yet. */
		if (br_head == br_tail)
			br_tail = (br_tail + 1) % ARRAY_SIZE(br_queue);
		ev_idle_start(&bridge_fwd);
	}
}

int forward_init(void)
{
	int fd, fdl2;

	fd = socket(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ALL));
	if (fd < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	ev_io_init(&packet_io, pfp_read_cb, fd, EV_READ);
	ev_io_start(&packet_io);

	ev_timer_init(&install_filter_timer, install_filter_cb, .01, .0);
	install_filter_cb(&install_filter_timer, 0);

	ev_idle_init(&mcast_route, send_multicast);
	ev_set_priority(&mcast_route, -1);

	uint32_t check = 0;
	nhrp_interface_foreach(check_interface_l2_bcast, &check);
	if (check == 0) {
		nhrp_debug("Don't snoop for bcast vxlan traffic\n");
		return TRUE;
	}

	fdl2 = socket(PF_PACKET, SOCK_DGRAM, ntohs(ETH_P_ALL));
	if (fdl2 < 0) {
		nhrp_error("Unable to create PF_PACKET socket");
		return FALSE;
	}

	fcntl(fdl2, F_SETFD, FD_CLOEXEC);

	ev_io_init(&bridge_io, pfp_l2_cb, fdl2, EV_READ);
	ev_io_start(&bridge_io);

	ev_timer_init(&install_br_filter_timer, install_filter_l2_cb, .01, .0);
	install_filter_l2_cb(&install_br_filter_timer, 0);

	ev_idle_init(&bridge_fwd, send_l2);
	ev_set_priority(&bridge_fwd, -1);
	return TRUE;
}

void forward_cleanup(void)
{
	ev_io_stop(&packet_io);
	close(packet_io.fd);
	ev_timer_stop(&install_filter_timer);
	ev_idle_stop(&mcast_route);
}
