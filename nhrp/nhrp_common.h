/* nhrp_common.h - Generic helper functions
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#ifndef NHRP_COMMON_H
#define NHRP_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <linux/if_ether.h>

struct nhrp_interface;
struct nhrp_address;

extern const char *nhrp_config_file, *nhrp_script_file;
extern int nhrp_running, nhrp_verbose;

/* Logging */
void nhrp_log(int level, const char *format, ...);

#define NHRP_LOG_DEBUG		0
#define NHRP_LOG_INFO		1
#define NHRP_LOG_ERROR		2

#define nhrp_debug(...)						\
	do {							\
		if (nhrp_verbose)				\
			nhrp_log(NHRP_LOG_DEBUG, __VA_ARGS__);	\
	} while(0)

#define nhrp_info(...) \
		nhrp_log(NHRP_LOG_INFO, __VA_ARGS__)

#define nhrp_error(...) \
		nhrp_log(NHRP_LOG_ERROR, __VA_ARGS__)

void nhrp_perror(const char *message);
void nhrp_hex_dump(const char *name, const uint8_t *buf, int bytes);

#define NHRP_BUG_ON(cond) if (cond) { \
	nhrp_error("BUG: failure at %s:%d/%s(): %s!", \
		__FILE__, __LINE__, __func__, #cond); \
	abort(); \
}

/* Initializers for system dependant stuff */
int forward_init(void);
void forward_cleanup(void);
int forward_local_addresses_changed(void);

int kernel_init(void);
void kernel_stop_listening(void);
void kernel_cleanup(void);
int kernel_route(struct nhrp_interface *out_iface,
		 struct nhrp_address *dest,
		 struct nhrp_address *default_source,
		 struct nhrp_address *next_hop,
		 u_int16_t *mtu);
int kernel_send(uint8_t *packet, size_t bytes, struct nhrp_interface *out,
		struct nhrp_address *to);
int kernel_inject_neighbor(struct nhrp_address *neighbor,
			   struct nhrp_address *hwaddr,
			   struct nhrp_interface *dev);
int kernel_inject_brneighbor(struct nhrp_address *neighbor,
			   struct nhrp_address *hwaddr,
			   struct nhrp_interface *dev, uint32_t vni);

int log_init(void);
int admin_init(const char *socket);
void server_init(void);

#endif
