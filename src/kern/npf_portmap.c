/*-
 * Copyright (c) 2014-2019 Mindaugas Rasiukevicius <rmind at netbsd org>
 * Copyright (c) 2010-2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF port map mechanism.
 *
 *	The port map is a bitmap used to track TCP/UDP ports used for
 *	translation.  Port maps are per IP addresses, therefore multiple
 *	NAT policies operating on the same IP address will share the
 *	same port map.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>

#include <sys/atomic.h>
#include <sys/bitops.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/cprng.h>
#include <sys/thmap.h>
#endif

#include "npf_impl.h"

/*
 * NPF portmap structure.
 */
struct npf_portmap {
	unsigned		p_refcnt;
	uint32_t		p_bitmap[0];
};

/* Portmap range: [ 1024 .. 65535 ] */
#define	PORTMAP_FIRST		(1024)
#define	PORTMAP_SIZE		((65536 - PORTMAP_FIRST) / 32)
#define	PORTMAP_FILLED		((uint32_t)~0U)
#define	PORTMAP_MASK		(31)
#define	PORTMAP_SHIFT		(5)

#define	PORTMAP_MEM_SIZE	\
    (sizeof(npf_portmap_t) + (PORTMAP_SIZE * sizeof(uint32_t)))

void
npf_portmap_init(npf_t *npf)
{
	npf->portmaps = thmap_create(0, NULL, 0);
	KASSERT(npf->portmaps != NULL);
}

void
npf_portmap_fini(npf_t *npf)
{
	thmap_destroy(npf->portmaps);
}

static npf_portmap_t *
npf_portmap_create_or_get(npf_t *npf, int alen, const npf_addr_t *addr)
{
	npf_portmap_t *pm;

	KASSERT(alen <= sizeof(npf_addr_t));

	/* Lookup the port map for this address. */
	pm = thmap_get(npf->portmaps, addr, alen);
	if (pm == NULL) {
		void *ret;

		/* Allocate a new port map for this address. */
		pm = kmem_zalloc(PORTMAP_MEM_SIZE, KM_SLEEP);
		pm->p_refcnt = 1;

		ret = thmap_put(npf->portmaps, addr, alen, pm);
		if (ret != pm) {
			/* Race: use an existing port map. */
			kmem_free(pm, PORTMAP_MEM_SIZE);
			pm = ret;
		}
	}
	KASSERT((uintptr_t)pm->p_bitmap == (uintptr_t)pm + sizeof(*pm));
	KASSERT(pm->p_refcnt > 0);
	return pm;
}

void
npf_portmap_destroy(npf_portmap_t *pm)
{
	KASSERT(pm->p_refcnt == 0);
	kmem_free(pm, PORTMAP_MEM_SIZE);
}

/*
 * npf_portmap_get: allocate and return a port from the given portmap.
 *
 * => Returns the port value in network byte-order.
 * => Zero indicates a failure.
 */
in_port_t
npf_portmap_get(npf_t *npf, int alen, const npf_addr_t *addr)
{
	npf_portmap_t *pm = npf_portmap_create_or_get(npf, alen, addr);
	unsigned n = PORTMAP_SIZE, idx, bit;
	uint32_t map, nmap;

	idx = cprng_fast32() % PORTMAP_SIZE;
	for (;;) {
		KASSERT(idx < PORTMAP_SIZE);
		map = pm->p_bitmap[idx];
		if (__predict_false(map == PORTMAP_FILLED)) {
			if (n-- == 0) {
				/* No space. */
				return 0;
			}
			/* This bitmap is filled, next. */
			idx = (idx ? idx : PORTMAP_SIZE) - 1;
			continue;
		}
		bit = ffs32(~map) - 1;
		nmap = map | (1U << bit);
		if (atomic_cas_32(&pm->p_bitmap[idx], map, nmap) == map) {
			/* Success. */
			break;
		}
	}
	return htons(PORTMAP_FIRST + (idx << PORTMAP_SHIFT) + bit);
}

/*
 * npf_portmap_take: allocate a specific port in the portmap.
 */
bool
npf_portmap_take(npf_t *npf, int alen, const npf_addr_t *addr, in_port_t port)
{
	npf_portmap_t *pm = npf_portmap_create_or_get(npf, alen, addr);
	uint32_t map, nmap;
	unsigned idx, bit;

	port = ntohs(port) - PORTMAP_FIRST;
	idx = port >> PORTMAP_SHIFT;
	bit = port & PORTMAP_MASK;
	map = pm->p_bitmap[idx];
	nmap = map | (1U << bit);
	if (map == nmap) {
		/* Already taken. */
		return false;
	}
	return atomic_cas_32(&pm->p_bitmap[idx], map, nmap) == map;
}

/*
 * npf_portmap_put: release the port, making it available in the portmap.
 *
 * => The port value should be in network byte-order.
 */
void
npf_portmap_put(npf_t *npf, int alen, const npf_addr_t *addr, in_port_t port)
{
	npf_portmap_t *pm = npf_portmap_create_or_get(npf, alen, addr);
	uint32_t map, nmap;
	unsigned idx, bit;

	KASSERT(pm->p_refcnt > 0);

	port = ntohs(port) - PORTMAP_FIRST;
	idx = port >> PORTMAP_SHIFT;
	bit = port & PORTMAP_MASK;
	do {
		map = pm->p_bitmap[idx];
		KASSERT(map | (1U << bit));
		nmap = map & ~(1U << bit);
	} while (atomic_cas_32(&pm->p_bitmap[idx], map, nmap) != map);
}
