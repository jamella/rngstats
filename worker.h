/*
 *  RNGstats worker bee.
 *  Copyright 2013 Zack Weinberg <zackw@panix.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef WORKERS_H__
#define WORKERS_H__

#include <stdint.h>

/* We analyze the first KEYSTREAM_LENGTH bytes of keystream produced
   by each key.  This is a compile-time parameter.  */

enum { KEYSTREAM_LENGTH = 65536ul };

/* Data input to each worker, telling it what to do. */
typedef struct
{
    /* Process key indices BASE through LIMIT. */
    uint64_t base;
    uint64_t limit;

    /* Operate on the cipher at this index in all_ciphers.  */
    uint32_t cipher_index;
} work_order;

/* Data output from each worker. */
typedef struct
{
    /* Time elapsed to process the block, in nanoseconds. */
    uint64_t overhead_ns;
    uint64_t cipher_ns;
    uint64_t stats_ns;

    /* Statistics output.  */
    uint16_t stats[KEYSTREAM_LENGTH][256];
} work_results;

extern void worker_run(const work_order *in, work_results *out);

#endif

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
