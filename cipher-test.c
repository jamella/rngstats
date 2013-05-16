/*
 *  RNGstats cipher known-answer test and benchmark.
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

#define _GNU_SOURCE

#include "worker.h"
#include "ciphers.h"

#include <stdio.h>
#include <time.h>

static work_order wo;
static work_results wr;

static inline double
timedelta_ns(const struct timespec *end,
             const struct timespec *start)
{
    uint64_t delta_s = end->tv_sec - start->tv_sec;
    long delta_ns    = end->tv_nsec - start->tv_nsec;
    if (delta_ns < 0)
        delta_ns += 1000000000L;

    return delta_ns * 1e-9 + delta_s;
}

int
main(void)
{
    int i;
    struct timespec start, stop;
    double elapsed;

    for (i = 0; all_ciphers[i]; i++)
    {
        fprintf(stderr, "KAT:  %11s... ", all_ciphers[i]->name);
        all_ciphers[i]->selftest();
        fputs("ok\n", stderr);
    }

    for (i = 0; all_ciphers[i]; i++)
    {
        wo.base  = 0;
        wo.limit = 2000;
        wo.cipher_index = i;

        fprintf(stderr, "TIME: %11s... ", all_ciphers[i]->name);
        clock_gettime(CLOCK_MONOTONIC, &start);
        worker_run(&wo, &wr);
        clock_gettime(CLOCK_MONOTONIC, &stop);
        elapsed = timedelta_ns(&stop, &start);

        fprintf(stderr,
                "%zu keys, %9.5fs -> %8.3f keys/s\n",
                wo.limit - wo.base,
                elapsed,
                (wo.limit - wo.base) / elapsed);
    }

    return 0;
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
