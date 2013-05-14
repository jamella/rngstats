/*
 *  RNGstats main program.
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

#include "config.h"
#include "ciphers.h"
#include "worker.h"

#include <stdio.h>

static work_order wo;
static work_results wr;

int
main(void)
{
    int i;
    for (i = 0; all_ciphers[i]; i++)
    {
        fprintf(stderr, "SELFTEST: %11s... ", all_ciphers[i]->name);
        all_ciphers[i]->selftest();
        fputs("ok\n", stderr);
    }

    for (i = 0; all_ciphers[i]; i++)
    {
        wo.base  = 0;
        wo.limit = 1024;
        wo.cipher_index = i;

        fprintf(stderr, "TIME: %11s... ", all_ciphers[i]->name);
        worker_run(&wo, &wr);
        fprintf(stderr, "c=%.6f s=%.6f o=%.6f -> %.3f keys/s\n",
                ((double)wr.cipher_ns) * 1e-6,
                ((double)wr.stats_ns) * 1e-6,
                ((double)wr.overhead_ns) * 1e-6,
                1.0 / (((double)(wr.cipher_ns + wr.stats_ns + wr.overhead_ns)
                        / 1024) * 1e-9)
                );
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
