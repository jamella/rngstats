/*
 *  RNGstats dataset reading and writing.
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

#define _BSD_SOURCE

#include "worker.h"
#include "dataset.h"

#include <err.h>
#include <inttypes.h>
#include <stdio.h>

static void
update_dataset(dataset *data, work_results *wr)
{
    uint64_t i, j;
    for (i = 0; i < KEYSTREAM_LENGTH; i++)
        for (j = 0; j < 256; j++)
            data->aggregate[i][j] += wr->stats[i][j];
}

int
main(int argc, char **argv)
{
    static dataset data;
    static work_order wo;
    static work_results wr;

    char *endp;
    uint64_t base, count, limit;

    if (argc != 3)
        errx(2, "need a data file and a key count");

    count = strtoumax(argv[2], &endp, 10);
    if (endp == argv[2] || *endp != '\0' || count == 0)
        errx(2, "key count must be a positive integer");

    read_dataset(argv[1], &data);

    base  = data.highest_key;
    limit = base + count;

    while (base < limit)
    {
        wo.cipher_index = data.cipher_index;
        wo.base = base;
        if (base + UINT16_MAX > limit)
            wo.limit = limit;
        else
            wo.limit = base + UINT16_MAX;

        fprintf(stderr, "block %"PRIu64"--%"PRIu64"...", wo.base, wo.limit);
        worker_run(&wo, &wr);
        fprintf(stderr, "%9.5fs\n", ((double)wr.elapsed_ns) * 1e-9);
        update_dataset(&data, &wr);
        base = wo.limit;
    }
    data.highest_key = limit;
    write_dataset(argv[1], &data);
    return 0;
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
