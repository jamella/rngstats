/*
 *  RNGstats main program; serial version.
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

#include "ciphers.h"
#include "worker.h"
#include "dataset.h"

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void
update_dataset(dataset *data, work_results *wr)
{
    uint64_t i, j;
    for (i = 0; i < KEYSTREAM_LENGTH; i++)
        for (j = 0; j < 256; j++)
            data->epmf[i][j] += wr->stats[i][j];
}

int
main(int argc, char **argv)
{
    static dataset data;
    static work_order wo;
    static work_results wr;

    char *endp, *dataset_name;
    uint64_t base, count, limit;
    uint32_t cipher_index;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s cipher key-count\n", argv[0]);
        goto list_ciphers;
    }

    for (cipher_index = 0; all_ciphers[cipher_index]; cipher_index++)
        if (!strcmp(all_ciphers[cipher_index]->name, argv[1]))
            break;
    if (!all_ciphers[cipher_index])
    {
        fprintf(stderr, "%s: unrecognized cipher: %s\n", argv[0], argv[1]);
        goto list_ciphers;
    }

    count = strtoumax(argv[2], &endp, 10);
    if (endp == argv[2] || *endp != '\0' || count == 0)
        errx(2, "key count '%s' is not a positive integer", argv[2]);

    dataset_name = 0;
    if (asprintf(&dataset_name, "results/%s.hdf", argv[1]) < 0)
        err(2, "forming dataset name");

    if (dataset_read(dataset_name, &data))
    {
        if (cipher_index != data.cipher_index)
            err(1, "dataset %s: expected cipher %s, see %s",
                dataset_name,
                all_ciphers[cipher_index]->name,
                all_ciphers[data.cipher_index]->name);
    }
    else
    {
        data.highest_key = 0;
        data.cipher_index = cipher_index;
    }

    base  = data.highest_key;
    limit = base + count;

    while (base < limit)
    {
        wo.cipher_index = data.cipher_index;
        wo.base = base;
        if (base + UINT16_MAX > limit)
            wo.limit = limit;
        else
            wo.limit = base + UINT16_MAX + 1;

        fprintf(stderr, "block %"PRIu64"--%"PRIu64"...", wo.base, wo.limit-1);
        worker_run(&wo, &wr);
        fprintf(stderr, "%9.5fs\n", ((double)wr.elapsed_ns) * 1e-9);
        update_dataset(&data, &wr);
        base = wo.limit;
    }
    data.highest_key = limit;
    dataset_write(dataset_name, &data);
    return 0;

    list_ciphers:
        fputs("supported ciphers:", stderr);
        for (int i = 0; all_ciphers[i]; i++)
        {
            putc(' ', stderr);
            fputs(all_ciphers[i]->name, stderr);
        }
        putc('\n', stderr);
        return 2;

}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
