/*
 *  RNGstats main program; MPI version.
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <mpi.h>

static MPI_Datatype dt_work_order;

static volatile sig_atomic_t interrupted;

static void
interrupt(int unused __attribute__((unused)))
{
    if (!interrupted)
        write(2, "(interrupted, exiting at next opportunity)\n",
              sizeof "(interrupted, exiting at next opportunity)\n" - 1);
    interrupted = 1;
}

static void * __attribute__((malloc))
xmalloc(size_t sz)
{
    void *rv = malloc(sz);
    if (!rv)
    {
        perror("memory allocation failure");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    return rv;
}

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

static double
interval(clockid_t clk, struct timespec *start)
{
    struct timespec end;
    double delta;
    clock_gettime(clk, &end);
    delta = timedelta_ns(&end, start);
    *start = end;
    return delta;
}

static void
head_process(int numprocs, const char *dataset_name,
             uint64_t count, uint64_t checkpoint_interval,
             dataset *data)
{
    /* We need work_order objects for every process, but we only need
       a work_results object for this one, It does not appear to
       be possible to do a direct reduction into data.epmf (we would
       need MPI to do += instead of = on the receive buffer), but we
       can at least do an in-place receive to save having a _third_
       buffer on this process.  */
    work_order   *wo = xmalloc(sizeof(work_order) * numprocs);
    work_results *wr  = xmalloc(sizeof(work_results));
    work_order mywo;
    uint64_t base, step, stride, sofar, since_last_checkpoint;
    struct timespec wall;
    double dwall;

    step = count / numprocs;
    if (step > UINT16_MAX+1)
    {
        step = UINT16_MAX+1;
        stride = step * numprocs;
    }
    else
        stride = count;
    base = data->highest_key;
    sofar = 0;
    since_last_checkpoint = 0;

    clock_gettime(CLOCK_MONOTONIC, &wall);
    signal(SIGUSR1, interrupt);

    while (sofar < count && !interrupted)
    {
        /* Reinitialize work orders on each pass in case MPI_Scatter
           clobbers them. */
        for (int i = 0; i < numprocs; i++)
        {
            wo[i].base  = base + sofar + i*step;
            if (wo[i].base > base + count)
                wo[i].base = base + count;

            wo[i].limit = base + sofar + (i+1)*step;
            if (wo[i].limit > base + count)
                wo[i].limit = base + count;

            wo[i].cipher_index = data->cipher_index;
        }

        MPI_Scatter(wo, 1, dt_work_order,
                    &mywo, 1, dt_work_order,
                    0, MPI_COMM_WORLD);

        worker_run(&mywo, wr);

        MPI_Reduce(MPI_IN_PLACE, wr->epmf,
                   KEYSTREAM_LENGTH * 256, MPI_UINT32_T, MPI_SUM,
                   0, MPI_COMM_WORLD);

        for (size_t i = 0; i < KEYSTREAM_LENGTH; i++)
            for (size_t j = 0; j < 256; j++)
                data->epmf[i][j] += wr->epmf[i][j];

        dwall = interval(CLOCK_MONOTONIC, &wall);
        fprintf(stderr, "%"PRIu64"--%"PRIu64": %9.5fs\n",
                sofar, sofar+stride-1, dwall);

        sofar += stride;
        if (sofar > count)
            sofar = count;
        since_last_checkpoint += stride;
        if (since_last_checkpoint > count)
            since_last_checkpoint = count;
        if (since_last_checkpoint > checkpoint_interval)
        {
            data->highest_key = base + sofar;
            dataset_write(dataset_name, data);

            since_last_checkpoint = 0;
            dwall = interval(CLOCK_MONOTONIC, &wall);
            fprintf(stderr, "checkpoint: %9.5fs\n", dwall);
        }
    }

    if (since_last_checkpoint)
    {
        data->highest_key = base + sofar;
        dataset_write(dataset_name, data);
        dwall = interval(CLOCK_MONOTONIC, &wall);
        fprintf(stderr, "checkpoint: %9.5fs\n", dwall);
    }

    /* final message tells workers to stop */
    for (int i = 0; i < numprocs; i++)
    {
        wo[i].base = 0;
        wo[i].limit = 0;
        wo[i].cipher_index = data->cipher_index;
    }
    MPI_Scatter(wo, 1, dt_work_order,
                &mywo, 1, dt_work_order,
                0, MPI_COMM_WORLD);

    free(wo);
    free(wr);
}

static void
worker_process(void)
{
    work_order   *wo = xmalloc(sizeof(work_order));
    work_results *wr = xmalloc(sizeof(work_results));

    signal(SIGUSR1, SIG_IGN);

    for (;;)
    {
        MPI_Scatter(0, 0, dt_work_order,
                    wo, 1, dt_work_order,
                    0, MPI_COMM_WORLD);
        if (wo->base == 0 && wo->limit == 0)
            break;

        /* The head process may not have any work for us this round,
           but we still have to participate in the reduce. */
        if (wo->base < wo->limit)
            worker_run(wo, wr);
        else
            memset(wr, 0, sizeof(work_results));

        MPI_Reduce(wr->epmf, 0,
                   KEYSTREAM_LENGTH * 256, MPI_UINT32_T, MPI_SUM,
                   0, MPI_COMM_WORLD);
    }

    free(wo);
    free(wr);
}

int
main(int argc, char **argv)
{
    char *endp, *dataset_name;
    uint64_t count, checkpoint_interval;
    uint32_t cipher_index;
    int nprocs, rank;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    /* There is no need to treat dt_work_order as a struct type;
       it can just be an opaque blob copied around as such. */
    MPI_Type_contiguous(sizeof(work_order), MPI_BYTE, &dt_work_order);
    MPI_Type_commit(&dt_work_order);

    if (rank == 0)
    {
        if (argc < 3 || argc > 4)
        {
            fprintf(stderr,
                    "usage: %s cipher key-count [checkpoint-interval]\n",
                    argv[0]);
            goto list_ciphers;
        }

        for (cipher_index = 0; all_ciphers[cipher_index]; cipher_index++)
            if (!strcmp(all_ciphers[cipher_index]->name, argv[1]))
                break;
        if (!all_ciphers[cipher_index])
        {
            fprintf(stderr, "%s: unrecognized cipher: %s\n",
                    argv[0], argv[1]);
            goto list_ciphers;
        }

        count = strtoumax(argv[2], &endp, 10);
        if (endp == argv[2] || *endp != '\0')
        {
            fprintf(stderr, "key count '%s' is not a nonnegative integer",
                    argv[2]);
            goto quit;
        }

        /* Default checkpoint interval is after 10 cycles of 64K keys. */
        checkpoint_interval = nprocs * 10 * 65536;
        if (argc == 4)
        {
            checkpoint_interval = strtoumax(argv[3], &endp, 10);
            if (endp == argv[3] || *endp != '\0' || checkpoint_interval == 0)
            {
                fprintf(stderr,
                        "checkpoint interval '%s' is not a positive integer",
                        argv[3]);
                goto quit;
            }
        }

        dataset_name = 0;
        if (asprintf(&dataset_name, "results/%s.hdf", argv[1]) < 0)
        {
            perror("forming dataset name");
            goto quit;
        }

        dataset *data = xmalloc(sizeof(dataset));
        if (dataset_read(dataset_name, data))
        {
            if (cipher_index != data->cipher_index)
            {
                fprintf(stderr, "dataset %s: expected cipher %s, see %s",
                        dataset_name,
                        all_ciphers[cipher_index]->name,
                        all_ciphers[data->cipher_index]->name);
                goto quit;
            }
        }
        else
        {
            data->highest_key = 0;
            data->cipher_index = cipher_index;
        }

        /* If the cipher behavior is ideal, the 32-bit counters in the
           file on disk will overflow at 2^40 keys.  Since we are
           looking for non-ideal behavior, leave plenty of headroom. */
        uint64_t limit = (((uint64_t)1) << 40) - 0xFFFFFFFF;
        if (count == 0 || count + data->highest_key > limit)
            count = limit - data->highest_key;

        head_process(nprocs, dataset_name, count, checkpoint_interval, data);
    }
    else
        worker_process();

    MPI_Finalize();
    return 0;

 list_ciphers:
    fputs("supported ciphers:", stderr);
    for (int i = 0; all_ciphers[i]; i++)
    {
        putc(' ', stderr);
        fputs(all_ciphers[i]->name, stderr);
    }
    putc('\n', stderr);
 quit:
    MPI_Finalize();
    return 2;
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
