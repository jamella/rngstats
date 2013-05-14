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
#define _FILE_OFFSET_BITS 64

#include "dataset.h"

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define FILE_LABEL "# RNGstats data set v1\n"

static void __attribute__((noreturn))
read_error(FILE *fp, const char *fname)
{
    if (feof(fp))
        errx(1, "reading %s: unexpected end of file", fname);
    else
        err(1, "reading %s", fname);
}

static uint64_t
readnum(FILE *fp, const char *fname)
{
    int c;
    uint64_t val = 0, v1;
    bool looped = false;
    while ((c = getc(fp)) >= '0' && c <= '9')
    {
        v1 = val*10 + (c - '0');
        if (v1 < val)
            errx(1, "%s: number too large", fname);
        val = v1;
        looped = true;
    }
    if (!looped)
        read_error(fp, fname);
    return val;
}

bool
read_dataset(const char *fname, dataset *data)
{
    unsigned int i, j;
    uintmax_t u;
    char buf[80], *p, *tok;
    FILE *fp = fopen(fname, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return false;
        read_error(fp, fname);
    }

    if (!fgets(buf, sizeof buf, fp))
    {
        int errnum = errno;
        if (feof(fp) && ftell(fp) == 0)
            return false;  /* empty file */
        errno = errnum;
        read_error(fp, fname);
    }
    /* line 1 is a label */
    if (strcmp(buf, FILE_LABEL))
        errx(1, "%s: not a RNGstats data set", fname);

    /* line 2 is '# <ciphername> <highestindex>' */
    if (!fgets(buf, sizeof buf, fp))
        read_error(fp, fname);

    if (buf[0] != '#' || buf[1] != ' ')
        errx(1, "%s: ill-formed header line", fname);

    p = &buf[2];
    tok = strsep(&p, " \t\n\r");
    for (i = 0; all_ciphers[i]; i++)
        if (!strcmp(tok, all_ciphers[i]->name))
        {
            data->cipher_index = i;
            break;
        }
    if (!all_ciphers[i])
        errx(1, "%s: unrecognized cipher '%s'", fname, tok);

    tok = p;
    u = strtoumax(tok, &p, 10);
    if (tok == p || *p != '\n' || u > UINT64_MAX)
        errx(1, "%s: ill-formed header line", fname);
    data->highest_key = u;

    /* lines 3 through KEYSTREAM_LENGTH have 256 space-separated decimal
       numbers, one for each bin */
    for (i = 0; i < KEYSTREAM_LENGTH; i++)
        for (j = 0; j < 256; j++)
        {
            if (feof(fp) || ferror(fp))
                read_error(fp, fname);
            data->aggregate[i][j] = readnum(fp, fname);
        }

    if (getc(fp) != EOF)
        errx(1, "%s: too much data", fname);

    fclose(fp);
    return true;
}

void
write_dataset(const char *fname, const dataset *data)
{
    unsigned int i, j;
    /* ??? atomic update */
    FILE *fp = fopen(fname, "w");
    if (!fp)
        err(1, "%s", fname);

    fputs(FILE_LABEL, fp);
    fprintf(fp, "# %s %"PRIu64"\n",
            all_ciphers[data->cipher_index]->name,
            data->highest_key);
    for (i = 0; i < KEYSTREAM_LENGTH; i++)
        for (j = 0; j < 256; j++)
            fprintf(fp, "%"PRIu64"%c", data->aggregate[i][j],
                    j < 255 ? ' ' : '\n');
    if (ferror(fp) || fflush(fp) || fclose(fp))
        err(1, "%s", fname);
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
