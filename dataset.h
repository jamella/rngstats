/*
 * RNGstats: dataset reading and writing.
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

#ifndef DATASET_H__
#define DATASET_H__

#include "config.h"
#include "ciphers.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    uint32_t cipher_index;
    uint64_t highest_key;

    uint64_t aggregate[KEYSTREAM_LENGTH][256];
}
dataset;

/* Read a data set from file FNAME into DATA.  On success, returns
   true.  If FNAME does not exist or is empty, returns false and does
   not modify DATA.  On any other error condition, terminates the
   program. */
extern bool read_dataset(const char *fname, dataset *data);

/* Write a data set to a file named FNAME.  Succeeds or else
   terminates the program.  */
extern void write_dataset(const char *fname, const dataset *data);

#endif

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
