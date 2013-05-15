/*
 *  RNGstats dataset reading and writing -- round-trip test.
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

#include "dataset.h"
#include <err.h>
#include <stddef.h>
#include <inttypes.h>

int
main(void)
{
    static dataset d1, d2;
    d1.cipher_index = 3;
    d1.highest_key = 4242424242;

    for (size_t i = 0; i < KEYSTREAM_LENGTH; i++)
        for (size_t j = 0; j < 256; j++)
            d1.epmf[i][j] = i*1000 + j;
    dataset_write("test.hdf", &d1);
    dataset_read("test.hdf", &d2);

    if (d1.cipher_index != d2.cipher_index)
        errx(1, "cipher index mismatch: %"PRIu32"/%"PRIu32,
             d1.cipher_index, d2.cipher_index);
    if (d1.highest_key != d2.highest_key)
        errx(1, "highest key mismatch: %"PRIu64"/%"PRIu64,
             d1.highest_key, d2.highest_key);

    for (size_t i = 0; i < KEYSTREAM_LENGTH; i++)
        for (size_t j = 0; j < 256; j++)
            if (d1.epmf[i][j] != d2.epmf[i][j])
                errx(1, "data mismatch at [%zu][%zu]: %"PRIu32"/%"PRIu32,
                     i, j, d1.epmf[i][j], d2.epmf[i][j]);
    return 0;
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
