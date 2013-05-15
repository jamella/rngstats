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

#include "dataset.h"
#include "ciphers.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define H5_NO_DEPRECATED_SYMBOLS
#include <hdf5.h>

/* deal with H5's rather baroque error handling scheme */

static herr_t __attribute__((noreturn))
report_error_(hid_t estack, void *unused __attribute__((unused)))
{
    H5Eprint(estack, stderr);
    exit(1);
}
static void __attribute__((noreturn))
report_error(void)
{
    report_error_(H5E_DEFAULT, 0);
}

#define CHECK(expr) do { if ((expr) < 0) report_error(); } while (0)
typedef struct
{
    H5E_auto2_t old_func;
    void *old_data;
}
old_auto_report;

static void
push_disable_auto_report(old_auto_report *state)
{
    CHECK(H5Eget_auto(H5E_DEFAULT, &state->old_func, &state->old_data));
    CHECK(H5Eset_auto(H5E_DEFAULT, 0, 0));
}

static void
push_fatal_auto_report(old_auto_report *state)
{
    CHECK(H5Eget_auto(H5E_DEFAULT, &state->old_func, &state->old_data));
    CHECK(H5Eset_auto(H5E_DEFAULT, report_error_, 0));
}

static void
set_fatal_auto_report(void)
{
    CHECK(H5Eset_auto(H5E_DEFAULT, report_error_, 0));
}

static void
pop_auto_report(old_auto_report *state)
{
    CHECK(H5Eset_auto(H5E_DEFAULT, state->old_func, state->old_data));
}

/* Read and write data sets.
   There's a bit of a jargon clash here; below, "dataset" is always the
   object defined in dataset.h, containing all of the information we
   serialize to disk, and "dset" is always a HDF5 dataset containing
   some subset of that information.  */

/* HDF5 dataset corresponding to dataset.epmf */
#define EPMF_DSET_NAME "keystream_epmf"

/* HDF5 attribute corresponding to dataset.cipher_index */
#define CIPHER_INDEX_ATTR_NAME "cipher"

/* HDF5 attribute corresponding to dataset.highest_key */
#define HIGHEST_KEY_ATTR_NAME "nkeys"

bool
dataset_read(const char *fname, dataset *data)
{
    hid_t file, dset, dspace, kattr, cattr, catype;
    hsize_t dims[2];
    char cname[24];
    int rank, i;
    old_auto_report astate;

    push_disable_auto_report(&astate);
    file = H5Fopen(fname, H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file < 0)
    {
        if (errno != ENOENT)
            report_error();
        pop_auto_report(&astate);
        return false;
    }
    set_fatal_auto_report();

    dset   = H5Dopen(file, EPMF_DSET_NAME, H5P_DEFAULT);
    dspace = H5Dget_space(dset);
    rank   = H5Sget_simple_extent_ndims(dspace);
    if (rank != 2)
        errx(1, "%s/%s: has %d dimensions, expected 2",
             fname, EPMF_DSET_NAME, rank);
    H5Sget_simple_extent_dims(dspace, dims, 0);
    if (dims[0] != KEYSTREAM_LENGTH || dims[1] != 256)
        errx(1, "%s/%s: dimensions are [%llu][%llu], expected [%lu][%u]",
             fname, EPMF_DSET_NAME, dims[0], dims[1], KEYSTREAM_LENGTH, 256);

    H5Dread(dset, H5T_NATIVE_UINT32, H5S_ALL, dspace, H5P_DEFAULT,
            data->epmf);

    kattr = H5Aopen(dset, HIGHEST_KEY_ATTR_NAME, H5P_DEFAULT);
    H5Aread(kattr, H5T_NATIVE_UINT64, &data->highest_key);

    cattr = H5Aopen(dset, CIPHER_INDEX_ATTR_NAME, H5P_DEFAULT);
    catype = H5Aget_type(cattr);
    if (H5Tget_size(catype) > sizeof cname)
        errx(1, "%s/%s/%s: cipher name too long (%zd, max 24)",
             fname, EPMF_DSET_NAME, CIPHER_INDEX_ATTR_NAME,
             H5Tget_size(catype));
    H5Aread(cattr, catype, cname);
    for (i = 0; all_ciphers[i]; i++)
        if (!strcmp(cname, all_ciphers[i]->name))
        {
            data->cipher_index = i;
            break;
        }
    if (!all_ciphers[i])
        errx(1, "%s: unrecognized cipher name %s", fname, cname);

    H5Tclose(catype);
    H5Aclose(cattr);
    H5Aclose(kattr);
    H5Sclose(dspace);
    H5Dclose(dset);
    H5Fclose(file);
    pop_auto_report(&astate);
    return true;
}

/* This should be in the library as H5Sequal() but, bafflingly, it
   isn't.  Only implements the cases we need right now.  */
static bool
spaces_equal(hid_t a, hid_t b)
{
    if (!H5Sis_simple(a) || !H5Sis_simple(b))
        abort();
    if (H5Sget_simple_extent_type(a) != H5Sget_simple_extent_type(b))
        return false;
    if (H5Sget_simple_extent_type(a) != H5S_SIMPLE)
        return true;

    int rank = H5Sget_simple_extent_ndims(a);
    if (rank != H5Sget_simple_extent_ndims(b))
        return false;

    hsize_t adim[rank], bdim[rank], amaxdim[rank], bmaxdim[rank];
    H5Sget_simple_extent_dims(a, adim, amaxdim);
    H5Sget_simple_extent_dims(b, bdim, bmaxdim);

    for (int i = 0; i < rank; i++)
        if (adim[i] != bdim[i] || amaxdim[i] != bmaxdim[i])
            return false;
    return true;
}

static hid_t
ensure_attr(hid_t loc, const char *attr_name, hid_t type, hid_t space)
{
    if (H5Aexists(loc, attr_name))
    {
        hid_t attr = H5Aopen(loc, attr_name, H5P_DEFAULT);
        hid_t file_space = H5Aget_space(attr);
        hid_t file_type = H5Aget_type(attr);
        bool ok = (spaces_equal(file_space, space) &&
                   H5Tequal(file_type, type));
        H5Sclose(file_space);
        H5Tclose(file_type);
        if (ok)
            return attr;
        H5Aclose(attr);
        H5Adelete(loc, attr_name);
    }
    return H5Acreate(loc, attr_name, type, space,
                     H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t
ensure_dset(hid_t loc_id, const char *dset_name,
            hid_t type, hid_t space, hid_t cpl)
{
    if (H5Lexists(loc_id, dset_name, H5P_DEFAULT))
    {
        hid_t dset = H5Dopen(loc_id, dset_name, H5P_DEFAULT);
        hid_t file_space = H5Dget_space(dset);
        hid_t file_type = H5Dget_type(dset);
        hid_t file_cpl = H5Dget_create_plist(dset);
        bool ok = (spaces_equal(file_space, space) &&
                   H5Tequal(file_type, type) &&
                   H5Pequal(file_cpl, cpl));
        H5Sclose(file_space);
        H5Tclose(file_type);
        H5Pclose(file_cpl);
        if (ok)
            return dset;
        H5Dclose(dset);
        H5Ldelete(loc_id, dset_name, H5P_DEFAULT);
    }
    return H5Dcreate(loc_id, dset_name, type, space, H5P_DEFAULT, cpl,
                     H5P_DEFAULT);
}

void
dataset_write(const char *fname, const dataset *data)
{
    hid_t file, dset, dspace, dcpl, aspace, kattr, cattr, catype;
    hsize_t dims[2], chunk[2];
    size_t cnamelen;
    old_auto_report astate;

    push_fatal_auto_report(&astate);
    file = H5Fopen(fname, H5F_ACC_RDWR|H5F_ACC_CREAT, H5P_DEFAULT);

    /* data */
    dims[0] = KEYSTREAM_LENGTH;
    dims[1] = 256;
    chunk[0] = 256;
    chunk[1] = 256;
    dspace = H5Screate_simple(2, dims, 0);
    dcpl = H5Pcreate(H5P_DATASET_CREATE);
    H5Pset_deflate(dcpl, 9);
    H5Pset_chunk(dcpl, 2, chunk);
    dset = ensure_dset(file, EPMF_DSET_NAME, H5T_STD_U32LE, dspace, dcpl);

    H5Dwrite(dset, H5T_NATIVE_UINT32, H5S_ALL, H5S_ALL, H5P_DEFAULT,
             data->epmf);

    H5Sclose(dspace);
    H5Pclose(dcpl);

    /* attributes */
    aspace = H5Screate(H5S_SCALAR);

    kattr = ensure_attr(dset, HIGHEST_KEY_ATTR_NAME,
                        H5T_STD_U64LE, aspace);
    H5Awrite(kattr, H5T_NATIVE_UINT64, &data->highest_key);
    H5Aclose(kattr);

    cnamelen = strlen(all_ciphers[data->cipher_index]->name);
    catype = H5Tcopy(H5T_C_S1);
    H5Tset_size(catype, cnamelen + 1);
    cattr = ensure_attr(dset, CIPHER_INDEX_ATTR_NAME, catype, aspace);
    H5Awrite(cattr, catype, all_ciphers[data->cipher_index]->name);
    H5Aclose(cattr);
    H5Tclose(catype);

    H5Sclose(aspace);
    H5Dclose(dset);

    H5Fclose(file);
    pop_auto_report(&astate);
}
