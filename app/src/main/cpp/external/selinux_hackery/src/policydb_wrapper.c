/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "policydb_wrapper.h"

#include "policydb.c"

int policydb_index_decls_wrapper(sepol_handle_t *handle, policydb_t *p) {
    return policydb_index_decls(handle, p);
}
