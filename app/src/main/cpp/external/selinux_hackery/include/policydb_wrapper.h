/*
 * Copyright (C) 2023  Andrew Gunnerson
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <sepol/handle.h>
#include <sepol/policydb/policydb.h>

#ifdef __cplusplus
extern "C" {
#endif

int policydb_index_decls_wrapper(sepol_handle_t *handle, policydb_t *p);

#ifdef __cplusplus
}
#endif
