/*
 * Copyright (C) 2014-2023  Andrew Gunnerson
 *
 * This file is part of Custota, based on DualBootPatcher code.
 *
 * Custota is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Custota is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Custota.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <cstdarg>
#include <climits>
#include <cstdio>

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// libsepol is not very C++ friendly. 'bool' is a struct field in conditional.h
#define bool bool2
#include <sepol/policydb/expand.h>
#include <sepol/policydb/policydb.h>
#include <sepol/sepol.h>
#include "policydb_wrapper.h"
#undef bool

#include "finally.h"

constexpr char SELINUX_POLICY_FILE[] = "/sys/fs/selinux/policy";
constexpr char SELINUX_LOAD_FILE[]   = "/sys/fs/selinux/load";

enum class SELinuxResult
{
    Changed,
    Unchanged,
    Error,
};

__attribute__((format(printf, 1, 2)))
static std::string format(const char *fmt, ...) {
    static_assert(INT_MAX <= SIZE_MAX, "INT_MAX > SIZE_MAX");

    va_list ap;
    va_start(ap, fmt);

    char *ptr = nullptr;
    auto ret = vasprintf(&ptr, fmt, ap);

    va_end(ap);

    std::string result;

    if (ret < 0) {
        result = "(alloc error)";
    } else {
        result = ptr;
    }

    return result;
}

static bool selinux_raw_reindex(
    policydb_t *pdb,
    std::vector<std::string> &errors
) {
    // Recreate maps like type_val_to_struct. libsepol will handle memory
    // deallocation for the old maps

    if (policydb_index_decls_wrapper(nullptr, pdb) != 0) {
        errors.push_back(format("Failed to reindex decls"));
        return false;
    }

    if (policydb_index_classes(pdb) != 0) {
        errors.push_back(format("Failed to reindex classes"));
        return false;
    }

    if (policydb_index_others(nullptr, pdb, 0) != 0) {
        errors.push_back(format("Failed to reindex other data"));
        return false;
    }

    return true;
}

static bool read_policy(
    const std::string &path,
    policydb_t *pdb,
    std::vector<std::string> &errors
) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        errors.push_back(format("%s: Failed to open sepolicy: %s",
            path.c_str(), strerror(errno)));
        return false;
    }

    auto close_fd = finally([&] {
        close(fd);
    });

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        errors.push_back(format("%s: Failed to stat sepolicy: %s",
            path.c_str(), strerror(errno)));
        return false;
    }

    void *map = mmap(nullptr, static_cast<size_t>(sb.st_size), PROT_READ,
                     MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        errors.push_back(format("%s: Failed to mmap sepolicy: %s",
            path.c_str(), strerror(errno)));
        return false;
    }

    auto unmap_map = finally([&] {
        munmap(map, static_cast<size_t>(sb.st_size));
    });

    struct policy_file pf;
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = static_cast<char *>(map);
    pf.len = static_cast<size_t>(sb.st_size);

    auto destroy_pf = finally([&] {
        sepol_handle_destroy(pf.handle);
    });

    return policydb_read(pdb, &pf, 0) == 0;
}

// /sys/fs/selinux/load requires the entire policy to be written in a single
// write(2) call.
// See: http://marc.info/?l=selinux&m=141882521027239&w=2
static bool write_policy(
    const std::string &path,
    policydb_t *pdb,
    std::vector<std::string> &errors
) {
    // Don't print warnings to stderr
    sepol_handle_t *handle = sepol_handle_create();
    sepol_msg_set_callback(handle, nullptr, nullptr);

    auto destroy_handle = finally([&] {
        sepol_handle_destroy(handle);
    });

    void *data;
    size_t len;

    if (policydb_to_image(handle, pdb, &data, &len) < 0) {
        errors.push_back(format("Failed to write policydb to memory"));
        return false;
    }

    auto free_data = finally([&] {
        free(data);
    });

    int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) {
        errors.push_back(format("%s: Failed to open sepolicy: %s",
            path.c_str(), strerror(errno)));
        return false;
    }

    auto close_fd = finally([&] {
        close(fd);
    });

    if (write(fd, data, len) < 0) {
        errors.push_back(format("%s: Failed to write sepolicy: %s",
            path.c_str(), strerror(errno)));
        return false;
    }

    return true;
}

struct AvtabResult {
    avtab_ptr_t ptr;
    bool created;
};

static AvtabResult raw_find_or_create_avtab_node(
    policydb_t *pdb,
    avtab_key_t *key,
    avtab_extended_perms_t *xperms,
    std::vector<std::string> &errors
) {
    avtab_ptr_t node = avtab_search_node(&pdb->te_avtab, key);

    if (key->specified & AVTAB_XPERMS) {
        bool found = false;

        for (; node; node = avtab_search_node_next(node, key->specified)) {
            if (node->datum.xperms->specified == xperms->specified
                    && node->datum.xperms->driver == xperms->driver) {
                found = true;
                break;
            }
        }

        if (!found) {
            node = nullptr;
        }
    }

    bool created = false;

    if (!node) {
        // avtab makes a copy of all data passed to it on insert
        avtab_datum_t avdatum = {
            key->specified == AVTAB_AUDITDENY ? ~0U : 0U,
            xperms,
        };

        node = avtab_insert_nonunique(&pdb->te_avtab, key, &avdatum);
        if (!node) {
            errors.emplace_back("Failed to insert avtab entry");
            return {nullptr, false};
        }

        created = true;
    }

    return {node, created};
}

static SELinuxResult raw_set_allow_rule(
    policydb_t *pdb,
    uint16_t source_type_val,
    uint16_t target_type_val,
    uint16_t class_val,
    uint32_t perm_val,
    bool remove,
    std::vector<std::string> &errors
) {
    avtab_key_t key;
    key.source_type = source_type_val;
    key.target_type = target_type_val;
    key.target_class = class_val;
    key.specified = AVTAB_ALLOWED;

    auto result = raw_find_or_create_avtab_node(pdb, &key, nullptr, errors);
    if (!result.ptr) {
        return SELinuxResult::Error;
    }

    auto old_data = result.ptr->datum.data;

    if (remove) {
        result.ptr->datum.data &= ~(1U << (perm_val - 1));
    } else {
        result.ptr->datum.data |= (1U << (perm_val - 1));
    }

    return (result.created || result.ptr->datum.data != old_data)
        ? SELinuxResult::Changed
        : SELinuxResult::Unchanged;
}

static SELinuxResult raw_set_attribute(
    policydb_t *pdb,
    uint16_t type_val,
    uint16_t attr_val,
    std::vector<std::string> &errors
) {
    bool changed = false;

    auto ret1 = ebitmap_get_bit(&pdb->type_attr_map[type_val - 1], attr_val - 1);
    auto ret2 = ebitmap_get_bit(&pdb->attr_type_map[attr_val - 1], type_val - 1);

    if (ret1 != ret2) {
        errors.emplace_back("Inconsistent type<->attr maps");
        return SELinuxResult::Error;
    }

    // Update type-attribute maps

    if (!ret1) {
        ret1 = ebitmap_set_bit(
                &pdb->type_attr_map[type_val - 1], attr_val - 1, 1);
        ret2 = ebitmap_set_bit(
                &pdb->attr_type_map[attr_val - 1], type_val - 1, 1);

        if (ret1 < 0 || ret2 < 0) {
            errors.emplace_back("Failed to update type<->attr maps");
            return SELinuxResult::Error;
        }

        changed = true;
    }

    // As of 5.0-rc6, the kernel doesn't use expr->type_names in
    // constraint_expr_eval(), even if pdb->policyvers >=
    // POLICYDB_VERSION_CONSTRAINT_NAMES. This loop will check every constraint
    // and toggle the bit corresponding to `type_val` in expr->names if the bit
    // corresponding to `attr_val` is toggled in expr->type_names->types. Note
    // that this only works if the source policy version is new enough. Older
    // policies do not retain attribute information in the constraints.
    for (uint32_t class_val = 1; class_val <= pdb->p_classes.nprim; ++class_val) {
        class_datum_t *clazz = pdb->class_val_to_struct[class_val - 1];

        for (constraint_node_t *node = clazz->constraints; node; node = node->next) {
            for (constraint_expr_t *expr = node->expr; expr; expr = expr->next) {
                if (expr->expr_type == CEXPR_NAMES && expr->attr & CEXPR_TYPE
                        && ebitmap_get_bit(&expr->type_names->types, attr_val - 1)) {
                    if (ebitmap_set_bit(&expr->names, type_val - 1, 1) < 0) {
                        errors.emplace_back("Failed to update MLS constraints");
                        return SELinuxResult::Error;
                    }

                    changed = true;
                }
            }
        }
    }

    return changed ? SELinuxResult::Changed : SELinuxResult::Unchanged;
}

static SELinuxResult raw_copy_attributes(
    policydb_t *pdb,
    uint16_t source_type_val,
    uint16_t target_type_val,
    std::vector<std::string> &errors
) {
    std::vector<uint16_t> attributes;
    ebitmap_node *n;
    unsigned int bit;

    ebitmap_for_each_bit(&pdb->type_attr_map[source_type_val - 1], n, bit) {
        if (!ebitmap_node_get_bit(n, bit)) {
            continue;
        }

        if (source_type_val != bit + 1) {
            attributes.push_back(static_cast<uint16_t>(bit + 1));
        }
    }

    bool changed = false;

    for (auto const &attr : attributes) {
        auto ret = raw_set_attribute(
            pdb, static_cast<uint16_t>(target_type_val), attr, errors);
        if (ret == SELinuxResult::Error) {
            errors.push_back(format("Failed to set attribute %s for type %s",
                pdb->p_type_val_to_name[attr - 1],
                pdb->p_type_val_to_name[target_type_val - 1]));
            return ret;
        } else {
            changed |= ret == SELinuxResult::Changed;
        }
    }

    return changed ? SELinuxResult::Changed : SELinuxResult::Unchanged;
}

static SELinuxResult raw_copy_constraints(
    policydb_t *pdb,
    uint16_t source_type_val,
    uint16_t target_type_val,
    std::vector<std::string> &errors
) {
    bool changed = false;

    for (uint32_t class_val = 1; class_val <= pdb->p_classes.nprim; ++class_val) {
        auto clazz = pdb->class_val_to_struct[class_val - 1];

        for (auto node = clazz->constraints; node; node = node->next) {
            for (auto expr = node->expr; expr; expr = expr->next) {
                if (expr->expr_type == CEXPR_NAMES && expr->attr & CEXPR_TYPE
                        && ebitmap_get_bit(&expr->names, source_type_val - 1)) {
                    if (ebitmap_set_bit(&expr->names, target_type_val - 1, 1) < 0) {
                        errors.emplace_back("Failed to update MLS constraints");
                        return SELinuxResult::Error;
                    }

                    changed = true;
                }
            }
        }
    }

    return changed ? SELinuxResult::Changed : SELinuxResult::Unchanged;
}

static SELinuxResult raw_add_to_role(
    policydb_t *pdb,
    uint16_t role_val,
    uint16_t type_val,
    std::vector<std::string> &errors
) {
    auto role = pdb->role_val_to_struct[role_val - 1];

    if (ebitmap_get_bit(&role->types.types, type_val - 1)) {
        return SELinuxResult::Unchanged;
    }

    if (ebitmap_set_bit(&role->types.types, type_val - 1, 1) < 0) {
        errors.emplace_back("Failed to update role types");
        return SELinuxResult::Error;
    }

    if (ebitmap_set_bit(&role->types.negset, type_val - 1, 0) < 0) {
        errors.emplace_back("Failed to update role negset");
        return SELinuxResult::Error;
    }

    return selinux_raw_reindex(pdb, errors)
        ? SELinuxResult::Changed
        : SELinuxResult::Error;
}

static SELinuxResult raw_copy_roles(
    policydb_t *pdb,
    uint16_t source_type_val,
    uint16_t target_type_val,
    std::vector<std::string> &errors
) {
    bool changed = false;

    for (uint32_t role_val = 1; role_val <= pdb->p_roles.nprim; ++role_val) {
        auto role = pdb->role_val_to_struct[role_val - 1];

        if (!ebitmap_get_bit(&role->types.types, source_type_val - 1)) {
            continue;
        }

        auto ret = raw_add_to_role(
                pdb, static_cast<uint16_t>(role_val), target_type_val, errors);
        if (ret == SELinuxResult::Error) {
            errors.push_back(format("Failed to add type %s to role %s",
                pdb->p_role_val_to_name[role_val - 1],
                pdb->p_type_val_to_name[target_type_val - 1]));
            return ret;
        } else {
            changed |= ret == SELinuxResult::Changed;
        }
    }

    return changed ? SELinuxResult::Changed : SELinuxResult::Unchanged;
}

static SELinuxResult raw_strip_no_audit(policydb_t *pdb)
{
    bool changed = false;

    for (uint32_t i = 0; i < pdb->te_avtab.nslot; i++) {
        avtab_ptr_t prev = nullptr;

        for (avtab_ptr_t cur = pdb->te_avtab.htable[i]; cur;) {
            if ((cur->key.specified & AVTAB_AUDITDENY)
                    || (cur->key.specified & AVTAB_XPERMS_DONTAUDIT)) {
                avtab_ptr_t to_free = cur;

                if (prev) {
                    prev->next = cur = cur->next;
                } else {
                    pdb->te_avtab.htable[i] = cur = cur->next;
                }

                if (to_free->key.specified & AVTAB_XPERMS) {
                    free(to_free->datum.xperms);
                }
                free(to_free);

                --pdb->te_avtab.nel;

                changed = true;

                // Don't advance pointer
            } else {
                prev = cur;
                cur = cur->next;
            }
        }
    }

    return changed ? SELinuxResult::Changed : SELinuxResult::Unchanged;
}

// Static helper functions

static inline class_datum_t * find_class(policydb_t *pdb, const char *name)
{
    return static_cast<class_datum_t *>(hashtab_search(
            pdb->p_classes.table, const_cast<hashtab_key_t>(name)));
}

static inline perm_datum_t * find_perm(class_datum_t *clazz, const char *name)
{
    // Find class-specific permissions first
    auto perm = static_cast<perm_datum_t *>(hashtab_search(
            clazz->permissions.table, const_cast<hashtab_key_t>(name)));

    // Then try common permissions
    if (!perm && clazz->comdatum) {
        perm = static_cast<perm_datum_t *>(hashtab_search(
                clazz->comdatum->permissions.table,
                const_cast<hashtab_key_t>(name)));
    }

    return perm;
}

static inline type_datum_t * find_type(policydb_t *pdb, const char *name)
{
    return static_cast<type_datum_t *>(hashtab_search(
            pdb->p_types.table, const_cast<hashtab_key_t>(name)));
}

// Helper functions

static bool set_allow_rule(
    policydb_t *pdb,
    const char *source_str,
    const char *target_str,
    const char *class_str,
    const char *perm_str,
    bool remove,
    std::vector<std::string> &errors
) {
    auto source = find_type(pdb, source_str);
    if (!source) {
        errors.push_back(format("Source type %s does not exist", source_str));
        return false;
    }

    auto target = find_type(pdb, target_str);
    if (!target) {
        errors.push_back(format("Target type %s does not exist", target_str));
        return false;
    }

    auto clazz = find_class(pdb, class_str);
    if (!clazz) {
        errors.push_back(format("Class %s does not exist", class_str));
        return false;
    }

    auto perm = find_perm(clazz, perm_str);
    if (!perm) {
        errors.push_back(format("Perm %s does not exist in class %s",
            perm_str, class_str));
        return false;
    }

    auto result = raw_set_allow_rule(
        pdb,
        static_cast<uint16_t>(source->s.value),
        static_cast<uint16_t>(target->s.value),
        static_cast<uint16_t>(clazz->s.value),
        static_cast<uint16_t>(perm->s.value),
        remove,
        errors
    );

    switch (result) {
    case SELinuxResult::Changed:
    case SELinuxResult::Unchanged:
        return true;
    case SELinuxResult::Error:
        errors.push_back(format("Failed to add rule: allow %s %s:%s %s;",
            source_str, target_str, class_str, perm_str));
    }

    return false;
}

static bool add_rule(
    policydb_t *pdb,
    const char *source_str,
    const char *target_str,
    const char *class_str,
    const char *perm_str,
    std::vector<std::string> &errors
) {
    return set_allow_rule(
        pdb, source_str, target_str, class_str, perm_str, false, errors);
}

static SELinuxResult create_type(
    policydb_t *pdb,
    const char *name,
    std::vector<std::string> &errors
) {
    if (find_type(pdb, name)) {
        // Type already exists
        return SELinuxResult::Unchanged;
    }

    // symtab_insert will take ownership of these allocations
    char *name_dup = strdup(name);
    if (!name_dup) {
        errors.emplace_back("(alloc error)");
        return SELinuxResult::Error;
    }

    auto new_type = static_cast<type_datum_t *>(malloc(sizeof(type_datum_t)));
    if (!new_type) {
        free(name_dup);
        errors.emplace_back("(alloc error)");
        return SELinuxResult::Error;
    }

    // We're creating a type, not an attribute
    type_datum_init(new_type);
    new_type->primary = 1;
    new_type->flavor = TYPE_TYPE;

    // New value for the type
    uint32_t type_val;

    // Add type declaration to symbol table
    int ret = symtab_insert(
            pdb, SYM_TYPES, name_dup, new_type, SCOPE_DECL, 1, &type_val);
    if (ret != 0) {
        // Policy file is broken if, somehow, ret == 1
        free(name_dup);
        free(new_type);
        errors.push_back(format(
            "Failed to insert type %s into symbol table", name));
        return SELinuxResult::Error;
    }

    new_type->s.value = type_val;

    if (ebitmap_set_bit(&pdb->global->branch_list->declared.scope[SYM_TYPES],
                        type_val - 1, 1) != 0) {
        return SELinuxResult::Error;
    }

    // Reallocate type-attribute maps for the new type
    // (see: policydb_read() in policydb.c)
    auto new_type_attr_map = static_cast<ebitmap_t *>(reallocarray(
        pdb->type_attr_map, pdb->p_types.nprim, sizeof(ebitmap_t)));
    if (new_type_attr_map) {
        pdb->type_attr_map = new_type_attr_map;
    } else {
        errors.emplace_back("(alloc error)");
        return SELinuxResult::Error;
    }

    auto new_attr_type_map = static_cast<ebitmap_t *>(reallocarray(
        pdb->attr_type_map, pdb->p_types.nprim, sizeof(ebitmap_t)));
    if (new_attr_type_map) {
        pdb->attr_type_map = new_attr_type_map;
    } else {
        errors.emplace_back("(alloc error)");
        return SELinuxResult::Error;
    }

    // Initialize bitmap
    ebitmap_init(&pdb->type_attr_map[type_val - 1]);
    ebitmap_init(&pdb->attr_type_map[type_val - 1]);

    // Handle degenerate case
    if (ebitmap_set_bit(&pdb->type_attr_map[type_val - 1],
                        type_val - 1, 1) < 0) {
        errors.push_back(format("Failed to add type %s to type<->attr map", name));
        return SELinuxResult::Error;
    }

    if (!selinux_raw_reindex(pdb, errors)) {
        return SELinuxResult::Error;
    }

    return SELinuxResult::Changed;
}

static bool copy_avtab_rules(
    policydb_t *pdb,
    const std::function<std::optional<avtab_key_t>(const avtab_key_t &)> &fn,
    std::vector<std::string> &errors
) {
    std::vector<std::pair<avtab_key_t, avtab_datum_t>> to_add;

    // Gather rules to copy
    for (uint32_t i = 0; i < pdb->te_avtab.nslot; ++i) {
        for (avtab_ptr_t cur = pdb->te_avtab.htable[i]; cur; cur = cur->next) {
            auto new_key = fn(cur->key);
            if (new_key) {
                to_add.emplace_back(new_key.value(), cur->datum);
            }
        }
    }

    for (auto &pair : to_add) {
        auto result = raw_find_or_create_avtab_node(
            pdb, &pair.first, pair.second.xperms, errors);
        if (!result.ptr) {
            return false;
        }

        if (result.created) {
            if (pair.first.specified & AVTAB_XPERMS) {
                auto array_size = sizeof(pair.second.xperms->perms)
                    / sizeof(pair.second.xperms->perms[0]);

                for (size_t i = 0; i < array_size; ++i) {
                    result.ptr->datum.xperms->perms[i]
                        |= pair.second.xperms->perms[i];
                }

                // data is used for neverallow rules. See avtab.c
                result.ptr->datum.data |= pair.second.data;
            } else if (pair.first.specified == AVTAB_AUDITDENY) {
                result.ptr->datum.data &= pair.second.data;
            } else {
                result.ptr->datum.data |= pair.second.data;
            }
        }
    }

    return true;
}

// Fail fast
#define ff(expr) \
    do { \
        if (!(expr)) return false; \
    } while (0)

static bool apply_patches(
    policydb_t *pdb,
    bool strip_no_audit,
    std::vector<std::string> &errors
) {
    const char *source_type = "untrusted_app";
    const char *source_uffd_type = "untrusted_app_userfaultfd";
    const char *target_type = "custota_app";
    const char *target_uffd_type = "custota_app_userfaultfd";

    auto source = find_type(pdb, source_type);
    if (!source) {
        errors.push_back(format("Source type does not exist: %s", source_type));
        return false;
    }

    auto source_uffd = find_type(pdb, source_uffd_type);
    if (!source_uffd) {
        errors.push_back(format("Source type does not exist: %s", source_uffd_type));
        return false;
    }

    auto target = find_type(pdb, target_type);
    if (!target) {
        ff(create_type(pdb, target_type, errors) != SELinuxResult::Error);
        target = find_type(pdb, target_type);
        ff(target);
    }

    auto target_uffd = find_type(pdb, target_uffd_type);
    if (!target_uffd) {
        ff(create_type(pdb, target_uffd_type, errors) != SELinuxResult::Error);
        target_uffd = find_type(pdb, target_uffd_type);
        ff(target_uffd);
    }

    auto source_val = static_cast<uint16_t>(source->s.value);
    auto source_uffd_val = static_cast<uint16_t>(source_uffd->s.value);
    auto target_val = static_cast<uint16_t>(target->s.value);
    auto target_uffd_val = static_cast<uint16_t>(target_uffd->s.value);

    ff(raw_copy_roles(pdb, source_val, target_val, errors) != SELinuxResult::Error);
    ff(raw_copy_roles(pdb, source_uffd_val, target_uffd_val, errors) != SELinuxResult::Error);

    ff(raw_copy_attributes(pdb, source_val, target_val, errors) != SELinuxResult::Error);
    ff(raw_copy_attributes(pdb, source_uffd_val, target_uffd_val, errors) != SELinuxResult::Error);

    ff(raw_copy_constraints(pdb, source_val, target_val, errors) != SELinuxResult::Error);
    ff(raw_copy_constraints(pdb, source_uffd_val, target_uffd_val, errors) != SELinuxResult::Error);

    ff(copy_avtab_rules(pdb, [&](auto const &key) {
        avtab_key_t copy = key;
        auto matched = false;

        if (key.source_type == source_val) {
            copy.source_type = static_cast<uint16_t>(target_val);
            matched = true;
        } else if (key.source_type == source_uffd_val) {
            copy.source_type = static_cast<uint16_t>(target_uffd_val);
            matched = true;
        }

        if (key.target_type == source_val) {
            copy.target_type = static_cast<uint16_t>(target_val);
            matched = true;
        } else if (key.target_type == source_uffd_val) {
            copy.target_type = static_cast<uint16_t>(target_uffd_val);
            matched = true;
        }

        (void) matched;

        return matched ? std::make_optional(copy) : std::nullopt;
    }, errors));

    // At this point, custota_app should be identical to untrusted_app. Now, add
    // the actual additional rules we need.

    // allow custota_app ota_package_file:dir rw_dir_perms;
    for (auto const &perm : {
        "add_name", "getattr", "ioctl", "lock", "open", "read", "remove_name",
        "search", "watch", "watch_reads", "write",
    }) {
        ff(add_rule(pdb, target_type, "ota_package_file", "dir", perm, errors));
    }

    // allow custota_app ota_package_file:file create_file_perms;
    for (auto const &perm : {
        "append", "create", "getattr", "ioctl", "lock", "map", "open", "read",
        "rename", "setattr", "unlink", "watch", "watch_reads", "write",
    }) {
        ff(add_rule(pdb, target_type, "ota_package_file", "file", perm, errors));
    }

    // binder_call(custota_app, update_engine)
    // binder_call(update_engine, custota_app)
    for (auto const &perm : {"call", "transfer"}) {
        ff(add_rule(pdb, target_type, "update_engine", "binder", perm, errors));
        ff(add_rule(pdb, "update_engine", target_type, "binder", perm, errors));
    }
    ff(add_rule(pdb, target_type, "update_engine", "fd", "use", errors));
    ff(add_rule(pdb, "update_engine", target_type, "fd", "use", errors));

    // allow custota_app update_engine_service:service_manager find;
    ff(add_rule(pdb, target_type, "update_engine_service", "service_manager", "find", errors));

    if (strip_no_audit) {
        ff(raw_strip_no_audit(pdb) != SELinuxResult::Error);
    }

    return true;
}

static bool patch_sepolicy(
    const std::string &source,
    const std::string &target,
    bool strip_no_audit,
    std::vector<std::string> &errors
) {
    policydb_t pdb;

    if (policydb_init(&pdb) < 0) {
        errors.push_back(format("Failed to initialize policydb"));
        return false;
    }

    auto destroy_pdb = finally([&]{
        policydb_destroy(&pdb);
    });

    if (!read_policy(source, &pdb, errors)) {
        return false;
    }

    printf("Policy version: %u\n", pdb.policyvers);

    if (!apply_patches(&pdb, strip_no_audit, errors)) {
        errors.push_back(format("%s: Failed to apply policy patches", source.c_str()));
        return false;
    }

    if (!write_policy(target, &pdb, errors)) {
        return false;
    }

    return true;
}

static void usage(const char *program, FILE *stream)
{
    fprintf(stream,
            "Usage: %s [OPTION]...\n\n"
            "Options:\n"
            "  -s [SOURCE], --source [SOURCE]\n"
            "                        Source policy file\n"
            "  -S, --source-kernel   Use currently loaded policy as source\n"
            "  -t [TARGET], --target [TARGET]\n"
            "                        Target policy file\n"
            "  -T, --target-kernel   Load patched policy into kernel\n"
            "  -d, --strip-no-audit  Remove dontaudit/dontauditxperm rules\n"
            "  -h, --help            Display this help message\n",
            program);
}

int main(int argc, char *argv[])
{
    int opt;
    const char *source_file = nullptr;
    const char *target_file = nullptr;

    static struct option long_options[] = {
        {"source",         required_argument, nullptr, 's'},
        {"source-kernel",  no_argument,       nullptr, 'S'},
        {"target",         required_argument, nullptr, 't'},
        {"target-kernel",  no_argument,       nullptr, 'T'},
        {"strip-no-audit", no_argument,       nullptr, 'd'},
        {"help",           no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };

    static const char short_options[] = "s:St:Tdh";

    int long_index = 0;
    bool strip_no_audit = false;

    while ((opt = getopt_long(
            argc, argv, short_options, long_options, &long_index)) != -1) {
        switch (opt) {
        case 's':
            source_file = optarg;
            break;

        case 'S':
            source_file = SELINUX_POLICY_FILE;
            break;

        case 't':
            target_file = optarg;
            break;

        case 'T':
            target_file = SELINUX_LOAD_FILE;
            break;

        case 'd':
            strip_no_audit = true;
            break;

        case 'h':
            usage(argv[0], stdout);
            return EXIT_SUCCESS;

        default:
            usage(argv[0], stderr);
            return EXIT_FAILURE;
        }
    }

    // There should be no other arguments
    if (argc - optind != 0) {
        usage(argv[0], stderr);
        return EXIT_FAILURE;
    }

    if (!source_file) {
        fprintf(stderr, "No source file specified\n");
        return EXIT_FAILURE;
    } else if (!target_file) {
        fprintf(stderr, "No target file specified\n");
        return EXIT_FAILURE;
    }

    std::vector<std::string> errors;

    if (!patch_sepolicy(source_file, target_file, strip_no_audit, errors)) {
        for (auto it = errors.rbegin(); it != errors.rend(); ++it) {
            fprintf(stderr, "Error: %s\n", it->c_str());
        }

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
