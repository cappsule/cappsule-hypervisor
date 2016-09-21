/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef TRUSTED_XCHAN_H
#define TRUSTED_XCHAN_H

#include "cuapi/trusted/xchan.h"
#include "common/error.h"

struct xchan_memory;

void xchan_set_memory_id(struct xchan_memory *memory, unsigned int capsule_id);
unsigned long xchan_get_memory_pages(struct xchan_memory *memory);
err_t trusted_xchan_init(void);
void trusted_xchan_exit(void);
struct xchan_memory *xchan_alloc_pages(void);
int xchan_put_pages(struct xchan_memory *memory);
int xchan_put_pages_by_id(unsigned int id);
err_t find_xchan_first_vector(void);

#endif /* TRUSTED_XCHAN_H */
