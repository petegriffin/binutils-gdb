/* Linux kernel-level threads support.

   Copyright (C) 2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef LINUX_KTHREAD_H
#define LINUX_KTHREAD_H 1

#include "objfiles.h"

struct addr_info
{
  char *name;
  struct bound_minimal_symbol bmsym;
  struct addr_info *next;
};

struct field_info
{
  char *struct_name;
  char *field_name;
  struct symbol *type;
  int offset;
  int size;
  struct field_info *next;
};

int linux_init_addr (struct addr_info *field, int check);
int linux_init_field (struct field_info *field, int check);

static inline CORE_ADDR
linux_get_address (struct addr_info *addr)
{
  if (addr->bmsym.minsym == NULL)
    linux_init_addr (addr, 0);

  return BMSYMBOL_VALUE_ADDRESS (addr->bmsym);
}

static inline unsigned int
linux_get_field_offset (struct field_info *field)
{
  if (field->type == NULL)
    linux_init_field (field, 0);

  return field->offset;
}

static inline unsigned int
linux_get_field_size (struct field_info *field)
{
  if (field->type == NULL)
    linux_init_field (field, 0);

  return field->size;
}


/* Set the function that supplies registers for an inactive thread for
   architecture GDBARCH to SUPPLY_KTHREAD.  */

extern void linux_kthread_set_supply_thread (struct gdbarch *gdbarch,
				    void (*supply_kthread) (struct regcache *,
							    int, CORE_ADDR));


/* Set the function that collects registers for an inactive thread for
   architecture GDBARCH to SUPPLY_KTHREAD.  */

extern void linux_kthread_set_collect_thread (struct gdbarch *gdbarch,
			     void (*collect_kthread) (const struct regcache *,
						      int, CORE_ADDR));


#endif /* linux_kthread.h */
