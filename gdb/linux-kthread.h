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


/* The list of tasks as cached in the debugger. */
typedef struct process_t_
{
  struct process_t_ *next;
  CORE_ADDR task_struct;
  CORE_ADDR mm;
  CORE_ADDR active_mm;

  ptid_t old_ptid;

  int core;			/*this is the "dynamic" core info */

  int tgid;
  unsigned int prio;
  char *comm;
  int valid;

  struct thread_info *gdb_thread;
} process_t;

#define PTID_OF(ps) ((ps)->gdb_thread->ptid)

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

#define CORE_INVAL (-1)		/* 0 = name on the inferior, cannot be used */

#define LKD_BYTE_ORDER BFD_ENDIAN_LITTLE

#define FIELD_INFO(s_name, field) _FIELD_##s_name##__##field

#define DECLARE_FIELD(s_name, field) \
		static struct field_info FIELD_INFO(s_name, field) \
		= { .struct_name = #s_name, .field_name = #field, 0 }

#define F_OFFSET(struct, field) \
		linux_get_field_offset (&FIELD_INFO(struct, field))
#define F_SIZE(struct, field) \
		linux_get_field_size (&FIELD_INFO(struct, field))
#define HAS_FIELD(struct, field) \
		(FIELD_INFO(struct, field).type != NULL \
				|| (linux_init_field(&FIELD_INFO(struct, field), 1), \
						FIELD_INFO(struct, field).type != NULL))

#define ADDR_INFO(symb) _ADDR_##symb

#define DECLARE_ADDR(symb) \
		static struct addr_info ADDR_INFO(symb) = { .name = #symb, .bmsym = {NULL, NULL} }

#define HAS_ADDR(symb) \
		(ADDR_INFO(symb).bmsym.minsym != NULL \
				|| (linux_init_addr(&ADDR_INFO(symb), 1), ADDR_INFO(symb).bmsym.minsym != NULL))

#define ADDR(sym) linux_get_address (&ADDR_INFO(sym))

#define read_unsigned_field(base, struct, field) \
		read_memory_unsigned_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define read_signed_field(base, struct, field) \
		read_memory_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define read_pointer_field(base, struct, field) \
		read_memory_typed_address (base + F_OFFSET (struct, field), \
				builtin_type (target_gdbarch ())->builtin_data_ptr)

#define read_unsigned_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_unsigned_integer (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				F_SIZE (emb_str, emb_field), LKD_BYTE_ORDER)

#define read_signed_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_integer (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				F_SIZE (emb_str, emb_field), LKD_BYTE_ORDER)

#define read_pointer_embedded_field(base, struct, field, emb_str, emb_field) \
		read_memory_typed_address (base + F_OFFSET (struct, field) \
				+ F_OFFSET (emb_str, emb_field), \
				builtin_type (target_gdbarch ())->builtin_data_ptr)

#define extract_unsigned_field(base, struct, field) \
		extract_unsigned_integer(base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define extract_signed_field(base, struct, field) \
		extract_signed_integer (base + F_OFFSET (struct, field), \
				F_SIZE (struct, field), LKD_BYTE_ORDER)

#define extract_pointer_field(base, struct, field) \
		extract_typed_address (base + F_OFFSET (struct, field), \
				builtin_type(target_gdbarch ())->builtin_data_ptr)

/* Mimic kernel macros */
#define container_of(ptr, struc, field)  ((ptr) - F_OFFSET(struc, field))


/*
 * Mapping GDB PTID to Linux PID and Core
 *
 * GDB Remote uses LWP to store the effective cpu core
 *  ptid.pid = Inferior PID
 *  ptid.lwp = CPU Core
 *  ptid.tid = 0
 *
 * STMC Debug remote uses TID to store the core.
 *  ptid.pid = Inferior PID
 *  ptid.lwp = Process ID
 *  ptid.tid = CPU Core (-1 for not running)
 *
 * This current naming, could cause some confusion between the inferior
 * PID and the Linux PID stored, but for now I'm going to accept that, until
 * I come up with a better name
 *
 * These macro's provide a level of indirection through the uses of LKD
 * accessing PTID structures. This allows clear identification of the aim
 * of function reading from the structure, and provides a single place to
 * swap usage if testing with an STMC in the short term.
 */

#define lkd_ptid_build(inferior_pid, core, process) ptid_build(inferior_pid, core, process)

#define lkd_ptid_to_core(ptid) ptid_get_lwp(ptid)
#define lkd_ptid_to_pid(ptid) ptid_get_tid(ptid)

#define LKD_PTID_SET_CORE(ptid, core) do { ptid.lwp = core; } while (0)
#define LKD_PTID_SET_PID(ptid, pid) do { ptid.tid = pid; } while (0)

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
