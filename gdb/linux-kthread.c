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

#include "defs.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "inferior.h"
#include "objfiles.h"
#include "observer.h"
#include "regcache.h"
#include "target.h"

#include "gdb_obstack.h"

#define DEBUG_LINUX_KTHREAD
#ifdef DEBUG_LINUX_KTHREAD
#define ENTER() do { printf_unfiltered("Enter %s:%d\n", __FUNCTION__, __LINE__); } while (0)
#define DEBUG(d,l,fmt, args...) do { printf_unfiltered("%s:%d: " fmt, __FUNCTION__, __LINE__, ##args); } while (0)

#else
#define ENTER() do { } while (0)
#define DEBUG(d,l, fmt, args...) do { } while (0)
#endif

#include "linux-kthread.h"

/* Save the linux_kthreads ops returned by linux_kthread_target.  */
static struct target_ops *linux_kthread_ops;

/* Non-zero if the thread stratum implemented by this module is active.  */
static int linux_kthread_active;

/* Architecture-specific operations.  */

/* Per-architecture data key.  */
static struct gdbarch_data *linux_kthread_data;

struct linux_kthread_ops
{
  /* Supply registers for a thread to a register cache.  */
  void (*supply_kthread) (struct regcache *, int, CORE_ADDR);

  /* Collect registers for a thread from a register cache.  */
  void (*collect_kthread) (const struct regcache *, int, CORE_ADDR);
};

static void *
linux_kthread_init (struct obstack *obstack)
{
  struct linux_kthread_ops *ops;

  ops = OBSTACK_ZALLOC (obstack, struct linux_kthread_ops);
  return ops;
}

/* Set the function that supplies registers from an inactive thread
   for architecture GDBARCH to SUPPLY_UTHREAD.  */

void
linux_kthread_set_supply_thread (struct gdbarch *gdbarch,
				 void (*supply_kthread) (struct regcache *,
							 int, CORE_ADDR))
{
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  ops->supply_kthread = supply_kthread;
}

/* Set the function that collects registers for an inactive thread for
   architecture GDBARCH to SUPPLY_UTHREAD.  */

void
linux_kthread_set_collect_thread (struct gdbarch *gdbarch,
				  void (*collect_kthread) (const struct
							   regcache *, int,
							   CORE_ADDR))
{
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  ops->collect_kthread = collect_kthread;
}


static char *
ptid_to_str (ptid_t ptid)
{
  static char str[32];
  snprintf (str, sizeof (str) - 1, "%d:%ld:%ld",
	    ptid_get_pid (ptid), ptid_get_lwp (ptid), ptid_get_tid (ptid));

  return str;
}

/* Symbol and Field resolutions */

/* Storage for the field layout and addresses already gathered. */
static struct field_info *field_info;
static struct addr_info *addr_info;

/* Called by ADDR to fetch the address of a symbol declared using
 DECLARE_ADDR. */
int
linux_init_addr (struct addr_info *addr, int check)
{
  if (addr->bmsym.minsym)
    return 1;

  addr->bmsym = lookup_minimal_symbol (addr->name, NULL, NULL);

  if (!addr->bmsym.minsym)
    {
      DEBUG (INIT, 3, "Checking for address of '%s' : NOT FOUND\n", addr->name);
      if (!check)
	error ("Couldn't find address of %s", addr->name);
      return 0;
    }

  /* Chain initialized entries for cleanup. */
  addr->next = addr_info;
  addr_info = addr;

  DEBUG (INIT, 1, "%s address is %s\n", addr->name,
	 phex (BMSYMBOL_VALUE_ADDRESS (addr->bmsym), 4));

  return 1;
}

/* Helper for linux_init_field. */
static int
find_struct_field (struct type *type, char *field, int *offset, int *size)
{
  int i;

  for (i = 0; i < TYPE_NFIELDS (type); ++i)
    {
      if (!strcmp (FIELD_NAME (TYPE_FIELDS (type)[i]), field))
	break;
    }

  if (i >= TYPE_NFIELDS (type))
    return 0;

  *offset = FIELD_BITPOS (TYPE_FIELDS (type)[i]) / TARGET_CHAR_BIT;
  *size = TYPE_LENGTH (check_typedef (TYPE_FIELDS (type)[i].type));
  return 1;
}

/* Called by F_OFFSET or F_SIZE to compute the description of a field
 declared using DECLARE_FIELD. */
int
linux_init_field (struct field_info *field, int check)
{
  if (field->type != NULL)
    return 1;

  field->type =
    lookup_symbol (field->struct_name, NULL, STRUCT_DOMAIN, NULL).symbol;
  if (field->type)
    {
      DEBUG (INIT, 1, "Checking for 'struct %s' : OK\n", field->struct_name);
    }
  else
    {
      field->type = lookup_symbol (field->struct_name,
				   NULL, VAR_DOMAIN, NULL).symbol;

      if (field->type
	  && TYPE_CODE (check_typedef (SYMBOL_TYPE (field->type)))
	  != TYPE_CODE_STRUCT)
	field->type = NULL;

      if (field->type != NULL)
	DEBUG (INIT, 1, "Checking for 'struct %s' : TYPEDEF\n", field->struct_name);
      else
	DEBUG (INIT, 1, "Checking for 'struct %s' : NOT FOUND\n", field->struct_name);
    }

  if (field->type == NULL
      || !find_struct_field (check_typedef (SYMBOL_TYPE (field->type)),
			     field->field_name, &field->offset, &field->size))
    {
      field->type = NULL;
      if (!check)
	error ("No such field %s::%s\n", field->struct_name,
	       field->field_name);

      return 0;
    }

  /* Chain initialized entries for cleanup. */
  field->next = field_info;
  field_info = field;

  DEBUG (INIT, 2, "%s::%s => offset %i  size %i\n", field->struct_name,
	 field->field_name, field->offset, field->size);
  return 1;
}

/* Cleanup all the field and address info that has been gathered. */
static void
fields_and_addrs_clear (void)
{
  struct field_info *next_field = field_info;
  struct addr_info *next_addr = addr_info;

  while (next_field)
    {
      next_field = field_info->next;
      field_info->type = NULL;
      field_info->next = NULL;
      field_info = next_field;
    }

  while (next_addr)
    {
      next_addr = addr_info->next;
      addr_info->bmsym.minsym = NULL;
      addr_info->bmsym.objfile = NULL;
      addr_info->next = NULL;
      addr_info = next_addr;
    }
}


/* If OBJFILE contains the symbols corresponding to one of the
   supported user-level threads libraries, activate the thread stratum
   implemented by this module.  */

static int
linux_kthread_activate (struct objfile *objfile)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  /* Skip if the thread stratum has already been activated.  */
  if (linux_kthread_active)
    return 0;

  /* There's no point in enabling this module if no
     architecture-specific operations are provided.  */
  if (!ops->supply_kthread)
    return 0;

  /* Verify that this represents an appropriate linux target */

  push_target (linux_kthread_ops);
  linux_kthread_active = 1;
  return 1;
}

/* Cleanup due to deactivation.  */

static void
linux_kthread_close (struct target_ops *self)
{
  linux_kthread_active = 0;

  /* Reset global variables */
  fields_and_addrs_clear ();
}

/* Deactivate the thread stratum implemented by this module.  */

static void
linux_kthread_deactivate (void)
{
  /* Skip if the thread stratum has already been deactivated.  */
  if (!linux_kthread_active)
    return;

  unpush_target (linux_kthread_ops);
}

static void
linux_kthread_inferior_created (struct target_ops *ops, int from_tty)
{
  linux_kthread_activate (NULL);
}

static void
linux_kthread_mourn_inferior (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);
  beneath->to_mourn_inferior (beneath);
  linux_kthread_deactivate ();
}

static void
linux_kthread_fetch_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_ops *kthread_ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);
  CORE_ADDR addr = ptid_get_tid (inferior_ptid);
  struct target_ops *beneath = find_target_beneath (ops);

  /* Always fetch the appropriate registers from the layer beneath.  */
  beneath->to_fetch_registers (beneath, regcache, regnum);
}

static void
linux_kthread_store_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_ops *kthread_ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);
  struct target_ops *beneath = find_target_beneath (ops);

  beneath->to_store_registers (beneath, regcache, regnum);
}

static ptid_t
linux_kthread_wait (struct target_ops *ops,
		    ptid_t ptid, struct target_waitstatus *status,
		    int options)
{
  struct target_ops *beneath = find_target_beneath (ops);

  /* Pass the request to the layer beneath.  */
  ptid = beneath->to_wait (beneath, ptid, status, options);

  return ptid;
}

static void
linux_kthread_resume (struct target_ops *ops,
		      ptid_t ptid, int step, enum gdb_signal sig)
{
  /* Pass the request to the layer beneath.  */
  struct target_ops *beneath = find_target_beneath (ops);
  beneath->to_resume (beneath, ptid, step, sig);
}

static int
linux_kthread_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  struct target_ops *beneath = find_target_beneath (ops);

  return beneath->to_thread_alive (beneath, ptid);
}

static void
linux_kthread_update_thread_list (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);

  prune_threads ();

  beneath->to_update_thread_list (beneath);
}

/* Return a string describing the state of the thread specified by
   INFO.  */

static char *
linux_kthread_extra_thread_info (struct target_ops *self,
				 struct thread_info *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());

  return "LinuxThread";
}

static char *
linux_kthread_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  return ptid_to_str (ptid);
}

static struct target_ops *
linux_kthread_target (void)
{
  struct target_ops *t = XCNEW (struct target_ops);

  t->to_shortname = "linux-kthreads";
  t->to_longname = "linux kernel-level threads";
  t->to_doc = "Linux kernel-level threads";
  t->to_close = linux_kthread_close;
  t->to_mourn_inferior = linux_kthread_mourn_inferior;
  t->to_fetch_registers = linux_kthread_fetch_registers;
  t->to_store_registers = linux_kthread_store_registers;
  t->to_wait = linux_kthread_wait;
  t->to_resume = linux_kthread_resume;
  t->to_thread_alive = linux_kthread_thread_alive;
  t->to_update_thread_list = linux_kthread_update_thread_list;
  t->to_extra_thread_info = linux_kthread_extra_thread_info;
  t->to_pid_to_str = linux_kthread_pid_to_str;
  t->to_stratum = thread_stratum;
  t->to_magic = OPS_MAGIC;
  linux_kthread_ops = t;

  return t;
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_linux_kthread;

void
_initialize_linux_kthread (void)
{
  complete_target_initialization (linux_kthread_target ());

  linux_kthread_data = gdbarch_data_register_pre_init (linux_kthread_init);

  observer_attach_inferior_created (linux_kthread_inferior_created);
}
