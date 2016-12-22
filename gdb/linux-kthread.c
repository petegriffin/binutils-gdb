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

/* This module allows GDB to correctly enumerate Linux kernel threads
   whilst debugging a Linux kernel. */

#include "defs.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "inferior.h"
#include "objfiles.h"
#include "observer.h"
#include "regcache.h"
#include "target.h"
#include "gdbcmd.h"

#include "gdb_obstack.h"
#include "macroscope.h"
#include "symtab.h"

#include "linux-kthread.h"

/* Whether to emit debugging output related to targetops. */
static int debug_linuxkthread_targetops=0;

/* Whether to emit debugging output related to threads. */
static int debug_linuxkthread_threads=0;

/* Whether to emit debugging output related to symbol lookup */
static int debug_linuxkthread_symbols=0;

/* Forward declarations */

static linux_kthread_info_t *lkthread_get_threadlist (void);
static linux_kthread_info_t *lkthread_get_by_ptid (ptid_t ptid);
static linux_kthread_info_t *lkthread_get_by_task_struct (CORE_ADDR task);
static linux_kthread_info_t *lkthread_get_running (int core);
static CORE_ADDR lkthread_get_runqueues_addr (void);
static CORE_ADDR lkthread_get_rq_curr_addr (int core);
static void lkthread_init (void);
static void lkthread_free_threadlist(void);
static void lkthread_invalidate_threadlist (void);
static int lkthread_is_curr_task (linux_kthread_info_t * ps);
static int lkthread_refresh_threadlist (int core);

/* Whether the cached Linux thread list needs refreshing */
static int kthread_list_invalid;

/* Whether target_ops to_interrupt is disabled */
static int lkthread_disable_to_interrupt=0;

/* Save the linux_kthreads ops returned by linux_kthread_target.  */
static struct target_ops *linux_kthread_ops;

/* Non-zero if the thread stratum implemented by this module is active.  */
static int linux_kthread_active;
static int linux_kthread_loaded;
static int linux_kthread_debug;

/* the core that triggered the event (zero-based) */
int stop_core = 0;

struct linux_kthread_data
{
  /* the processes list from Linux perspective */
  linux_kthread_info_t *process_list = NULL;

  /* the process we stopped at in target_wait */
  linux_kthread_info_t *wait_process = NULL;

  /* __per_cpu_offset */
  CORE_ADDR *per_cpu_offset;

  /* array of cur_rq(cpu) on each cpu */
  CORE_ADDR *rq_curr;

  /*array of rq->idle on each cpu */
  CORE_ADDR *rq_idle;

  /* array of scheduled process on each core */
  linux_kthread_info_t **running_process = NULL;

  /* array of process_counts for each cpu used for process list
     housekeeping */
  unsigned long *process_counts;

  /* Storage for the field layout and addresses already gathered. */
  struct field_info *field_info_list;
  struct addr_info *addr_info_list;

  unsigned char *scratch_buf;
  int scratch_buf_size;
};

/* Handle to global lkthread data.  */
static struct linux_kthread_data *lkthread_h;

/* Helper function to convert ptid to a string.  */

static char *
ptid_to_str (ptid_t ptid)
{
  static char str[32];
  snprintf (str, sizeof (str) - 1, "ptid %d: lwp %ld: tid %ld",
	    ptid_get_pid (ptid), ptid_get_lwp (ptid), ptid_get_tid (ptid));

  return str;
}

/* Symbol and Field resolution helper functions.  */

/* Helper function called by ADDR macro to fetch the address of a symbol
   declared using DECLARE_ADDR macro.  */

int
lkthread_lookup_addr (struct addr_info *addr, int check)
{
  if (addr->bmsym.minsym)
    return 1;

  addr->bmsym = lookup_minimal_symbol (addr->name, NULL, NULL);

  if (!addr->bmsym.minsym)
    {
      if (debug_linuxkthread_symbols)
	fprintf_unfiltered (gdb_stdlog, "Checking for address of '%s' :"
			    "NOT FOUND\n", addr->name);

      if (!check)
	error ("Couldn't find address of %s", addr->name);
      return 0;
    }

  /* Chain initialized entries for cleanup. */
  addr->next = lkthread_h->addr_info_list;
  lkthread_h->addr_info_list = addr;

  if (debug_linuxkthread_symbols)
    fprintf_unfiltered (gdb_stdlog, "%s address is %s\n", addr->name,
			phex (BMSYMBOL_VALUE_ADDRESS (addr->bmsym), 4));

  return 1;
}

/* Helper for lkthread_lookup_field.  */

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
   declared using DECLARE_FIELD.  */

int
lkthread_lookup_field (struct field_info *f, int check)
{

  if (f->type != NULL)
    return 1;

  f->type =
    lookup_symbol (f->struct_name, NULL, STRUCT_DOMAIN, NULL).symbol;

  if (!f->type)
    {
      f->type = lookup_symbol (f->struct_name, NULL, VAR_DOMAIN,
				   NULL).symbol;

      if (f->type && TYPE_CODE (check_typedef (SYMBOL_TYPE (f->type)))
	  != TYPE_CODE_STRUCT)
	f->type = NULL;

    }

  if (f->type == NULL
      || !find_struct_field (check_typedef (SYMBOL_TYPE (f->type)),
			     f->field_name, &f->offset, &f->size))
    {
      f->type = NULL;
      if (!check)
	error ("No such field %s::%s\n", f->struct_name, f->field_name);

      return 0;
    }

  /* Chain initialized entries for cleanup. */
  f->next = lkthread_h->field_info_list;
  lkthread_h->field_info_list = f;

  if (debug_linuxkthread_symbols)
    {
      fprintf_unfiltered (gdb_stdlog, "Checking for 'struct %s' : OK\n",
			  f->struct_name);
      fprintf_unfiltered (gdb_stdlog, "%s::%s => offset %i  size %i\n",
			  f->struct_name, f->field_name, f->offset, f->size);
    }
  return 1;
}

/* Cleanup all the field and address info that has been gathered.  */

static void
lkthread_reset_fields_and_addrs (void)
{
  struct field_info *next_field = lkthread_h->field_info_list;
  struct addr_info *next_addr = lkthread_h->addr_info_list;

  /* clear list of collected fields */
  while (next_field)
    {
      next_field = lkthread_h->field_info_list->next;
      lkthread_h->field_info_list->type = NULL;
      lkthread_h->field_info_list->next = NULL;
      lkthread_h->field_info_list = next_field;
    }

  /* clear list of collected addrs */
  while (next_addr)
    {
      next_addr = lkthread_h->addr_info_list->next;
      lkthread_h->addr_info_list->bmsym.minsym = NULL;
      lkthread_h->addr_info_list->bmsym.objfile = NULL;
      lkthread_h->addr_info_list->next = NULL;
      lkthread_h->addr_info_list = next_addr;
    }
}

/* This function checks for a macro definition at a particular symbol
   PC location and returns the replacement string or NULL if not found.
   It is used to allow linux-kthread debugger to hook on a kernel symbol
   and find out a macro definition e.g. PAGE_OFFSET if the kernel has
   been compiled with -g3.  */

const char *
kthread_find_macro_at_symbol(struct addr_info *symbol, char *macroname)
{
  struct symtab_and_line sal;
  struct macro_scope *ms = NULL;
  struct macro_definition *d;

  if (debug_linuxkthread_symbols)
    fprintf_filtered (gdb_stdout, "kthread_find_macro_at_symbol symbol=%s"
		      "macro %s\n", symbol->name, macroname);
  if (!macroname)
    {
      printf_filtered("No macro name provided\n");
      return NULL;
    }

  if (!HAS_ADDR_PTR(symbol))
    {
      printf_filtered("symbol doesn't exist\n");
      return NULL;
    }

  /* get symtab for the address of the symbol */
  sal = find_pc_line(ADDR_PTR(symbol), 0);

  /* get macro scope for that symtab */
  ms = sal_macro_scope (sal);

  if (!ms)
    {
      fprintf_filtered (gdb_stdout, "GDB has no preprocessor macro information"
			"for %s. Compile with -g3\n", symbol->name);
      return NULL;
    }

  d = macro_lookup_definition (ms->file, ms->line, macroname);
  xfree(ms);

  if (d)
    {
      return d->replacement;
    }
  else
    {
      fprintf_filtered (gdb_stdout,
			"The macro `%s' has no definition as a C/C++"
			" preprocessor macro at %s symbol\n"
			"at ", macroname, symbol->name);
      return NULL;
    }
}

/* Symbols for Process and Task list parsing.  */

DECLARE_ADDR (init_pid_ns);
DECLARE_FIELD (pid_namespace, last_pid);

DECLARE_ADDR (init_task);
DECLARE_FIELD (list_head, next);
DECLARE_FIELD (task_struct, active_mm);
DECLARE_FIELD (task_struct, mm);
DECLARE_FIELD (task_struct, tasks);
DECLARE_FIELD (task_struct, thread_group);
DECLARE_FIELD (task_struct, pid);
DECLARE_FIELD (task_struct, tgid);
DECLARE_FIELD (task_struct, prio);
DECLARE_FIELD (task_struct, comm);

DECLARE_FIELD (rq, curr);
DECLARE_FIELD (rq, idle);
DECLARE_FIELD (rq, lock);
DECLARE_FIELD (raw_spinlock, magic);

/* asm/generic/percpu.h
 * per_cpu_offset() is the offset that has to be added to a
 * percpu variable to get to the instance for a certain processor.
 * Most arches use the __per_cpu_offset array for those offsets but
 * some arches have their own ways of determining the offset (x86_64, s390).
 */

DECLARE_ADDR (__per_cpu_offset);
DECLARE_ADDR (per_cpu__process_counts);
DECLARE_ADDR (process_counts);
DECLARE_ADDR (per_cpu__runqueues);
DECLARE_ADDR (runqueues);

#define CORE_INVAL (-1)
int max_cores = CORE_INVAL;

static int last_pid;

/* Iterate_over_threads() callback.  */

static int
find_thread_tid (struct thread_info *tp, void *arg)
{
  long tid = *(long*)arg;

  return (ptid_get_tid(tp->ptid) == tid);
}

/* Iterate_over_threads() callback.  */

static int
find_thread_swapper (struct thread_info *tp, void *arg)
{
  long core = *(long*)arg;

  if ((!ptid_get_tid(tp->ptid)) && (ptid_get_lwp(tp->ptid) == core))
    {
      if (debug_linuxkthread_threads)
	fprintf_unfiltered (gdb_stdlog,
			    "swapper found: tp=%p tp->ptid %s core=%ld\n",
			    tp, ptid_to_str(tp->ptid), core);

      return 1;
    }
  return 0;
}

static void
proc_private_dtor (struct private_thread_info * dummy)
{
	/* nop, do not free. */
}

/* Creates the 'linux_kthread_info_t' for the task pointed to by the passed
   task_struct address by reading from the targets memory. If task_struct
   is zero it creates placeholder swapper entry.  */

static void
lkthread_get_task_info (CORE_ADDR task_struct, linux_kthread_info_t ** ps,
			int core)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  linux_kthread_info_t *l_ps;
  size_t size;
  unsigned char *task_name;
  int i = 0;
  long tid = 0;
  ptid_t this_ptid;

  while (*ps && (*ps)->valid)
      ps = &((*ps)->next);

  if (*ps == NULL)
    *ps = XCNEW (linux_kthread_info_t);

  l_ps = *ps;

  if (task_struct == 0)
    {
      /* Create swapper entry.  */

      if (debug_linuxkthread_threads)
	fprintf_unfiltered (gdb_stdlog, "Creating swapper for core %d ps=%p\n",
			    core, l_ps);

      /* Create a fake swapper entry now for the additional core
	 to keep the gdb_thread ordering.  */
      l_ps->task_struct = 0;
      l_ps->mm = 0;
      l_ps->tgid = 0;
      l_ps->prio = 0;
      l_ps->core = -1;

      if (l_ps->comm)
        {
	  xfree (l_ps->comm);
	  l_ps->comm = NULL;
        }
      l_ps->comm = xstrdup ("[swapper]");
    }
  else
    {
      /* Populate linux_kthread_info_t entry by reading from
	 task_struct target memory.  */
      size = F_OFFSET (task_struct, comm) + F_SIZE (task_struct, comm);

      task_name = lkthread_h->scratch_buf + F_OFFSET (task_struct, comm);

      /* Use scratch area for messing around with strings
	 to avoid static arrays and dispersed mallocs and frees.  */
      gdb_assert (lkthread_h->scratch_buf);
      gdb_assert (lkthread_h->scratch_buf_size >= size);

      /* The task_struct is not likely to change much from one kernel version
	 to another. Knowing that comm is one of the far fields,
	 try reading the task_struct in one go.  */
      read_memory (task_struct, lkthread_h->scratch_buf, size);

      l_ps->task_struct = task_struct;
      tid = extract_unsigned_field (lkthread_h->scratch_buf, task_struct,
				    pid, byte_order);

      l_ps->mm = extract_pointer_field (lkthread_h->scratch_buf,
					task_struct, mm);
      l_ps->active_mm = extract_pointer_field (lkthread_h->scratch_buf,
					       task_struct, active_mm);
      l_ps->tgid = extract_unsigned_field (lkthread_h->scratch_buf,
					   task_struct, tgid, byte_order);
      l_ps->prio = extract_unsigned_field (lkthread_h->scratch_buf,
					   task_struct, prio, byte_order);
      /* For to_core_of_threads.  */
      l_ps->core = core;

      /* Add square brackets to name for kernel threads.  */
      if (!l_ps->mm)
	{
	  int len = strlen ((char *)task_name);
	  *(task_name + len) = ']';
	  *(task_name + len + 1) = '\0';
	  *(--task_name) = '[';
	}

      if (l_ps->comm)
        {
	  xfree (l_ps->comm);
	  l_ps->comm = NULL;
        }
      l_ps->comm = xstrdup ((char*)task_name);
    }

  if (core != CORE_INVAL)
    {
      /* Long usage to map to LWP.  */
      long core_mapped = core + 1;

      /* swapper[core].  */
      gdb_assert (tid==0);

      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), core_mapped, tid);
      l_ps->gdb_thread =
	iterate_over_threads (find_thread_swapper, &core_mapped);
    }
  else
    {
      /* lwp stores CPU core, tid stores linux
	 pid this matches gdbremote usage.  */

      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), CORE_INVAL, tid);

      l_ps->gdb_thread = iterate_over_threads (find_thread_tid, &tid);

      /* Reset the thread core value, if existing.  */
      if (l_ps->gdb_thread)
	{
	  gdb_assert (!l_ps->gdb_thread->priv);
	  PTID_OF (l_ps).lwp = CORE_INVAL;
	}
    }

  /* Flag the new entry as valid.  */
  l_ps->valid = 1;

  /* Add new GDB thread if not found.  */
  if (!l_ps->gdb_thread)
   {
     if (debug_linuxkthread_threads)
       fprintf_unfiltered (gdb_stdlog, "allocate a new GDB thread\n");

      /* Add with info so that pid_to_string works.  */
      l_ps->gdb_thread =  add_thread_with_info (this_ptid,
				(struct private_thread_info *)l_ps);
    }

  /* Forcibly update the private field, as some threads (like hw threads)
     have already have been created without. This also indicates whether
     the gdb_thread needs to be pruned or not.  */

  l_ps->gdb_thread->priv = (struct private_thread_info *)l_ps;

  if (debug_linuxkthread_threads)
      fprintf_unfiltered (gdb_stdlog, "ps: comm = %s ptid=%s\n"
			  ,l_ps->comm, ptid_to_str(PTID_OF (l_ps)));

  /* The process list freeing is not handled thanks to
     this `private` facility, yet.  */

  l_ps->gdb_thread->private_dtor = proc_private_dtor;

  /* Keep trace of the last state to notify a change.  */
  l_ps->old_ptid = PTID_OF (l_ps);
}

/* Get the rq->curr task_struct address from the runqueue of the requested
   CPU core. Function returns a cached copy if already obtained from
   target memory. If no cached address is available it fetches it from
   target memory.  */

CORE_ADDR
lkthread_get_rq_curr_addr (int cpucore)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  int length =
    TYPE_LENGTH (builtin_type (target_gdbarch ())->builtin_data_ptr);

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_get_rq_curr_addr core(%d)\n",
			cpucore);

  /* If not already cached read from target.  */
  if (!lkthread_h->rq_curr[cpucore])
    {
      CORE_ADDR curr_addr = lkthread_get_runqueues_addr ();
      if (!curr_addr)
	return 0;

      curr_addr = curr_addr + (CORE_ADDR) lkthread_h->per_cpu_offset[cpucore] +
	F_OFFSET (rq, curr);

      lkthread_h->rq_curr[cpucore] =
	read_memory_unsigned_integer (curr_addr, length, byte_order);
    }

  return lkthread_h->rq_curr[cpucore];
}

/* Return the address of runqueues either from runqueues
   symbol or more likely per_cpu__runqueues symbol.  */

static CORE_ADDR
lkthread_get_runqueues_addr (void)
{
  CORE_ADDR runqueues_addr;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_get_runqueues_addr\n");

  if (HAS_ADDR (runqueues))
    {
      runqueues_addr = ADDR (runqueues);
    }
  else
    {
      runqueues_addr = ADDR (per_cpu__runqueues);
    }

  return runqueues_addr;
}

/* Returns the 'linux_kthread_info_t' corresponding to the passed task_struct
   address or NULL if not in the list.  */

linux_kthread_info_t *
lkthread_get_by_task_struct (CORE_ADDR task_struct)
{
  linux_kthread_info_t *ps = lkthread_get_threadlist ();

  while ((ps != NULL) && (ps->valid == 1))
    {
      if (ps->task_struct == task_struct)
	return ps;
      ps = ps->next;
    }

  return NULL;
}

/* Return the linux_kthread_info_t* for the process currently executing
   on the CPU core or NULL if CPU core is invalid.  */

linux_kthread_info_t *
lkthread_get_running (int core)
{
  linux_kthread_info_t **running_ps = lkthread_h->running_process;
  linux_kthread_info_t *current = NULL;
  CORE_ADDR rq_curr_taskstruct;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_get_running core=%d\n",core);

  if (core == CORE_INVAL)
    return NULL;

  /* If not already cached, read from target.  */
  if (running_ps[core] == NULL)
    {

      /* Ensure we have a runqueues address.  */
      gdb_assert (lkthread_get_runqueues_addr ());

      /* Get rq->curr task_struct address for CPU core.  */
      rq_curr_taskstruct = lkthread_get_rq_curr_addr (core);

      if (rq_curr_taskstruct)
	{
	  /* smp cpu is initialized.  */
	  current = lkthread_get_by_task_struct (rq_curr_taskstruct);

	  if (!current)
	    {
	      /* this task struct is not known yet AND was not seen
		 while running down the tasks lists, so this is presumably
		 the swapper of an secondary SMP core.  */

	      current =
		lkthread_get_by_ptid (ptid_build(ptid_get_pid(inferior_ptid),
						 core + 1, 0));

	      gdb_assert(current);

	      current->task_struct = rq_curr_taskstruct;
	    }
	  else
	    {
	      /* Update the thread's lwp in thread_list if it exists and
		 wasn't scheduled so that tid makes sense for both the
		 gdbserver and infrun.c.  */
	      PTID_OF (current).lwp = core + 1;
	    }

	  current->core = core;
	  running_ps[core] = current;

	}
    }

    if (debug_linuxkthread_threads)
      fprintf_unfiltered (gdb_stdlog, "running ps[%d]: comm = %s ptid=%s\n",
			  core, running_ps[core]->comm,
			  ptid_to_str(PTID_OF (running_ps[core])));

  return running_ps[core];
}

/* Return 1 if the passed linux_kthread_info_t is currently executing
   on the CPU. Otherwise return 0.  */

int
lkthread_is_curr_task (linux_kthread_info_t * ps)
{
  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_proc_is_curr_task\n");

  return (ps && (ps == lkthread_get_running (ps->core)));
}

/* Get the runqueue idle task_struct address for the given CPU core.  */

static CORE_ADDR
lkthread_get_rq_idle (int core)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  int length = TYPE_LENGTH (builtin_type (target_gdbarch ())->builtin_func_ptr);
  CORE_ADDR curr_addr = lkthread_get_runqueues_addr ();

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "get_rq_idle core(%d)\n", core);

  if (!curr_addr || !HAS_FIELD (rq, idle))
    return 0;

  /* If not already cached read from target.  */
  if (!lkthread_h->rq_idle[core])
    {
      curr_addr += (CORE_ADDR) lkthread_h->per_cpu_offset[core] +
	F_OFFSET (rq, idle);

      lkthread_h->rq_idle[core] = read_memory_unsigned_integer (curr_addr,
								length,
								byte_order);
    }

  return lkthread_h->rq_idle[core];
}

static int
get_process_count (int core)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  CORE_ADDR curr_addr = (CORE_ADDR) lkthread_h->per_cpu_offset[core];
  int length =
    TYPE_LENGTH (builtin_type (target_gdbarch ())->builtin_unsigned_long);
  static int warned = 0;
  int process_count;

  if (HAS_ADDR (process_counts))
    curr_addr += ADDR (process_counts);
  else if (HAS_ADDR (per_cpu__process_counts))
    curr_addr += ADDR (per_cpu__process_counts);
  else
    {
      /* Return a fake, changing value so the thread list will be
	 refreshed but in a less optimal way.  */
      if (!warned)
	fprintf_unfiltered (gdb_stdlog, "No `process_counts` symbol\n");

      warned++;
      return warned;
    }

  process_count = read_memory_unsigned_integer (curr_addr, length, byte_order);

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "core(%d) curr_addr=0x%lx proc_cnt=%d\n",
			core, curr_addr, process_count);

  return process_count;
}

static int
get_last_pid (void)
{
  int new_last_pid = 0;
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());

  if (HAS_ADDR (init_pid_ns))
    {
      /* Since 2.6.23 */
      new_last_pid = read_signed_field (ADDR (init_pid_ns),
					pid_namespace, last_pid, byte_order);
    }
  else
    fprintf_unfiltered (gdb_stdlog, "No `init_pid_ns` symbol found\n");

  return new_last_pid;
};

static void
lkthread_memset_percpu_data(int numcores)
{
  memset (lkthread_h->running_process, 0x0,
	  numcores * sizeof (linux_kthread_info_t *));
  memset (lkthread_h->rq_curr, 0x0, numcores * sizeof (CORE_ADDR));
  memset (lkthread_h->rq_idle, 0x0, numcores * sizeof (CORE_ADDR));
  memset (lkthread_h->per_cpu_offset, 0, numcores * sizeof (CORE_ADDR));
}

/* Allocate memory which is dependent on number of physical CPUs.  */

static void
lkthread_alloc_percpu_data(int numcores)
{
  gdb_assert (numcores >= 1);

  lkthread_h->running_process = XNEWVEC (linux_kthread_info_t *, numcores);
  lkthread_h->process_counts = XNEWVEC (unsigned long, numcores);

  lkthread_h->per_cpu_offset = XNEWVEC (CORE_ADDR, numcores);
  lkthread_h->rq_curr = XNEWVEC (CORE_ADDR, numcores);
  lkthread_h->rq_idle = XNEWVEC (CORE_ADDR, numcores);

  memset (lkthread_h->process_counts, 0, sizeof (unsigned long));
  lkthread_memset_percpu_data(numcores);
}

/* Free memory allocated by lkthread_alloc_percpu_data().  */

static void
lkthread_free_percpu_data(int numcores)
{
  xfree(lkthread_h->running_process);
  xfree(lkthread_h->process_counts);
  xfree(lkthread_h->per_cpu_offset);
  xfree(lkthread_h->rq_curr);
  xfree(lkthread_h->rq_idle);
}

void
lkthread_get_per_cpu_offsets(int numcores)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  int length = TYPE_LENGTH (builtin_type (target_gdbarch ())->builtin_data_ptr);
  CORE_ADDR curr_addr = ADDR (__per_cpu_offset);
  int core;


  if (!HAS_ADDR (__per_cpu_offset))
    {
      if (debug_linuxkthread_threads)
	fprintf_unfiltered (gdb_stdlog, "Assuming non-SMP kernel.\n");

      return;
    }

  for (core=0; core < numcores; core++)
    {
      if (!lkthread_h->per_cpu_offset[core])
	lkthread_h->per_cpu_offset[core] =
	  read_memory_unsigned_integer (curr_addr, length, byte_order);

      curr_addr += (CORE_ADDR) length;

      if (!lkthread_h->per_cpu_offset[core])
	{
	  warning ("Suspicious null per-cpu offsets,"
		   " or wrong number of detected cores:\n"
		   "ADDR (__per_cpu_offset) = %s\nmax_cores = %d",
		   phex (ADDR (__per_cpu_offset),4), max_cores);

	  break;
	}
    }

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "SMP kernel. %d cores detected\n",
			numcores);
}

/* Iterate_over_threads() callback to print thread info.  */

static int
thread_print_info (struct thread_info *tp, void *ignored)
{
  fprintf_unfiltered (gdb_stdlog, "thread_info = 0x%p ptid = %s\n",
		      tp, ptid_to_str(tp->ptid));
  return 0;
}


/* Initialise and allocate memory for linux-kthread module.  */

static void
lkthread_init (void)
{
  struct thread_info *th = NULL;
  struct cleanup *cleanup;
  int size =
    TYPE_LENGTH (builtin_type (target_gdbarch ())->builtin_unsigned_long);

  /* Ensure thread list from beneath target is up to date.  */
  cleanup = make_cleanup_restore_integer (&print_thread_events);
  print_thread_events = 0;
  update_thread_list ();
  do_cleanups (cleanup);

  /* Count the h/w threads.  */
  max_cores = thread_count ();
  gdb_assert (max_cores);

  if (debug_linuxkthread_threads)
    {
      fprintf_unfiltered (gdb_stdlog, "lkthread_init() cores(%d) GDB"
			  "HW threads\n", max_cores);
      iterate_over_threads (thread_print_info, NULL);
    }

  /* Allocate per cpu data.  */
  lkthread_alloc_percpu_data(max_cores);

  lkthread_get_per_cpu_offsets(max_cores);

  if (!lkthread_get_runqueues_addr () && (max_cores > 1))
    fprintf_unfiltered (gdb_stdlog, "Could not find the address of CPU"
			" runqueues current context information maybe "
			"less precise\n.");

  /* Invalidate the linux-kthread cached list.  */
  lkthread_invalidate_threadlist ();
}

/* Determines whether the cached Linux thread list needs
   to be invalidated and rebuilt by inspecting the targets
   memory.  */

int
lkthread_refresh_threadlist (int cur_core)
{
  int core;
  int new_last_pid;
  linux_kthread_info_t *ps;
  int do_invalidate = 0;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_refresh_threadlist (%d)\n",
			cur_core);

  /* Reset running_process and rq->curr cached values as they will
     always need to be refreshed.  */
  memset (lkthread_h->running_process, 0,
	  max_cores * sizeof (linux_kthread_info_t *));
  memset (lkthread_h->rq_curr, 0, max_cores * sizeof (CORE_ADDR));

  new_last_pid = get_last_pid ();
  if (new_last_pid != last_pid)
    {
      do_invalidate = 1;
      last_pid = new_last_pid;
    }

  /* Check if a process exited.  */
  for (core = 0; core < max_cores; core++)
    {
      int new_pcount = get_process_count (core);

      /* If primary core has no processes kernel hasn't started.  */
      if (core == 0 && new_pcount == 0)
	{
	  warning ("Primary core has no processes - has kernel started?\n");
	  warning ("linux-kthread will deactivate\n");
	  return 0;
	}

      if (new_pcount != lkthread_h->process_counts[core])
	{
	  lkthread_h->process_counts[core] = new_pcount;
	  do_invalidate = 1;
	}
    }

  if (do_invalidate)
      lkthread_invalidate_threadlist ();

  /* Update the process_list now, so that init_task is in there. */
  (void) lkthread_get_threadlist ();

  /* Call update_thread_list() to prune GDB threads which are no
     longer linked to a Linux task. */

  if (linux_kthread_active)
    update_thread_list();

  /* Set the running process
     we now have a thread_list looking like this:
     [1] = { 42000, 0, 1  }
     [2] = { 42000, 0, 2  }
     [3] = { 42000, 1, -1 }
     ....
     [N] = { 42000, PID_N, -1 }
     Now set the tid according to the running core.  */

  for (core = 0; core < max_cores; core++)
    lkthread_get_running (core);

  lkthread_h->wait_process = lkthread_get_running (cur_core);

  if (!lkthread_h->wait_process)
    return 0;

  gdb_assert(lkthread_h->wait_process->gdb_thread);

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "wait_process comm=%s ptid= %s\n",
			lkthread_h->wait_process->comm,
			ptid_to_str(PTID_OF (lkthread_h->wait_process)));

  gdb_assert((linux_kthread_info_t *) lkthread_h->wait_process->gdb_thread->priv
	     == lkthread_h->wait_process);

  /* Notify ptid changed.  */
  ps = lkthread_h->process_list;
  while (ps && ps->valid)
    {
      if (ptid_get_tid(ps->old_ptid) != ptid_get_tid(PTID_OF (ps)))
	{
	  observer_notify_thread_ptid_changed (ps->old_ptid, PTID_OF (ps));
	  ps->old_ptid.tid = ptid_get_tid(PTID_OF (ps));
	}
      ps = ps->next;
    }

  switch_to_thread(PTID_OF (lkthread_h->wait_process));
  gdb_assert(lkthread_get_by_ptid(inferior_ptid) == lkthread_h->wait_process);

  return 1;
}


static CORE_ADDR
_next_task (CORE_ADDR p)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct, tasks,
						      list_head, next,
						      byte_order);

  if (!cur_entry)
    {
      warning ("kernel task list contains NULL pointer");
      return 0;
    }

  return container_of (cur_entry, task_struct, tasks);
}

static CORE_ADDR
_next_thread (CORE_ADDR p)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct,
						      thread_group,
						      list_head, next,
						      byte_order);

  if (!cur_entry)
    {
      warning ("kernel thread group list contains NULL pointer\n");
      return 0;
    }

  return container_of (cur_entry, task_struct, thread_group);
}

/* Iterate round linux task_struct linked list calling
   lkthread_get_task_info() for each task_struct. Also
   calls lkthread_get_task_info() for each CPU runqueue
   idle task_struct to create swapper threads.  */

static linux_kthread_info_t **
lkthread_get_threadlist_helper (linux_kthread_info_t ** ps)
{
  struct linux_kthread_arch_ops *arch_ops =
    gdbarch_linux_kthread_ops (target_gdbarch ());
  CORE_ADDR rq_idle_taskstruct;
  CORE_ADDR g, t, init_task_addr;
  int core = 0, i;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_get_threadlist_helper\n");

  init_task_addr = ADDR (init_task);
  g = init_task_addr;

  do
    {
      t = g;
      do
        {

	  if (!arch_ops->is_kernel_address(t))
	    {
	      warning ("parsing of task list stopped because of invalid address"
		       "%s", phex (t, 4));
              break;
	    }

          lkthread_get_task_info (t, ps, core /*zero-based */ );
          core = CORE_INVAL;

          if (ptid_get_tid (PTID_OF (*ps)) == 0)
            {
              /* This is init_task, let's insert the other cores swapper
		 now.  */
              for (i = 1; i < max_cores; i++)
                {
                  ps = &((*ps)->next);
                  rq_idle_taskstruct = lkthread_get_rq_idle (i);
                  lkthread_get_task_info (rq_idle_taskstruct, ps, i);
                }
            }

	    if (debug_linuxkthread_threads)
	      fprintf_unfiltered (gdb_stdlog, "Got task info for %s (%li)\n",
				  (*ps)->comm, ptid_get_lwp (PTID_OF (*ps)));

          ps = &((*ps)->next);

	  /* Mark end of chain and remove those threads that disappeared
	     from the thread_list to avoid any_thread_of_process() to
	     select a ghost.  */
          if (*ps)
            (*ps)->valid = 0;

          t = _next_thread (t);
        } while (t && (t != g));

      g = _next_task (g);
    } while (g && (g != init_task_addr));

  return ps;
}

/*----------------------------------------------------------------------------*/

/* This function returns a the list of 'linux_kthread_info_t' corresponding
   to the tasks in the kernel's task list.  */

static linux_kthread_info_t *
lkthread_get_threadlist (void)
{
  /* Return the cached copy if there is one,
     or rebuild it.  */

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkthread_getthread_list\n");

  if (lkthread_h->process_list && lkthread_h->process_list->valid)
    return lkthread_h->process_list;

  gdb_assert (kthread_list_invalid);

  lkthread_get_threadlist_helper (&lkthread_h->process_list);

  kthread_list_invalid = FALSE;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "kthread_list_invalid (%d)\n",
			kthread_list_invalid);

  return lkthread_h->process_list;
}

/* Returns a valid 'linux_kthread_info_t' corresponding to
   the passed ptid or NULL if not found. NULL means
   the thread needs to be pruned.  */

linux_kthread_info_t *lkthread_get_by_ptid (ptid_t ptid)
{
  struct thread_info *tp;
  long tid = ptid_get_tid(ptid);
  long lwp = ptid_get_lwp(ptid);
  linux_kthread_info_t *ps;

  /* Check list is valid.  */
  gdb_assert(!kthread_list_invalid);

  if (tid)
    {
	  /* non-swapper, tid is Linux pid.  */
	  tp = iterate_over_threads (find_thread_tid, (void *) &tid);
    }
  else
    {
	  /* swapper, lwp gives the core, tid = 0 and is not unique.  */
	  tp = iterate_over_threads (find_thread_swapper, (void *) &lwp);
    }

  ps = (linux_kthread_info_t *)tp->priv;

  if (debug_linuxkthread_threads > 2)
    fprintf_unfiltered (gdb_stdlog, "ptid %s tp=0x%p ps=0x%p\n",
			ptid_to_str(ptid), tp, tp->priv);

  /* Prune the gdb-thread if the process is not valid
     meaning it was no longer found in the task list.  */
  return ps;
}

/* Iterate_over_threads() callback. Invalidate the gdb thread if
   the linux process has died.  */

static int
thread_clear_info (struct thread_info *tp, void *ignored)
{
  tp->priv = NULL;
  return 0;
}

/* Invalidate the cached Linux task list.  */

static void
lkthread_invalidate_threadlist (void)
{
  linux_kthread_info_t *ps = lkthread_h->process_list;
  linux_kthread_info_t *cur;

  while (ps)
    {
      cur = ps;
      ps = ps->next;
      cur->valid = 0;
    }

  /* We invalidate the processes attached to the gdb_thread
     setting tp->private to null tells if the thread can
     be deleted or not.  */

  iterate_over_threads (thread_clear_info, NULL);

  kthread_list_invalid = TRUE;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "kthread_list_invalid (%d)\n",
			kthread_list_invalid);
}

/* Free memory allocated in the task list.  */

static void
lkthread_free_threadlist (void)
{
  linux_kthread_info_t *ps = lkthread_h->process_list;
  linux_kthread_info_t *cur;
  while (ps)
    {
      cur = ps;
      ps = ps->next;
      xfree (cur->comm);
      xfree (cur);
    }
  lkthread_h->process_list = NULL;
}

/* Target Layer Implementation  */


/* If OBJFILE contains the symbols corresponding to the Linux kernel,
   activate the thread stratum implemented by this module.  */

static int
linux_kthread_activate (struct objfile *objfile)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct linux_kthread_arch_ops *arch_ops = gdbarch_linux_kthread_ops (gdbarch);
  struct regcache *regcache;
  CORE_ADDR pc;

  /* Skip if the thread stratum has already been activated.  */
  if (linux_kthread_active)
    return 0;

  /* There's no point in enabling this module if no
     architecture-specific operations are provided.  */
  if (!arch_ops)
    return 0;

  /* Allocate global data struct.  */
  lkthread_h = XCNEW (struct linux_kthread_data);

  /* Allocate private scratch buffer.  */
  lkthread_h->scratch_buf_size = 4096;
  lkthread_h->scratch_buf =
    (unsigned char *) xcalloc (lkthread_h->scratch_buf_size, sizeof (char));

  /* Verify that this represents an appropriate linux target.  */

  /* Check target halted at a kernel address, otherwise we can't
     access any kernel memory. Using regcache_read_pc() is OK
     here as we haven't pushed linux-kthread stratum yet.  */
  regcache = get_thread_regcache (inferior_ptid);
  pc = regcache_read_pc (regcache);
  if (!arch_ops->is_kernel_address(pc))
  {
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_activate() target"
			"stopped in user space\n");
    return 0;
  }

  lkthread_init ();

  /* TODO: check kernel in memory matches vmlinux (Linux banner etc?) */

  /* To get correct thread names from add_thread_with_info()
     target_ops must be pushed before enumerating kthreads.  */

  push_target (linux_kthread_ops);
  linux_kthread_active = 1;

  /* Scan the linux threads.  */
  if (!lkthread_refresh_threadlist (stop_core))
    {
      if (debug_linuxkthread_threads)
	  fprintf_unfiltered (gdb_stdlog, "lkthread_refresh_threadlist\n");

      /* Don't activate linux-kthread as no threads were found.  */
      lkthread_invalidate_threadlist ();

      prune_threads();
      return 0;
    }

  return 1;
}

/* The linux-kthread to_load target_ops method.  */

static void
linux_kthread_load (struct target_ops *ops, const char *prog, int fromtty)
{
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_load\n");

  beneath->to_load (ops, prog, fromtty);
}

/* The target_ops callback called by GDB to load the attach to an
   already running program. Just sets 'loaded' to 1, as the program is
   already loaded. If you attach with a non standard command, you have
   to do 'set linux-awareness loaded 1' by hand.  */

static void
linux_kthread_attach (struct target_ops *ops, const char *prog, int fromtty)
{
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_attach\n");

  beneath->to_attach (ops, prog, fromtty);
}


/* The linux-kthread to_close target_ops method.  */

static void
linux_kthread_close (struct target_ops *self)
{
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_close\n");

}

/* Deactivate the linux-kthread stratum implemented by this module.  */

static void
linux_kthread_deactivate (void)
{

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_deactivate (%d)\n",
			linux_kthread_active);

  /* Skip if the thread stratum has already been deactivated.  */
  if (!linux_kthread_active)
    return;

  lkthread_h->wait_process = NULL;

  lkthread_invalidate_threadlist();

  lkthread_free_threadlist ();

  /* Reset collected symbol info.  */
  lkthread_reset_fields_and_addrs ();

  /* Fallback to any thread that makes sense for the beneath target.  */
  unpush_target (linux_kthread_ops);

  /* So we are only left with physical CPU threads from beneath
     target.  */
  prune_threads();

  lkthread_free_percpu_data(max_cores);

  /* Free global lkthread struct.  */
  xfree(lkthread_h);

  linux_kthread_active = 0;
}

static void
linux_kthread_inferior_created (struct target_ops *ops, int from_tty)
{
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_inferior_created\n");

  linux_kthread_activate (NULL);
}

/* The linux-kthread to_mourn_inferior target_ops method */

static void
linux_kthread_mourn_inferior (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_mourn_inferior\n");
  beneath->to_mourn_inferior (beneath);
  linux_kthread_deactivate ();
}

/* The linux-kthread to_fetch_registers target_ops method.
   This function determines whether the thread is running on
   a physical CPU in which cases it defers to the layer beneath
   to populate the register cache or if it is a sleeping
   descheduled thread it uses the arch_ops to populate the registers
   from what the kernel saved on the stack.  */

static void
linux_kthread_fetch_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_arch_ops *arch_ops = gdbarch_linux_kthread_ops (gdbarch);
  struct target_ops *beneath = find_target_beneath (ops);
  CORE_ADDR addr = ptid_get_tid (inferior_ptid);
  linux_kthread_info_t *ps;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_fetch_registers\n");

  if (!(ps = lkthread_get_by_ptid (inferior_ptid))
      || lkthread_is_curr_task (ps))
    return beneath->to_fetch_registers (beneath, regcache, regnum);

  /* Call the platform specific code.  */
  arch_ops->to_fetch_registers(regcache, regnum, ps->task_struct);
}

/* The linux-kthread to_store_registers target_ops method.
   This function determines whether the thread is running on
   a physical CPU in which cases it defers to the layer beneath
   or uses the arch_ops callback to write the registers into
   the stack of the sleeping thread.  */

static void
linux_kthread_store_registers (struct target_ops *ops,
			       struct regcache *regcache, int regnum)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct linux_kthread_arch_ops *arch_ops = gdbarch_linux_kthread_ops (gdbarch);
  struct target_ops *beneath = find_target_beneath (ops);
  linux_kthread_info_t *ps;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_store_registers\n");

  if (!(ps = lkthread_get_by_ptid (inferior_ptid)) || lkthread_is_curr_task (ps))
      return beneath->to_store_registers (beneath, regcache, regnum);

  /* Call the platform specific code.  */
  arch_ops->to_store_registers(regcache, regnum, ps->task_struct);
}

/* Helper function to always use layer beneath to fetch PC.
   Parts of linux-kthread can't use regcache_read_pc() API to determine
   the PC as it vectors through  linux_kthread_fetch_registers()
   which itself needs to read kernel memory to determine whether
   the thread is sleeping or not. This function is used to help
   determine whether the target stopped in userspace and therefore
   linux-kthread can no longer read kernel memory or display
   kernel threads.  */

static CORE_ADDR lkthread_get_pc(struct target_ops *ops)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct target_ops *beneath = find_target_beneath (ops);
  struct regcache *regcache;
  CORE_ADDR pc;
  int regnum;

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "lkthread_get_pc\n");

  regcache = get_thread_regcache (inferior_ptid);
  regnum = gdbarch_pc_regnum (gdbarch);

  gdb_assert(regnum > 0);

  beneath->to_fetch_registers (beneath, regcache, regnum);

  regcache_raw_collect (regcache, regnum, &pc);

  return pc;
}

/* The linux-kthread to_wait target_ops method */

static ptid_t
linux_kthread_wait (struct target_ops *ops,
		    ptid_t ptid, struct target_waitstatus *status,
		    int options)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct linux_kthread_arch_ops *arch_ops = gdbarch_linux_kthread_ops (gdbarch);
  struct target_ops *beneath = find_target_beneath (ops);
  ptid_t stop_ptid;
  CORE_ADDR pc;

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_wait\n");

  /* Pass the request to the layer beneath.  */
  stop_ptid = beneath->to_wait (beneath, ptid, status, options);

  /* get PC of CPU.  */
  pc = lkthread_get_pc(ops);

  /* Check it is executing in the kernel before accessing kernel
     memory.  */
  if (!arch_ops->is_kernel_address(pc))
  {
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_wait() target stopped"
			" in user space. Disabling linux-kthread\n");
    linux_kthread_deactivate();
    return stop_ptid;
  }

  if (max_cores > 1)
    stop_core = ptid_get_lwp (stop_ptid) - 1;
  else
    stop_core = 0;

  /* Reset the inferior_ptid to the stopped ptid.  */
  inferior_ptid = stop_ptid;

  /* Rescan for new task, but avoid storming the debug connection.  */
  lkthread_refresh_threadlist (stop_core);

   /* The above calls might will end up accessing the registers
      of the target because of inhibit_thread_awareness(). However,
      this will populate a register cache associated with
      inferior_ptid, which we haven't updated yet. Force a flush
      of these cached values so that they end up associated to
      the right context.  */
   registers_changed ();

   /* This is normally done by infrun.c:handle_inferior_event (),
      but we need it set to access the frames for some operations
      below (eg. in check_exec_actions (), where we don't know
      what the user will ask in his commands.  */
   set_executing (minus_one_ptid, 0);

   if (lkthread_h->wait_process)
     {
       inferior_ptid = PTID_OF (lkthread_h->wait_process);
       stop_ptid = inferior_ptid;
     }

  return stop_ptid;
}

/* The linux-kthread to_resume target_ops method.  */

static void
linux_kthread_resume (struct target_ops *ops,
		      ptid_t ptid, int step, enum gdb_signal sig)
{
  /* Pass the request to the layer beneath.  */
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "Resuming %i with sig %i (step %i)\n",
			(int) ptid_get_pid (ptid), (int) sig, step);

  beneath->to_resume (beneath, ptid, step, sig);
}

/* The linux-kthread to_thread_alive target_ops method.  */

static int
linux_kthread_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  struct target_ops *beneath = find_target_beneath (ops);
  linux_kthread_info_t *ps;

  if (debug_linuxkthread_targetops > 2)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_thread_alive ptid=%s\n",
			ptid_to_str(ptid));

  ps = lkthread_get_by_ptid (ptid);

  if (!ps)
    {
      if (debug_linuxkthread_threads > 2)
	fprintf_unfiltered (gdb_stdlog, "Prune thread ps(%p)\n",ps);

      return 0;
    }

  if (debug_linuxkthread_threads > 2)
    fprintf_unfiltered (gdb_stdlog, "Alive thread ps(%p)\n",ps);

  return 1;
}

/* The linux-kthread to_update_thread_list target_ops method.  */

static void
linux_kthread_update_thread_list (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_update_thread_list\n");

  /* Build linux threads on top.  */
  lkthread_get_threadlist ();

  prune_threads ();
}

/* The linux-kthread to_extra_thread_info target_ops method.
   Return a string describing the state of the thread specified by
   INFO.  */

static char *
linux_kthread_extra_thread_info (struct target_ops *self,
				 struct thread_info *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  linux_kthread_info_t *ps = (linux_kthread_info_t *) info->priv;

  if (ps)
    {
      char *msg = get_print_cell ();
      size_t len = 0;

      len = snprintf (msg, PRINT_CELL_SIZE, "pid: %li tgid: %i",
		      ptid_get_tid(PTID_OF (ps)), ps->tgid);

      /* Now GDB is displaying all kernel threads it is important
	 to let the user know which threads are actually scheduled
	 on the CPU cores. We do this by adding <C core_num> to the
	 thread name if it is currently executing on the processor
	 when the target was halted.  */

      if (lkthread_is_curr_task (ps))
	snprintf (msg + len, PRINT_CELL_SIZE - len, " <C%u>", ps->core);

      return msg;
    }

  return "LinuxThread";
}

/* The linux-kthread to_pid_to_str target_ops method.  */

static char *
linux_kthread_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  linux_kthread_info_t *ps;
  struct thread_info *tp;

  /* when quitting typically */
  if (!ptid_get_lwp(ptid))
    return "Linux Kernel";

  tp = find_thread_ptid (ptid);

  if (!tp || !tp->priv) {
    warning ("Suspicious !tp or !tp->priv");
    return "";
  }

  /* We use thread_info priv field for storing linux_kthread_info_t.  */
  ps = (linux_kthread_info_t *) tp->priv;

  gdb_assert (ps->comm);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "kthread_pid_to_str ptid %s str=%s\n",
			ptid_to_str(ptid), ps->comm);

  return ps->comm;
}

/* The linux-kthread to_thread_name target_ops method.  */

static const char *
linux_kthread_thread_name (struct target_ops *ops, struct thread_info *thread)
{
  /* All the thread name information has generally been
     returned already through the pid_to_str.
     We could refactor this around and 'correct' the naming
     but then you wouldn't get niceties such as
     [Switching to thread 52 (getty)].  */

  return NULL;
}

/* The linux-kthread to_can_async_p target_ops method.  */

static int
linux_kthread_can_async_p (struct target_ops *ops)
{
  return 0;
}

/* The linux-kthread is_async_p target_ops method.  */

static int
linux_kthread_is_async_p (struct target_ops *ops)
{
  return 0;
}

/* The linux-kthread to_interrupt target_ops method.  */

static void
linux_kthread_interrupt (struct target_ops *ops, ptid_t ptid)
{
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_interrupt called\n");

  if (!lkthread_disable_to_interrupt)
    beneath->to_interrupt(ops, ptid);
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
  /* Registers */
  t->to_fetch_registers = linux_kthread_fetch_registers;
  t->to_store_registers = linux_kthread_store_registers;

  /* Execution */
  t->to_wait = linux_kthread_wait;
  t->to_resume = linux_kthread_resume;

  /* Threads */
  t->to_thread_alive = linux_kthread_thread_alive;
  t->to_update_thread_list = linux_kthread_update_thread_list;
  t->to_extra_thread_info = linux_kthread_extra_thread_info;
  t->to_thread_name = linux_kthread_thread_name;
  t->to_pid_to_str = linux_kthread_pid_to_str;
  t->to_stratum = thread_stratum;
  t->to_magic = OPS_MAGIC;

  t->to_interrupt = linux_kthread_interrupt;

  linux_kthread_ops = t;

  /* Prevent async operations */
  t->to_can_async_p = linux_kthread_can_async_p;
  t->to_is_async_p = linux_kthread_is_async_p;

  return t;
}

static ptid_t target_thread_ptid;

static void
linux_awareness_target_thread_changed (ptid_t ptid)
{
  if (ptid_equal (ptid, null_ptid) || ptid_equal (ptid, minus_one_ptid))
    target_thread_ptid = null_ptid;
  else if (ptid_get_tid (ptid) != CORE_INVAL)
    target_thread_ptid = ptid;
}


/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_linux_kthread;

/* Command-list for the "set/show linuxkthread" prefix command.  */
static struct cmd_list_element *set_linuxkthread_list;
static struct cmd_list_element *show_linuxkthread_list;

static void
set_linuxkthread_command (char *arg, int from_tty)
{
  printf_unfiltered (_(\
"\"set linuxkthread\" must be followed by the name of a setting.\n"));
  help_list (set_linuxkthread_list, "set linuxkthread ", all_commands, gdb_stdout);
}

/* Implement the "show linuxkthread" prefix command.  */

static void
show_linuxkthread_command (char *args, int from_tty)
{
  cmd_show_list (show_linuxkthread_list, from_tty, "");
}

/* This function is called after load, or after attach, when we know
   that the kernel code is in memory. (This might be called direclty
   by the user by issuing 'set linux-kthread loaded on', if he doesn't
   use a standard attach mechanism.  */

void
lkthread_loaded_set (char *arg, int from_tty, struct cmd_list_element *c)
{
  ptid_t stop_ptid;

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "lkthread_loaded_set (%d)\n",
			linux_kthread_loaded);

  /* If stratum already active, and user requests it to be disabled.  */
  if (linux_kthread_active && !linux_kthread_loaded)
    {
      linux_kthread_deactivate ();
    }
  else if (!linux_kthread_active && linux_kthread_loaded)
    {
      /* If already disabled, and user requests it to be enabled.  */
      stop_core = 0;
      linux_kthread_activate (NULL);
    }
}


void
_initialize_linux_kthread (void)
{
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "_initialize_linux_kthread\n");

  complete_target_initialization (linux_kthread_target ());

  /* Notice when a inferior is created in order to push the
     linuxkthread ops if needed.  */
  observer_attach_inferior_created (linux_kthread_inferior_created);

  target_thread_ptid = null_ptid;
  observer_attach_target_thread_changed (linux_awareness_target_thread_changed);

  add_prefix_cmd ("linuxkthread", no_class, set_linuxkthread_command,
                  _("Prefix command for changing Linuxkthread-specific settings"),
                  &set_linuxkthread_list, "set linuxkthread ", 0, &setlist);

  add_prefix_cmd ("linuxkthread", no_class, show_linuxkthread_command,
                  _("Prefix command for showing Linuxkthread-specific settings"),
                  &show_linuxkthread_list, "show linuxkthread ", 0, &showlist);

  add_setshow_boolean_cmd ("loaded",
			   no_class,
			   &linux_kthread_loaded,
			   "Enable support for Linux thread runtime",
			   "Disable support for Linux thread runtime",
			   NULL, &lkthread_loaded_set, NULL,
			   &set_linuxkthread_list,
			   &show_linuxkthread_list);

}
