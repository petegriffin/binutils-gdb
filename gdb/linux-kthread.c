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

#include "gdb_obstack.h"

#include "linux-kthread.h"

/* Whether to emit debugging output related to targetops. */
static int debug_linuxkthread_targetops=0;

/* Whether to emit debugging output related to threads. */
static int debug_linuxkthread_threads=0;

/* Whether to emit debugging output related to symbol lookup */
static int debug_linuxkthread_symbols=0;

/* Forward declarations */
void lkd_proc_invalidate_list (void);
int lkd_proc_refresh_info (int core);

static linux_kthread_info_t *lkd_proc_get_list (void);
static linux_kthread_info_t *lkd_proc_get_by_ptid (ptid_t ptid);
static linux_kthread_info_t *lkd_proc_get_by_task_struct (CORE_ADDR task);
static linux_kthread_info_t *lkd_proc_get_running (int core);
static CORE_ADDR lkd_proc_get_runqueues (int reset);
static CORE_ADDR lkd_proc_get_rq_curr (int core);
static void lkd_proc_init (void);
static void lkd_proc_free_list(void);
static int lkd_proc_is_curr_task (linux_kthread_info_t * ps);

static int kthread_list_invalid;
static unsigned char *scratch_buf;
static int scratch_buf_size;

/* Save the linux_kthreads ops returned by linux_kthread_target.  */
static struct target_ops *linux_kthread_ops;

/* Non-zero if the thread stratum implemented by this module is active.  */
static int linux_kthread_active;

/* the core that triggered the event (zero-based)*/
int stop_core = 0;

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
  snprintf (str, sizeof (str) - 1, "ptid %d: lwp %ld: tid %ld",
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
      if (debug_linuxkthread_symbols)
	fprintf_unfiltered (gdb_stdlog, "Checking for address of '%s' :"
			    "NOT FOUND\n", addr->name);

      if (!check)
	error ("Couldn't find address of %s", addr->name);
      return 0;
    }

  /* Chain initialized entries for cleanup. */
  addr->next = addr_info;
  addr_info = addr;

  if (debug_linuxkthread_symbols)
    fprintf_unfiltered (gdb_stdlog, "%s address is %s\n", addr->name,
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
      if (debug_linuxkthread_symbols)
	fprintf_unfiltered (gdb_stdlog, "Checking for 'struct %s' : OK\n",
			    field->struct_name);
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
	fprintf_unfiltered (gdb_stdlog, "Checking for 'struct %s' : TYPEDEF\n",
			    field->struct_name);
      else
	fprintf_unfiltered (gdb_stdlog, "Checking for 'struct %s' : NOT FOUND\n",
			    field->struct_name);
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

  if (debug_linuxkthread_symbols)
    fprintf_unfiltered (gdb_stdlog, "%s::%s => offset %i  size %i\n"
			, field->struct_name, field->field_name,
			field->offset, field->size);
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

/* Process and Task list Parsing  */

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

/*realize cur_rq(cpu)->curr*/
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


/* TODO dynamically allocate memory based on thread_count() */
#define MAX_CORES 5
#define CORE_INVAL (-1)		/* 0 = name on the inferior, cannot be used */
int max_cores = MAX_CORES;


/* The current task. */
/* the processes list from Linux perspective */
linux_kthread_info_t *process_list = NULL;
/* the process we stopped at in target_wait */
linux_kthread_info_t *wait_process = NULL;
/* scheduled process as seen by each core */
linux_kthread_info_t *running_process[MAX_CORES];

uint32_t per_cpu_offset[MAX_CORES]; /*__per_cpu_offset*/

/* per cpu peeks */
CORE_ADDR runqueues_addr;
CORE_ADDR rq_curr[MAX_CORES];	/*cur_rq(cpu) */
CORE_ADDR rq_idle[MAX_CORES];	/*rq->idle */

/* process list housekeeping*/
static unsigned long kthread_process_counts[MAX_CORES];
static int last_pid;

static int
find_thread_tid (struct thread_info *tp, void *arg)
{
  long tid = *(long*)arg;

  return (ptid_get_tid(tp->ptid) == tid);
}

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

/* invalidate the cached task list. */
static void
proc_private_dtor (struct private_thread_info * dummy)
{
	/* nop, do not free. */
}

/* Create the 'linux_kthread_info_t' for the task pointed by the passed
 TASK_STRUCT. */
static void
get_task_info (CORE_ADDR task_struct, linux_kthread_info_t ** ps,
	       int core /*zero-based */ )
{
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

      if (debug_linuxkthread_threads)
	fprintf_unfiltered (gdb_stdlog, "Creating swapper for core %d ps=%p\n",
			    core, l_ps);
      /* create a fake swapper entry now for the additional core
       * to keep the gdb_thread ordering
       **/
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
      size = F_OFFSET (task_struct, comm) + F_SIZE (task_struct, comm);

      task_name = scratch_buf + F_OFFSET (task_struct, comm);

      /* use scratch area for messing around with strings
       * to avoid static arrays and dispersed mallocs and frees
       **/
      gdb_assert (scratch_buf);
      gdb_assert (scratch_buf_size >= size);

      /* the task struct is not likely to change much from one kernel version
       * to another. Knowing that comm is one of the far fields,
       * try read the task struct in one command */
      read_memory (task_struct, scratch_buf, size);

      l_ps->task_struct = task_struct;
      tid = extract_unsigned_field (scratch_buf, task_struct, pid);
      l_ps->mm = extract_pointer_field (scratch_buf,
					task_struct, mm);
      l_ps->active_mm = extract_pointer_field (scratch_buf,
					       task_struct, active_mm);
      l_ps->tgid = extract_unsigned_field (scratch_buf,
					 task_struct, tgid);
      l_ps->prio = extract_unsigned_field (scratch_buf,
					   task_struct, prio);
      l_ps->core = core;	/* for to_core_of_threads */

      /* add square brackets to name for kernel threads */
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
      /* Long usage to map to LWP */
      long core_mapped = core + 1;

      /* swapper[core] */
      gdb_assert (tid==0);

      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), core_mapped, tid /* == 0*/);
      l_ps->gdb_thread =
	iterate_over_threads (find_thread_swapper, &core_mapped);
    }
  else
    {
      /* lwp is now cpu core for everything, tid is linux
	 pid this matches gdbremote usage */

      this_ptid = ptid_build (ptid_get_pid(inferior_ptid), CORE_INVAL, tid);

      l_ps->gdb_thread = iterate_over_threads (find_thread_tid, &tid);

      /*reset the thread core value, if existing */
      if (l_ps->gdb_thread)
	{
	  gdb_assert (!l_ps->gdb_thread->priv);
	  PTID_OF (l_ps).lwp = CORE_INVAL;
	}
    }

  l_ps->valid = 1;

  /* allocate if not found
   */
  if (!l_ps->gdb_thread)
   {
     if (debug_linuxkthread_threads)
       fprintf_unfiltered (gdb_stdlog, "allocate a new thread");

      /* add with info so that pid_to_string works. */
      l_ps->gdb_thread =  add_thread_with_info (this_ptid,
				(struct private_thread_info *)l_ps);
    }

  /* forcibly update the private fields, as some thread may
   * already have been created without, like hw threads.
   * and this also tell is the gdb_thread is pruned or not!*/

  l_ps->gdb_thread->priv = (struct private_thread_info *)l_ps;

  if (debug_linuxkthread_threads)
      fprintf_unfiltered (gdb_stdlog, "ps: comm = %s ptid=%s\n"
			  ,l_ps->comm, ptid_to_str(PTID_OF (l_ps)));

  /* the process list freeing is not handled thanks to
   * this `private` facility, yet.
   */
  l_ps->gdb_thread->private_dtor = proc_private_dtor;

  /* keep trace of the last state to notify a change */
  l_ps->old_ptid = PTID_OF (l_ps);
}

/*attempt getting the runqueue address for a core*/
CORE_ADDR
lkd_proc_get_rq_curr (int core)
{

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkd_proc_get_rq_curr\n");

  if (!rq_curr[core])
    {
      CORE_ADDR curr_addr = lkd_proc_get_runqueues (0);
      if (!curr_addr)
	return 0;
      curr_addr =
	curr_addr + (CORE_ADDR) per_cpu_offset[core] + F_OFFSET (rq, curr);
      rq_curr[core] = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
						    LKD_BYTE_ORDER);
    }

  return rq_curr[core];
};

CORE_ADDR
lkd_proc_get_runqueues (int reset)
{
  CORE_ADDR swapper = 0;
  linux_kthread_info_t *test_ps;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkd_proc_get_runqueues\n");

  runqueues_addr = 0;

  if (HAS_ADDR (runqueues))
    {
      runqueues_addr = ADDR (runqueues);
    }
  else
    {
      runqueues_addr = ADDR (per_cpu__runqueues);
    }
  /* check validity */

  if (debug_linuxkthread_threads)
    {
      if (HAS_FIELD (raw_spinlock, magic))
	{

	  CORE_ADDR lock_magic = ADDR (runqueues)
	    + (CORE_ADDR) per_cpu_offset[0]
	    + F_OFFSET (rq, lock) + F_OFFSET (raw_spinlock,
					      magic);

	  if ((read_memory_unsigned_integer (lock_magic, 4 /*uint32 */ ,
					     LKD_BYTE_ORDER) & 0xdead0000)
	      != 0xdead0000)
	    error ("accessing the core runqueues seems to be compromised.");
	}
      else
	printf_filtered ("runqueues access validated OK.\n");
    }

  return runqueues_addr;
}

/* Returns the 'linux_kthread_info_t' corresponding to the passed task_struct or
 NULL if not in the list. */
linux_kthread_info_t *
lkd_proc_get_by_task_struct (CORE_ADDR task_struct)
{
  linux_kthread_info_t *ps = lkd_proc_get_list ();

  while ((ps != NULL) && (ps->valid == 1))
    {
      if (ps->task_struct == task_struct)
	return ps;
      ps = ps->next;
    }

  return NULL;
}

/* Return the process currently scheduled on one core */
linux_kthread_info_t *
lkd_proc_get_running (int core)
{
  linux_kthread_info_t *current = NULL;
  CORE_ADDR task;
  struct thread_info *tp;	/*gdb ti */
  ptid_t old_ptid;

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkd_proc_get_running core=%d\n",core);

  if (core == CORE_INVAL)
    return NULL;

  if (running_process[core] == NULL)
    {

      gdb_assert (lkd_proc_get_runqueues (0));

      task = lkd_proc_get_rq_curr (core);

      if (task)
	{			/* smp cpu is initialized */
	  current = lkd_proc_get_by_task_struct (task);

	  if (!current)
	    {
	      /* this task struct is not known yet AND was not seen
	       * while running down the tasks lists, so this is presumably
	       * the swapper of an secondary SMP core.
	       */

	      current =
		lkd_proc_get_by_ptid (ptid_build(ptid_get_pid(inferior_ptid),
						 core + 1, 0));

	      gdb_assert(current);

	      current->task_struct = task;
	    }
	  else
	    {
	      /* update the thread's lwp in thread_list if it exists and wasn't
	       * scheduled so that tid makes sense for both the gdbserver and
	       * infrun.c */
	      PTID_OF (current).lwp = core + 1;
	    }

	  current->core = core;	/* was CORE_INVAL */
	  running_process[core] = current;

	}			// task
    }				// running_process[core]

    if (debug_linuxkthread_threads)
      fprintf_unfiltered (gdb_stdlog, "running ps[%d]: comm = %s ptid=%s\n",
			  core, running_process[core]->comm,
			  ptid_to_str(PTID_OF (running_process[core])));

  return running_process[core];
}

/* Return 1 if this is a current task (or 0)*/
int
lkd_proc_is_curr_task (linux_kthread_info_t * ps)
{
  return (ps && (ps == lkd_proc_get_running (ps->core)));
}

/*attempt getting the idle task for a core*/
static CORE_ADDR
get_rq_idle (int core)
{
  CORE_ADDR curr_addr = lkd_proc_get_runqueues (0);

  if (!curr_addr || !HAS_FIELD (rq, idle))
    return 0;

  if (!rq_idle[core])
    {
      curr_addr += (CORE_ADDR) per_cpu_offset[core] + F_OFFSET (rq, idle);

      rq_idle[core] = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
						    LKD_BYTE_ORDER);
    }

  return rq_idle[core];
};

static int
get_process_count (int core)
{
  CORE_ADDR curr_addr = (CORE_ADDR) per_cpu_offset[core];
  int proc_cnt;
  static int warned = 0;

  /* curr_addr can be null on UNI systems
   * */
  if (HAS_ADDR (process_counts))
    curr_addr += ADDR (process_counts);
  else if (HAS_ADDR (per_cpu__process_counts))
    curr_addr += ADDR (per_cpu__process_counts);
  else
    {
      /* return a fake, changing value
       * at least the list will be refreshed, but in a less optimal way.*/
      if (!warned)
	printf_filtered ("this kernel does not support `process_counts`\n");

      // if (!lkd_stepping)
      //warned++;

      return warned;
    }

  /* TODO remove LKD_BYTE_ORDER. Also shouldn't hard code 4 here */
  proc_cnt = read_memory_unsigned_integer (curr_addr, 4 /*uint32 */ ,
					   LKD_BYTE_ORDER);

    if (debug_linuxkthread_threads)
      fprintf_unfiltered (gdb_stdlog, "core(%d) curr_addr=0x%lx proc_cnt=%d\n",
			  core, curr_addr, proc_cnt);

  return proc_cnt;
};

static int
get_last_pid (void)
{
  int new_last_pid = 0;

  if (HAS_ADDR (init_pid_ns))
    {
      /* Since STLinux 2.3 (2.6.23) */
      new_last_pid = read_signed_field (ADDR (init_pid_ns),
					pid_namespace, last_pid);
    }
  else
    printf_filtered ("this kernel does not support `init_pid_ns`\n");

  return new_last_pid;
};

void
lkd_proc_init (void)
{
  int i = MAX_CORES;
  struct thread_info *th = NULL;
  struct cleanup *cleanup;

  memset (per_cpu_offset, 0, MAX_CORES * sizeof (uint32_t));

  /* ensure thread list from beneath target is up to date */
  cleanup = make_cleanup_restore_integer (&print_thread_events);
  print_thread_events = 0;
  update_thread_list ();
  do_cleanups (cleanup);

  /* count the h/w threads */
  max_cores = thread_count ();
  gdb_assert (max_cores);

  if (HAS_ADDR (__per_cpu_offset))
    {
      int core = max_cores;

      read_memory (ADDR (__per_cpu_offset),
		   (gdb_byte *) (per_cpu_offset),
		   max_cores * sizeof (uint32_t));

      while (--core)
	if (!per_cpu_offset[core])
	  {
	    warning ("Suspicious null per-cpu offsets,"
		     " or wrong number of detected cores:\n"
		     "ADDR (__per_cpu_offset) = %s\nmax_cores = %d",
		     phex (ADDR (__per_cpu_offset),4), max_cores);
	    break;
	  }
    }
  else
    {
        if (debug_linuxkthread_threads)
	  fprintf_unfiltered (gdb_stdlog, "Assuming non-SMP kernel.\n");
    }

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "SMP kernel. %d cores detected\n",
			max_cores);

  if (!lkd_proc_get_runqueues (1 /*reset */ ) && (max_cores > 1))
    printf_filtered ("\nCould not find the address of cpu runqueues:"
		     "\ncurrent context information maybe less precise\n.");
}

/* still useful with non-smp systems
 **/
CORE_ADDR current_task_struct[MAX_CORES];
CORE_ADDR current_thread_info[MAX_CORES];

int
lkd_proc_refresh_info (int cur_core)
{
  int i = max_cores;
  int new_last_pid;
  linux_kthread_info_t *ps;
  int do_invalidate = 0;

  memset (running_process, 0, max_cores * sizeof (linux_kthread_info_t *));
  memset (current_thread_info, 0, max_cores * (sizeof (CORE_ADDR)));
  memset (current_task_struct, 0, max_cores * (sizeof (CORE_ADDR)));
  memset (rq_curr, 0, max_cores * sizeof (CORE_ADDR));

  new_last_pid = get_last_pid ();
  if (new_last_pid != last_pid)
    {
      do_invalidate = 1;
      last_pid = new_last_pid;
    }

  /* check if a process exited */
  for (i = 0; i < max_cores; i++)
    {
      int new_pcount = get_process_count (i);

      /* if primary core has no processes kernel hasn't started */
      if (i == 0 && new_pcount == 0)
	{
	  warning ("Primary core has no processes - has kernel started?\n");
	  warning ("linux-kthread will deactivate\n");
	  return 0;
	}

      if (new_pcount != kthread_process_counts[i])
	{
	  kthread_process_counts[i] = new_pcount;
	  do_invalidate = 1;
	}
    }

  if (do_invalidate)
      lkd_proc_invalidate_list ();

  /* Update the process_list now, so that init_task is in there. */
  (void) lkd_proc_get_list ();

  /* Call update_thread_list() to prune GDB threads which are no longer linked
   * to a Linux task no longer linked to a linux task. */

  if (linux_kthread_active)
    update_thread_list();

  /* Set the running process
   *
   * we now have a thread_list looking like this:
   * [1] = { 42000, 0, 1  }
   * [2] = { 42000, 0, 2  }
   * [3] = { 42000, 1, -1 }
   *  ....
   * [N] = { 42000, PID_N, -1 }
   *
   * Now set the tid according to the running core,
   * */
  for (i = 0; i < max_cores; i++)
    lkd_proc_get_running (i);

  wait_process = lkd_proc_get_running (cur_core);

  if (!wait_process)
    return 0;

  gdb_assert(wait_process->gdb_thread);

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "wait_process comm=%s ptid= %s\n",
			wait_process->comm,
			ptid_to_str(PTID_OF (wait_process)));

  gdb_assert((linux_kthread_info_t *) wait_process->gdb_thread->priv == wait_process);


  /* Notify ptid changed. */
  ps = process_list;
  while (ps && ps->valid)
    {
      if (ptid_get_tid(ps->old_ptid) != ptid_get_tid(PTID_OF (ps)))
	{
	  observer_notify_thread_ptid_changed (ps->old_ptid, PTID_OF (ps));
	  ps->old_ptid.tid = ptid_get_tid(PTID_OF (ps));
	}
      ps = ps->next;
    }

  switch_to_thread(PTID_OF (wait_process));
  gdb_assert(lkd_proc_get_by_ptid(inferior_ptid) == wait_process);

  return 1;
}


static CORE_ADDR
_next_task (CORE_ADDR p)
{
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct, tasks,
						      list_head, next);

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
  CORE_ADDR cur_entry = read_unsigned_embedded_field (p, task_struct,
						      thread_group,
						      list_head, next);

  if (!cur_entry)
    {
      warning ("kernel thread group list contains NULL pointer\n");
      return 0;
    }

  return container_of (cur_entry, task_struct, thread_group);
}


static linux_kthread_info_t **
get_list_helper (linux_kthread_info_t ** ps)
{
  CORE_ADDR g, t, init_task_addr;
  int core;

  init_task_addr = ADDR (init_task);
  g = init_task_addr;
  core = 0;

  do
    {
      t = g;
      do
        {

#if 0
	  /* todo replace with a arch specific helper which checks versus CONFIG_PAGEOFFSET */
          if (!linux_awareness_ops->lo_is_kernel_address (t))
	    {
              warning ("parsing of task list stopped because of invalid address %s", phex (t, 4));
              break;
	    }
#endif
          get_task_info (t, ps, core /*zero-based */ );
          core = CORE_INVAL;

          if (ptid_get_tid (PTID_OF (*ps)) == 0)
            {
              /* this is init_task, let's insert the other cores swapper now */
              int i;
              for (i = 1; i < max_cores; i++)
                {
                  CORE_ADDR idle;
                  ps = &((*ps)->next);
                  idle = get_rq_idle (i);
                  get_task_info (idle, ps, i);
                }
            }

	    if (debug_linuxkthread_threads)
	      fprintf_unfiltered (gdb_stdlog, "Got task info for %s (%li)\n",
				  (*ps)->comm, ptid_get_lwp (PTID_OF (*ps)));

          ps = &((*ps)->next);

          /* mark end of chain and remove those threads
           * that disappeared from the thread_list
           * to avoid any_thread_of_process() to select a ghost.
           **/
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
 to the tasks in the kernel's task list. */
static linux_kthread_info_t *
lkd_proc_get_list (void)
{
  /* Return the cached copy if there's one,
   * or rebuild it.
   */

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "lkd_proc_get_list\n");

  if (process_list && process_list->valid)
    return process_list;

  gdb_assert (kthread_list_invalid);

  get_list_helper (&process_list);

  kthread_list_invalid = FALSE;

  return process_list;
}

/* Returns a valid 'linux_kthread_info_t' corresponding to
 * the passed ptid or NULL if not found. NULL means
 * the thread needs to be pruned.
 */
linux_kthread_info_t *lkd_proc_get_by_ptid (ptid_t ptid)
{
  struct thread_info *tp;
  long tid = ptid_get_tid(ptid);
  long lwp = ptid_get_lwp(ptid);
  linux_kthread_info_t *ps;

  /* check list is valid */
  gdb_assert(!kthread_list_invalid);

  /* We must ensure that we don't try to return
   *  threads created by another layer ... such as the remote layer
   */

  if (tid)
    {
	  /* non-swapper, tis is Linux pid */
	  tp = iterate_over_threads (find_thread_tid, (void *) &tid);
    }
  else
    {
	  /*swapper, LWP gives the core, tid = 0 is not unique */
	  tp = iterate_over_threads (find_thread_swapper, (void *) &lwp);
    }

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "ptid %s tp=0x%p\n",
			ptid_to_str(ptid), tp);

  ps = (linux_kthread_info_t *)tp->priv;

  /* Prune the gdb-thread if the process is not valid
   * meaning is was no longer found in the task list. */
  return ps;
}

/* invalidate the gdb thread is the linux ps has died.*/
static int
thread_clear_info (struct thread_info *tp, void *ignored)
{
  tp->priv = NULL;
  return 0;
}

/* debug function to print thread info. */
static int
thread_print_info (struct thread_info *tp, void *ignored)
{
  fprintf_unfiltered (gdb_stdlog, "thread_info = 0x%p ptid = %s\n",
		      tp, ptid_to_str(tp->ptid));
  return 0;
}

/* invalidate the cached task list. */
void
lkd_proc_invalidate_list (void)
{
  linux_kthread_info_t *ps = process_list;
  linux_kthread_info_t *cur;

  while (ps)
    {
      cur = ps;
      ps = ps->next;
      cur->valid = 0;
    }

  /* We invalidate the processes attached to the gdb_thread
  * setting tp->private to null tells if the thread can
  * be deleted or not. */
  iterate_over_threads (thread_clear_info, NULL);

  kthread_list_invalid = TRUE;
}

void
lkd_proc_free_list (void)
{
  linux_kthread_info_t *ps = process_list;
  linux_kthread_info_t *cur;
  while (ps)
    {
      cur = ps;
      ps = ps->next;
      // xfree does check for null pointers.
      xfree (cur->comm);
      xfree (cur);
    }
  process_list = NULL;
}

/* Target Layer Implementation  */


/* If OBJFILE contains the symbols corresponding to one of the
   supported user-level threads libraries, activate the thread stratum
   implemented by this module.  */

static int
linux_kthread_activate (struct objfile *objfile)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct linux_kthread_ops *ops
    = (struct linux_kthread_ops *) gdbarch_data (gdbarch, linux_kthread_data);

  /*debug print for existing hw threads from layer beneath */
  if (debug_linuxkthread_threads)
    {
      fprintf_unfiltered (gdb_stdlog, "linux_kthread_activate GDB HW threads\n");
      iterate_over_threads (thread_print_info, NULL);
    }

  /* Skip if the thread stratum has already been activated.  */
  if (linux_kthread_active)
    return 0;

  /* There's no point in enabling this module if no
     architecture-specific operations are provided.  */
  if (!ops->supply_kthread)
    return 0;

  /* Verify that this represents an appropriate linux target */

  /* Allocate private scratch buffer */
  scratch_buf_size = 4096;
  scratch_buf = (unsigned char *) xcalloc (scratch_buf_size, sizeof (char));

  kthread_list_invalid = TRUE;

  lkd_proc_init ();

  /* TODO: check kernel in memory matches vmlinux (Linux banner etc?) */

  /* TODO: Need arch specific callback (to check MMU / VM support etc) */

  lkd_proc_invalidate_list ();

  /* to get correct thread names from add_thread_with_info()
     target_ops must be pushed before enumerating kthreads */

  push_target (linux_kthread_ops);
  linux_kthread_active = 1;

  /* scan the linux threads */
  if (!lkd_proc_refresh_info (stop_core))
    {
      /* don't activate linux-kthread as no threads were found */
      lkd_proc_invalidate_list ();

      prune_threads();
      return 0;
    }

  return 1;
}

/* Cleanup due to deactivation.  */
static void
linux_kthread_close (struct target_ops *self)
{
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_close\n");

  linux_kthread_active = 0;

  wait_process = NULL;

  lkd_proc_free_list ();

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

  lkd_proc_free_list ();
  
  /* fallback to any thread that makes sense for the beneath target */
  //lkd_reset_thread_list ();

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

  linux_kthread_info_t *ps;

  if (!(ps = lkd_proc_get_by_ptid (inferior_ptid)) || lkd_proc_is_curr_task (ps))
      return beneath->to_fetch_registers (beneath, regcache, regnum);

  /* Call the platform specific code */
  kthread_ops->supply_kthread(regcache, regnum, ps->task_struct);
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
  ptid_t stop_ptid;
  CORE_ADDR pc;
  CORE_ADDR task;
  int i;
  struct regcache *regcache;

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_wait\n");

  /* Pass the request to the layer beneath.  */
  stop_ptid = beneath->to_wait (beneath, ptid, status, options);

  if (max_cores > 1)
    stop_core = ptid_get_tid (stop_ptid) - 1;
  else
    stop_core = 0;

  /*reset the inferior_ptid to the stopped ptid */
  inferior_ptid = stop_ptid;

  /* rescan for new task, but avoid storming the debug connection */
  lkd_proc_refresh_info (stop_core);

   /* The above calls might will end up accessing the registers
      of the target because of inhibit_thread_awareness(). However,
      this will populate a register cache associated with
      inferior_ptid, which we haven't updated yet. Force a flush
      of these cached values so that they end up associated to
      the right context. */
   registers_changed ();

   /* This is normally done by infrun.c:handle_inferior_event (),
      but we need it set to access the frames for some operations
      below (eg. in check_exec_actions (), where we don't know
      what the user will ask in his commands. */
   set_executing (minus_one_ptid, 0);

   regcache = get_thread_regcache (inferior_ptid);

   pc = regcache_read_pc (regcache);

   if (wait_process)
     {
       inferior_ptid = PTID_OF (wait_process);
       stop_ptid = inferior_ptid;
     }

  return stop_ptid;
}

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

static int
linux_kthread_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  struct target_ops *beneath = find_target_beneath (ops);
  linux_kthread_info_t *ps;

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_thread_alive ptid=%s",
			ptid_to_str(ptid));

  ps = lkd_proc_get_by_ptid (ptid);

  if (!ps)
    {
      if (debug_linuxkthread_threads)
	fprintf_unfiltered (gdb_stdlog, "Prune thread ps(%p)\n",ps);

      return 0;
    }

  if (debug_linuxkthread_threads)
    fprintf_unfiltered (gdb_stdlog, "Alive thread ps(%p)\n",ps);

  return 1;
}

static void
linux_kthread_update_thread_list (struct target_ops *ops)
{
  struct target_ops *beneath = find_target_beneath (ops);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "linux_kthread_update_thread_list\n");

  /* Build linux threads on top */
  lkd_proc_get_list ();

  prune_threads ();
}

/* Return a string describing the state of the thread specified by
   INFO.  */

static char *
linux_kthread_extra_thread_info (struct target_ops *self,
				 struct thread_info *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch ());
  linux_kthread_info_t *ps = (linux_kthread_info_t *) info->priv;

  if (ps /* && check_ps_magic */)
    {
      char *msg = get_print_cell ();
      size_t len = 0;

      len = snprintf (msg, PRINT_CELL_SIZE, "pid: %li tgid: %i",
		      ptid_get_tid(PTID_OF (ps)), ps->tgid);

      /* yao: don't do anything special this could come from xml threads.dtd */

      if (lkd_proc_is_curr_task (ps))
	snprintf (msg + len, PRINT_CELL_SIZE - len, " <C%u>", ps->core);

      return msg;
    }

  return "LinuxThread";
}

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

  /* we use thread_info priv field for storing linux_kthread_info_t */
  ps = (linux_kthread_info_t *) tp->priv;

  gdb_assert (ps->comm);

  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "kthread_pid_to_str ptid %s str=%s\n",
			ptid_to_str(ptid), ps->comm);

  return ps->comm;
}

static const char *
linux_kthread_thread_name (struct target_ops *ops, struct thread_info *thread)
{
  /* All the thread name information has generally been
   * returned already through the pid_to_str.
   *
   * We could refactor this around and 'correct' the naming
   * but then you wouldn't get niceties such as
   *    [Switching to thread 52 (getty)]
   */

  return NULL;
}

static int
linux_kthread_can_async_p (struct target_ops *ops)
{
  return 0;
}

static int
linux_kthread_is_async_p (struct target_ops *ops)
{
  return 0;
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
  linux_kthread_ops = t;

  /* Prevent Async operations
   * LKD doesn't yet support ASync,
   * Particularly on connect/resume, which can break things
   * when connecting to an async target such as QEmu
   */

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

void
_initialize_linux_kthread (void)
{
  if (debug_linuxkthread_targetops)
    fprintf_unfiltered (gdb_stdlog, "_initialize_linux_kthread\n");

  complete_target_initialization (linux_kthread_target ());

  linux_kthread_data = gdbarch_data_register_pre_init (linux_kthread_init);

  observer_attach_inferior_created (linux_kthread_inferior_created);

  target_thread_ptid = null_ptid;
  observer_attach_target_thread_changed (linux_awareness_target_thread_changed);

}
