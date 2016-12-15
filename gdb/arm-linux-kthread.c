/* Linux kernel thread ARM target support.

   Copyright (C) 2011-2016 Free Software Foundation, Inc.

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
#include "regcache.h"
#include "inferior.h"
#include "arch/arm.h"
#include "arm-tdep.h"
#include "linux-kthread.h"
#include "arm-linux-kthread.h"

/* Support for Linux kernel threads */

/* From Linux arm/include/asm/thread_info.h */
static struct cpu_context_save
{
  uint32_t r4;
  uint32_t r5;
  uint32_t r6;
  uint32_t r7;
  uint32_t r8;
  uint32_t r9;
  uint32_t sl;
  uint32_t fp;
  uint32_t sp;
  uint32_t pc;
} cpu_cxt;

/* This function gets the register values that the schedule() routine
 * has stored away on the stack to be able to restart a sleeping task.
 *
 **/

static void
arm_linuxkthread_fetch_registers (struct regcache *regcache,
			 int regnum, CORE_ADDR task_struct)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  CORE_ADDR sp = 0;
  gdb_byte buf[8];
  int i;
  uint32_t cpsr;
  uint32_t thread_info_addr;

  DECLARE_FIELD (thread_info, cpu_context);
  DECLARE_FIELD (task_struct, stack);

  gdb_assert (regnum >= -1);

  /*get thread_info address */
  thread_info_addr = read_unsigned_field (task_struct, task_struct, stack,
					  byte_order);

  /*get cpu_context as saved by scheduled */
  read_memory ((CORE_ADDR) thread_info_addr +
	       F_OFFSET (thread_info, cpu_context),
	       (gdb_byte *) & cpu_cxt, sizeof (struct cpu_context_save));

  regcache_raw_supply (regcache, ARM_PC_REGNUM, &cpu_cxt.pc);
  regcache_raw_supply (regcache, ARM_SP_REGNUM, &cpu_cxt.sp);
  regcache_raw_supply (regcache, ARM_FP_REGNUM, &cpu_cxt.fp);

  /*general purpose registers */
  regcache_raw_supply (regcache, 10, &cpu_cxt.sl);
  regcache_raw_supply (regcache, 9, &cpu_cxt.r9);
  regcache_raw_supply (regcache, 8, &cpu_cxt.r8);
  regcache_raw_supply (regcache, 7, &cpu_cxt.r7);
  regcache_raw_supply (regcache, 6, &cpu_cxt.r6);
  regcache_raw_supply (regcache, 5, &cpu_cxt.r5);
  regcache_raw_supply (regcache, 4, &cpu_cxt.r4);

  /* Fake a value for cpsr:T bit.  */
#define IS_THUMB_ADDR(addr)	((addr) & 1)
  cpsr = IS_THUMB_ADDR(cpu_cxt.pc) ? arm_psr_thumb_bit (target_gdbarch ()) : 0;
  regcache_raw_supply (regcache, ARM_PS_REGNUM, &cpsr);

  for (i = 0; i < gdbarch_num_regs (target_gdbarch ()); i++)
    if (REG_VALID != regcache_register_status (regcache, i))
      /* Mark other registers as unavailable.  */
      regcache_invalidate (regcache, i);
}

static void
arm_linuxkthread_store_registers (const struct regcache *regcache,
			   int regnum, CORE_ADDR addr)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  /* TODO */
  gdb_assert (regnum >= -1);
  gdb_assert (0);

}

/* get_unmapped_area() in linux/mm/mmap.c */
DECLARE_ADDR (get_unmapped_area);

#define DEFAULT_PAGE_OFFSET 0xC0000000

void arm_linuxkthread_get_page_offset(CORE_ADDR *page_offset)
{
  const char *result = NULL;

  /* we can try executing a python command if it exists in the kernel source
     result = execute_command_to_string ("lx-pageoffset", 0); */

  /* find CONFIG_PAGE_OFFSET macro definition at get_unmapped_area symbol
     in linux/mm/mmap.c */

  result = kthread_find_macro_at_symbol(&get_unmapped_area, "CONFIG_PAGE_OFFSET");
  if (result)
    {
      *page_offset = strtol(result, (char **) NULL, 16);
    }
  else
    {
      /* kernel is compiled without macro infor so make an educated guess */
      warning("Assuming PAGE_OFFSET is 0x%x\n", DEFAULT_PAGE_OFFSET);
      *page_offset = DEFAULT_PAGE_OFFSET;
    }

  return;
}

static int arm_linuxkthread_is_kernel_address (const CORE_ADDR addr)
{
  static CORE_ADDR linux_page_offset;

  if (!linux_page_offset)
    arm_linuxkthread_get_page_offset(&linux_page_offset);

  return (addr >= linux_page_offset) ? true : false;
}

/* The linux_kthread_arch_ops for most ARM targets.  */

static struct linux_kthread_arch_ops arm_linuxkthread_ops =
{
  arm_linuxkthread_fetch_registers,
  arm_linuxkthread_store_registers,
  arm_linuxkthread_is_kernel_address,
};

/* Register arm_linuxkthread_ops in GDBARCH.  */

void
register_arm_linux_kthread_ops (struct gdbarch *gdbarch)
{
  set_gdbarch_linux_kthread_ops (gdbarch, &arm_linuxkthread_ops);
}
