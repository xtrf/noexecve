/*
 * Copyright (C) 2015 Red Hat, Inc.
 * Written by Florian Weimer <fweimer@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <stddef.h>

#include <asm/unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

// If execveat is not available, pretend that it is execve, so that we
// do not have to tweak the offsets in the BPF program.
#ifndef __NR_execveat
#define __NR_execveat __NR_execve
#endif

// BPF system call filter.
const struct sock_filter execve_filter[] = {
  // Load system call number.
  BPF_STMT(BPF_LD | BPF_ABS, offsetof(struct seccomp_data, nr)),
  // Skip next two instructions if execve.
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 2, 0),
  // Skip next instruction if execveat.
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0),
  // Permit this system call.
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  // Reject this system call (reached for execve and execveat).
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO),
};

const struct sock_fprog execve_filter_program = {
  .len = sizeof(execve_filter) / (sizeof(execve_filter[0])),
  .filter = (struct sock_filter *)execve_filter
};

// Check if the executable has a user.noexecve attribute.
static bool
noexecve_enabled(void)
{
  char value[16];
  int ret = getxattr("/proc/self/exe", "user.noexecve",
                     value, sizeof(value));
  return ret >= 0 || errno == ERANGE;
}

// Install the seccomp filter.
static void
disable_execve(void)
{
  // This is required to make seccomp filters an unprivileged
  // operation.  It does not matter because we block execve entirely.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    abort();
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
            &execve_filter_program) != 0) {
    abort();
  }
}

static void __attribute__((constructor))
constructor(void)
{
  if (noexecve_enabled()) {
    disable_execve();
  }
}
