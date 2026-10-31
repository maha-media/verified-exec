/* release tester-only SDK contract for the fixed owned-exec operations. No child or user-state access.
 * clang -Wall -Werror exec_abi.c -o <owned scratch>/exec_abi && <owned scratch>/exec_abi */
#include <stdio.h>
#include <spawn.h>
#include <mach/mach.h>
_Static_assert(POSIX_SPAWN_START_SUSPENDED == 0x0080, "suspended flag");
_Static_assert(POSIX_SPAWN_SETSID == 0x0400, "setsid flag");
_Static_assert(POSIX_SPAWN_CLOEXEC_DEFAULT == 0x4000, "cloexec flag");
_Static_assert(TASK_AUDIT_TOKEN == 15, "self audit selector");
_Static_assert(TASK_AUDIT_TOKEN_COUNT == 8, "self audit count");
_Static_assert(sizeof(audit_token_t) == 32, "self audit storage");
int main(void) { puts("Darwin owned exec ABI assertions PASS"); return 0; }
