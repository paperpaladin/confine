/* A process with a known number of seccomp filters, for confine to read.
 *
 * Everything the suite checked about the seccomp line until now was
 * checked against a process with no filter at all: mode 0, count 0.
 * A reader that printed "disabled, 0" unconditionally would have
 * passed. This builds the other case.
 *
 * The filters permit everything. The point is their existence and
 * their number, not their effect, and a restrictive one would stop
 * this process doing the one thing it has to do next, which is wait.
 *
 * Two filters rather than one matters: a reader that reports the
 * presence of filtering as "1" is right for the common case and wrong
 * here, and the kernel counts them for exactly this reason.
 *
 * Needs no privileges: PR_SET_NO_NEW_PRIVS makes an unprivileged
 * seccomp(2) legal.
 */
#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int want = argc > 1 ? atoi(argv[1]) : 1;
	struct sock_filter prog[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog fprog = { 1, prog };

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("PR_SET_NO_NEW_PRIVS");
		return 2;
	}
	for (int i = 0; i < want; i++) {
		if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0) {
			perror("seccomp");
			return 2;
		}
	}

	/* The parent cannot read /proc until the filters are in, and it
	 * has no other way to know. */
	printf("ready %d\n", (int)getpid());
	fflush(stdout);
	for (;;)
		pause();
}
