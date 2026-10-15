/* confine: report what a running process can actually do.
 *
 * Every line carries the word "observed" or "measured" in column one.
 * Observed means it was read from a named file under /proc. Measured
 * means an operation was attempted and this is what the kernel did. The
 * two are never mixed, because a tool that presents a guess as a
 * measurement is the reassurance that stops someone checking.
 *
 * Usage: confine [PID]
 */
/* readlink and access are POSIX, not ISO C, and -std=c11 hides them.
 * The macro rather than -std=gnu11: the rest of this collection builds
 * with c11 and a strict mode that quietly turns into a loose one is a
 * difference nobody notices until something else breaks. */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caps.h"

#define LINEMAX 4096

/* The status file is written by the kernel, but a process chooses its own
 * name, and that name reaches us through /proc/PID/status as "Name:". So
 * the parser is written for hostile input even though most of the file is
 * not. */
static int status_field(const char *pid, const char *key, char *out, size_t n)
{
	char path[64], line[LINEMAX];
	FILE *f;
	size_t klen = strlen(key);
	int found = 0;

	if (snprintf(path, sizeof path, "/proc/%s/status", pid) >= (int)sizeof path)
		return -1;
	if (!(f = fopen(path, "r")))
		return -1;
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, key, klen) || line[klen] != ':')
			continue;
		{
			const char *p = line + klen + 1;
			size_t i = 0;

			while (*p == ' ' || *p == '\t')
				p++;
			while (p[i] && p[i] != '\n' && i + 1 < n) {
				out[i] = p[i];
				i++;
			}
			out[i] = 0;
			found = 1;
		}
		break;
	}
	fclose(f);
	return found ? 0 : -1;
}

/* A capability set is printed as 16 hex digits in /proc. Parsing it as a
 * 64-bit value and naming the bits is the whole of this. A bit with no
 * name is printed as its number rather than dropped: a kernel newer than
 * the header we built against is exactly when that matters. */
static void print_caps(const char *label, const char *hex)
{
	uint64_t v = strtoull(hex, NULL, 16);
	int i, first = 1;

	printf("observed  %-14s ", label);
	if (v == 0) {
		puts("(none)");
		return;
	}
	for (i = 0; i < 64; i++) {
		if (!(v & ((uint64_t)1 << i)))
			continue;
		if (!first)
			putchar(' ');
		first = 0;
		if (i < CAP_COUNT && CAP_NAME[i])
			fputs(CAP_NAME[i], stdout);
		else
			printf("cap_%d", i);
	}
	putchar('\n');
}


/* The eight namespace kinds, plus the two "_for_children" links, which
 * are not namespaces a process is in but the ones its children will get.
 * Reported separately because confusing them is easy and the difference
 * matters exactly when someone has just called unshare. */
static const char *const NS_KIND[] = {
	"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts",
	"pid_for_children", "time_for_children",
};

static int ns_inode(const char *pid, const char *kind, char *out, size_t n)
{
	char path[96], link[128];
	ssize_t k;
	char *lb, *rb;

	if (snprintf(path, sizeof path, "/proc/%s/ns/%s", pid, kind)
	    >= (int)sizeof path)
		return -1;
	if ((k = readlink(path, link, sizeof link - 1)) < 0)
		return -1;
	link[k] = 0;
	/* "mnt:[4026531840]" and nothing else is accepted: a link that does
	 * not have this shape is a kernel we do not understand, and
	 * guessing at it would be worse than saying so. */
	if (!(lb = strchr(link, '[')) || !(rb = strchr(lb, ']')))
		return -1;
	*rb = 0;
	if (snprintf(out, n, "%s", lb + 1) >= (int)n)
		return -1;
	return 0;
}

/* Whether the target shares a namespace with PID 1 is the fact a reader
 * wants, and on an ordinary unprivileged run /proc/1/ns is not readable,
 * so it cannot be had. Saying "not shared with init" when the truth is
 * "could not look" is the failure this whole program is shaped against,
 * so the comparison is against this process instead, and the output says
 * which comparison it made. */
static void print_namespaces(const char *pid)
{
	char mine[64], theirs[64];
	size_t i;
	int init_readable = access("/proc/1/ns/mnt", R_OK) == 0;
	/* Comparing the target against ourselves is meaningless when the
	 * target IS ourselves: it reports "same as this process" for every
	 * namespace including one that unshare just created, which reads
	 * like a fact and is a tautology. The first version did exactly
	 * that and looked right. */
	int is_self = !strcmp(pid, "self") || atoi(pid) == (int)getpid();

	for (i = 0; i < sizeof NS_KIND / sizeof *NS_KIND; i++) {
		const char *k = NS_KIND[i];
		char label[32];

		if (ns_inode(pid, k, theirs, sizeof theirs) != 0)
			continue;
		snprintf(label, sizeof label, "ns_%s", k);
		printf("observed  %-14s %-12s", label, theirs);
		if (init_readable && ns_inode("1", k, mine, sizeof mine) == 0)
			printf(" %s init\n",
			       strcmp(mine, theirs) ? "not shared with" : "shared with");
		else if (!is_self && ns_inode("self", k, mine, sizeof mine) == 0)
			printf(" %s this process\n",
			       strcmp(mine, theirs) ? "differs from" : "same as");
		else
			putchar('\n');
	}
	if (!init_readable)
		printf("observed  note           /proc/1/ns is not readable here, so "
		       "no namespace\n                         can be compared against "
		       "init%s\n", is_self ? ". Inspecting this process, so\n"
		       "                         there is nothing else to compare "
		       "against either" : ". They are compared against\n"
		       "                         this process instead");
}

static const char *seccomp_mode(const char *s)
{
	switch (atoi(s)) {
	case 0:  return "disabled";
	case 1:  return "strict";
	case 2:  return "filter";
	default: return "unknown";
	}
}

int main(int argc, char **argv)
{
	const char *pid = argc > 1 ? argv[1] : "self";
	char buf[LINEMAX], buf2[LINEMAX];
	size_t i;
	static const struct { const char *key, *label; } CAPSETS[] = {
		{ "CapInh", "cap_inherit" }, { "CapPrm", "cap_permitted" },
		{ "CapEff", "cap_effective" }, { "CapBnd", "cap_bounding" },
		{ "CapAmb", "cap_ambient" },
	};

	if (argc > 2) {
		fputs("usage: confine [PID]\n", stderr);
		return 2;
	}
	for (i = 0; pid[i]; i++)
		if (!isdigit((unsigned char)pid[i]) && strcmp(pid, "self")) {
			fprintf(stderr, "confine: %s is not a pid\n", pid);
			return 2;
		}
	if (status_field(pid, "Name", buf, sizeof buf) != 0) {
		fprintf(stderr, "confine: cannot read /proc/%s/status: %s\n",
		        pid, strerror(errno));
		return 1;
	}
	printf("observed  %-14s %s\n", "name", buf);
	if (status_field(pid, "Uid", buf, sizeof buf) == 0)
		printf("observed  %-14s %s\n", "uid", buf);

	for (i = 0; i < sizeof CAPSETS / sizeof *CAPSETS; i++)
		if (status_field(pid, CAPSETS[i].key, buf, sizeof buf) == 0)
			print_caps(CAPSETS[i].label, buf);

	print_namespaces(pid);

	if (status_field(pid, "NoNewPrivs", buf, sizeof buf) == 0)
		printf("observed  %-14s %s\n", "no_new_privs", buf);

	/* Two fields, and the second is the one people misread. A filter
	 * count says a filter exists. It says nothing whatever about which
	 * syscalls it permits, and there is no way to ask the kernel that
	 * from outside the process. */
	if (status_field(pid, "Seccomp", buf, sizeof buf) == 0) {
		if (status_field(pid, "Seccomp_filters", buf2, sizeof buf2) != 0)
			strcpy(buf2, "?");
		printf("observed  %-14s %s (%s), %s filter(s) installed\n",
		       "seccomp", buf, seccomp_mode(buf), buf2);
	}
	return 0;
}
