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
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
