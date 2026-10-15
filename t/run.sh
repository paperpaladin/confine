#!/bin/sh
# Oracle: a process whose confinement we constructed, plus util-linux.
#
# The strongest check here is not "does confine agree with setpriv", it is
# "does confine report the confinement we just built". setpriv and unshare
# make a process with known capability sets and known namespaces, and
# confine has to say exactly that.
set -u
cd "$(dirname "$0")/.."

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
nok()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }
skip() { printf 'SKIP  %s\n' "$1"; }

eq() { # label want got
	if [ "$2" = "$3" ]; then ok "$1"; else nok "$1" "want [$2] got [$3]"; fi
}

[ -x ./confine ] || make -s confine

# ---------------------------------------------------------------- basics
out=$(./confine 2>&1)
case $out in
*"observed  name"*) ok "reports its own name" ;;
*) nok "reports its own name" "$out" ;;
esac

eq "a non-numeric pid is refused, exit 2" "2" \
   "$(./confine notapid >/dev/null 2>&1; echo $?)"
eq "two arguments are refused, exit 2" "2" \
   "$(./confine 1 2 >/dev/null 2>&1; echo $?)"
eq "a pid that does not exist, exit 1" "1" \
   "$(./confine 999999 >/dev/null 2>&1; echo $?)"

# ----------------------------------------------- the generated name table
# The table must come from the header. If someone replaces it with a typed
# list this catches the drift, because the count is derived twice.
hdr=$(grep -cE '^#define[[:blank:]]+CAP_[A-Z0-9_]+[[:blank:]]+[0-9]+[[:blank:]]*$' \
      /usr/include/linux/capability.h)
gen=$(grep -c '^	\[' caps.h)
eq "every capability in the kernel header is in the table" "$hdr" "$gen"

# The highest bit the header defines must be named, not printed as a
# number. This is the assertion that fails when a new kernel ships.
last=$(grep -E '^#define[[:blank:]]+CAP_[A-Z0-9_]+[[:blank:]]+[0-9]+[[:blank:]]*$' \
       /usr/include/linux/capability.h |
       sed -E 's/.*[[:blank:]]([0-9]+)[[:blank:]]*$/\1/' | sort -n | tail -1)
if grep -q "^	\[$last\] = " caps.h; then
	ok "the highest capability the header defines is named ($last)"
else
	nok "the highest capability the header defines is named ($last)"
fi

# ------------------------------------------------- oracle: setpriv --dump
# setpriv reports the same sets for the current process. Comparing names
# rather than hex is the point: it checks the decoding, not the read.
if command -v setpriv >/dev/null 2>&1; then
	sp=$(setpriv --dump 2>/dev/null |
	     sed -n 's/^Inheritable capabilities: //p' | tr 'A-Z' 'a-z')
	cf=$(./confine | sed -n 's/^observed  cap_inherit  *//p')
	case "$sp" in
	"[none]"|"") sp="(none)" ;;
	esac
	# setpriv separates with ", " and we separate with " ".
	sp=$(printf '%s' "$sp" | tr -d ',')
	eq "inheritable set agrees with setpriv --dump" "$sp" "$cf"
else
	skip "setpriv is not installed, so its half of the capability oracle did not run"
fi

# ------------------------------------- oracle: a process we constructed
# Two namespaces, built to differ in exactly one way, and confine has to
# tell them apart.
#
# "unshare --user" alone is the wrong expectation and was the first thing
# written here: capabilities are recomputed on execve, so by the time any
# program runs inside it the effective set is empty, and the kernel
# agrees (CapEff 0000000000000000). It is --map-root-user that makes the
# process root in the new namespace and gives it the full set. Asserting
# the first would have been asserting a bug that is not there.
if unshare --user true 2>/dev/null; then
	plain=$(unshare --user ./confine | sed -n 's/^observed  cap_effective  *//p')
	eq "plain --user: caps are dropped on exec, and confine says so" \
	   "(none)" "$plain"

	rooted=$(unshare --user --map-root-user ./confine |
	         sed -n 's/^observed  cap_effective  *//p')
	case $rooted in
	*chown*sys_admin*checkpoint_restore*)
		ok "--map-root-user: the full set, named from first bit to last" ;;
	*)
		nok "--map-root-user: the full set, named from first bit to last" \
		    "got [$rooted]" ;;
	esac

	# The bits the kernel set, counted, against the names we printed.
	hex=$(unshare --user --map-root-user grep ^CapEff /proc/self/status |
	      sed 's/.*\t//')
	want=$(python3 -c "print(bin(int('$hex',16)).count('1'))")
	got=$(printf '%s' "$rooted" | wc -w)
	eq "every bit the kernel set is named exactly once" "$want" "$got"
else
	skip "unshare --user is not permitted here, so the constructed-process oracle did not run"
fi

# no_new_privs is a bit we can set from outside the program under test,
# which makes it the cheapest end-to-end check there is.
if command -v setpriv >/dev/null 2>&1; then
	got=$(setpriv --no-new-privs ./confine | sed -n 's/^observed  no_new_privs  *//p')
	eq "setpriv --no-new-privs is observed as 1" "1" "$got"
	got=$(./confine | sed -n 's/^observed  no_new_privs  *//p')
	eq "and without it, as 0" "0" "$got"
fi

# ------------------------------------------------------- seccomp reading
# The mode names have to be right, and the line has to say what it does
# NOT tell you. A filter count is not a policy.
case $(./confine | sed -n 's/^observed  seccomp  *//p') in
*"filter(s) installed"*) ok "the seccomp line names the mode and the filter count" ;;
*) nok "the seccomp line names the mode and the filter count" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
