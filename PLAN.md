# confine: plan

## Contract

`confine PID` reports what a running process can actually do: its
namespaces, its capability sets, whether `no_new_privs` is set, whether a
seccomp filter is installed and how many, and which of a set of sensitive
paths it can reach.

Every line it prints is labelled with where the fact came from. There are
three kinds and they are never mixed:

    observed   read from a named file under /proc/PID
    declared   taken from whatever launched it, such as a flatpak
               manifest or a systemd unit
    measured   an operation was attempted and this is what the kernel did

The distinction is the whole point. Existing tools report the declaration
and stop. `--filesystem=home` in a flatpak manifest is a declaration;
whether that app can read `~/.ssh/id_ed25519` is a measurement, and the
two are not the same question.

## Hard invariant

Nothing labelled `measured` may be printed unless the operation was
attempted during this run, and nothing labelled `observed` may be printed
unless it was read from a file that exists. A tool that guesses and
labels the guess as a measurement is worse than no tool, because it is
the reassurance that stops someone checking.

Second: no input may make confine crash, hang or read out of bounds.
Every input here is a file under /proc written by the kernel, except the
ones written by a process that chose its own `/proc/PID/cmdline`, and
those are attacker-controlled.

## Oracle, ranked by how little we control it

1. A process whose confinement we constructed. `unshare` and
   `setpriv` build a process with exactly known namespaces, capability
   sets and `no_new_privs`, and confine must report exactly that and
   nothing else. This is the strongest oracle available because the
   ground truth is not an opinion.
2. The kernel's answer to an attempted operation. For the `measured`
   lines there is no second opinion to want: either the open succeeded or
   it returned EACCES.
3. `lsns` from util-linux, for namespace identity. Its inode numbers
   must match ours for every namespace of every process it lists.
4. `setpriv --dump`, for the capability sets of the current process.
5. `/usr/include/linux/capability.h`, for the capability name table.
   The table is generated from the header at build time, never typed in,
   so a kernel that adds CAP_ANYTHING does not silently become "cap 41".
6. `systemd-analyze security`, for units. Ranked last because it
   scores rather than reports, and its scoring is an opinion.

## Non-goals

- Changing anything. confine reports. `jail` and `seccompc` in this
  collection apply confinement; mixing the two in one tool makes a
  reporting bug into a security bug.
- Entering another process's namespaces. That needs CAP_SYS_ADMIN, and a
  tool that asks for privilege to tell you about privilege is the wrong
  shape. Measurement happens in a child we launched, never by joining
  something we did not.
- A sandbox escape detector. It reports reach; deciding whether a given
  reach is acceptable is the operator's.
- Windows, macOS, or any kernel without /proc.
- A GUI. Flatseal already edits flatpak permissions.

## Commit sequence

- [x] 01 the capability name table, generated from the kernel header
      why: everything else prints names, and a table typed by hand is a
           table that rots. Generating it first means the rot cannot
           start.
- [x] 02 `confine PID`: capability sets and no_new_privs, observed
      why: the smallest complete fact, four bitmasks and a flag, with
           setpriv --dump as an oracle for the current process.
- [x] 03 namespaces: which of the eight, and whether each is shared with
      PID 1
      why: lsns gives inode numbers to compare against, and "shared with
           init" is the fact a reader actually wants.
      files: confine.c t/run.sh
      proves: all eight kinds plus the two _for_children links, with every
              inode checked against lsns. unshare --user --uts moves
              exactly one namespace and confine reports that one as moved
              and the rest as unchanged.
      found: "shared with init" is the fact a reader wants and it cannot
             be had here: /proc/1/ns is not readable unprivileged, so the
             comparison is against this process and the output says which
             comparison it made. Claiming the first while measuring the
             second would be the exact failure this project is shaped
             against.
             And comparing the target against ourselves is a tautology
             when the target IS ourselves. The first version printed
             "same as this process" for every namespace including one
             unshare had just created, which reads like a fact. Self
             inspection prints no comparison at all now.
      note: the test for this first found its target with pgrep, which
            picked up a stale sleep from an unrelated job and reported
            the wrong namespace as proof that it worked. The target
            writes its own pid to a file.
- [ ] 04 seccomp mode and filter count, and what that does NOT tell you
      why: /proc says a filter exists and says nothing about what it
           permits, and the README has to say so before anyone trusts the
           line.
- [ ] 05 a constructed-process test rig: unshare and setpriv build a
      target with known confinement, confine reports it, the suite
      compares
      why: oracle 1, and the one that makes every later item cheap to
           check.
- [ ] 06 `confine -- CMD`: run a command and measure its reach
      why: the first `measured` output, and the first time the tool says
           something no existing tool says.
- [ ] 07 filesystem reach: a named set of sensitive paths, each probed
      for read and write
      why: the question people actually have, and the reason the
           declared/measured split exists.
- [ ] 08 mount namespace reporting from /proc/PID/mountinfo
      why: reach inside a mount namespace is decided by what is mounted,
           so the reach report is incomplete without it.
- [ ] 09 flatpak cross-check: declared permissions against observed state
      why: this is where declared and observed diverge most often, and
           twelve apps on this machine to test it against.
- [ ] 10 systemd unit cross-check against systemd-analyze security
      why: the last oracle, and the one that needs the others working
           first.
- [ ] 11 a truncation and corruption sweep over every /proc file parsed
      why: /proc/PID/cmdline is written by the process being inspected.
- [ ] 12 README with what does not work, in detail
      why: last, so the numbers in it are the numbers the suite prints.
