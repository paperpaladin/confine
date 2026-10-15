# confine

Reports what a running process can actually do: its capability sets, its
namespaces, whether `no_new_privs` is set, whether a seccomp filter is
installed.

```
$ ./confine
observed  name           confine
observed  uid            1000	1000	1000	1000
observed  cap_inherit    (none)
observed  cap_permitted  (none)
observed  cap_effective  (none)
observed  cap_bounding   chown dac_override dac_read_search fowner ...
observed  cap_ambient    (none)
observed  no_new_privs   0
observed  seccomp        0 (disabled), 0 filter(s) installed
```

`make test`: **13 passed, 0 failed.**

## Why the first word of every line

There are three kinds of fact about a sandbox and they get confused
constantly:

    observed   read from a named file under /proc/PID
    declared   taken from whatever launched it, a flatpak manifest or a
               systemd unit
    measured   an operation was attempted and this is what the kernel did

`--filesystem=home` in a flatpak manifest is a declaration. Whether that
application can read `~/.ssh/id_ed25519` is a measurement. Existing tools
report the first and stop, and the gap between the two is where people
get surprised. Labelling every line with its own provenance is cheap and
makes the gap impossible to miss.

Only `observed` exists today. `measured` arrives with item 06, and
nothing will print that word until an operation is actually attempted.

## The oracle

A process whose confinement was constructed on purpose. `unshare` and
`setpriv` build a target with exactly known capability sets and
namespaces, and `confine` has to report exactly that. The ground truth is
not an opinion, which is what makes it the strongest check here.

Underneath that: `setpriv --dump` for the capability sets of the current
process, and `/usr/include/linux/capability.h` for the names.

The name table is generated from that header by `mkcaps.sh` at build
time, never typed in. A kernel that adds `CAP_ANYTHING` is picked up by
rebuilding, and the suite asserts twice over that the count in the header
and the count in the table agree, and that the highest capability the
header defines is printed by name rather than as `cap_41`.

## One assertion that was wrong before it was right

The constructed-process check first asserted that a process inside
`unshare --user` holds a full capability set. It does not. Capabilities
are recomputed on `execve`, so by the time any program runs in there the
effective set is empty and the kernel says so:
`CapEff: 0000000000000000`. It is `--map-root-user` that makes the
process root in the new namespace and gives it the full set.

Asserting the first version would have been asserting a bug that is not
there. The suite now checks both: plain `--user` must report `(none)`,
and `--map-root-user` must report every bit, counted against the hex the
kernel put in `/proc/self/status`.

## What does not work

- Everything from item 03 onwards in `PLAN.md`. Namespaces, seccomp
  policy, filesystem reach, mount namespaces, flatpak and systemd
  cross-checks are all unwritten.
- A seccomp filter count tells you a filter exists. It tells you nothing
  about which syscalls it permits, and there is no way to ask the kernel
  that from outside the process. The output says so on the line itself,
  because the number looks more informative than it is.
- `uid` is printed as the kernel writes it, four tab-separated values for
  real, effective, saved and filesystem uid. Splitting them is item 02's
  leftover.
- Nothing enters another process's namespaces. That needs
  `CAP_SYS_ADMIN`, and a tool that asks for privilege in order to report
  on privilege is the wrong shape. Measurement will happen in a child
  this program launched, never by joining one it did not.
- Linux only, and only with `/proc` mounted.

GPL-3.0-or-later.
