Google Summer of Code 2019 Work Product Submission
=================================

Summary
---------------------------------
This summer I worked on integrating fuzz testing into
[QEMU](https://www.qemu.org/). Fuzzing is a powerful technique for detecting
software bugs by providing random inputs to programs. Some of these bugs may be
potentially exploitable. Within QEMU, some of the most dangerous bugs are the
ones in virtual devices - they can allow a malicious guest to perform
a [virtual-machine
escape](https://en.wikipedia.org/wiki/Virtual_machine_escape).

My changes are in this github repo. I have submitted patch-sets to the
qemu-devel mailing list from my email - alxndr@bu.edu . These patches include
fuzzer code, as well as bug fixes.

Description
---------------------------------
The rate at which a fuzzer can identify bugs is largely dictated by the speed at
which it can test new inputs. To fuzz virtual devices in QEMU, I needed a
running virtual machine, from which I could send I/O commands to the devices.
Additionally, I needed to reset QEMU's state in between fuzzing runs, since
finding a crash is not very useful, if I cannot reproduce it. I provide three
fuzzing skeletons which each have pros/cons. The Rebooting-based fuzzer simply
performs a system-reboot after each fuzzing run. This is fairly fast, but
requires any device-initialization to be repeated after each run. The
Restore-based fuzzer uses QEMU's snapshot/restore functionality to restore
QEMU's state, though it is slower than rebooting. The Fork-based fuzzer executes
each new input in a fork()'ed process. This is fast, but relies on a custom
change to libfuzzer (the fuzzing framework).

To make it simple for QEMU developers to fuzz additional devices, I based the
fuzzing framework on qtest - QEMU's existing testing system. Though qtest
usually uses two processes to execute tests, this requires expensive
inter-process communication, which slows down the fuzzer. My changes include
a new qtest setting which allows the tester and the testee to exist within the
same process. Fuzzers are also able to use QOS, which abstracts away device
initialization and complicated communication protocols.

The Code and Building It
---------------------------------
The changes I have made to QEMU to add fuzzing are covered by commits
11e1fdb826-11dad83297 in this repo.
To build and run the code:
```
git clone https://github.com/a1xndr/qemu
mkdir qemu-build
cd qemu-build
# Substitute your version of clang
CC=clang-7 CXX=clang++-7 ../qemu/configure --enable-fuzzing
make i386-softmmu/all
# Pick the fuzz target and fuzzing options
./i386-softmmu/qemu-system-i386 --virtio-net-ctrl-multi-fuzz -detect_leaks=0 -close_fd_mask=3
```

Conclusion
---------------------------------
Over time, my changes have become more self-contained, and I hope to get the
fuzzing framework merged, soon.

Thank you to my mentors, Bandan Das, Paolo Bonzini, and Stefan Hajnoczi for all
of their help and advice throughout the summer.
