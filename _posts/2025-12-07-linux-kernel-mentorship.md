---
layout: post
title: "Reflections on the Linux Kernel Mentorship"
date: 2025-12-07
---

## Introduction

***

From September 2025 to December 2025, I was a mentee in the Linux Foundation's [Linux Kernel Mentorship Program](https://wiki.linuxfoundation.org/lkmp).

The Linux Kernel Mentorship Program (LKMP) is an opportunity providing access to mentors while contributing to the Linux Kernel. At the end of the project term, mentees will have a much deeper knowledge of many subsystems of the Linux kernel and hopefully, many bugs fixed and many patches accepted.

I am looking to break into the kernel and operating system space to become a kernel software developer. I have wanted to contribute to Linux for a long time, and this was an excellent opportunity to get started and see what it is like.

## Getting started

***

The objective of the LKMP is to contribute 5+ patches to the Linux Kernel. These patches may include fixes to compiler warnings, documentation, kselftest, drivers, and/or core kernel areas. However, mentees are encouraged to provide bug fixes rather than fixes to compiler warnings or documentation.

I chose to fix kernel bugs reported by [Syzkaller](https://syzkaller.appspot.com/upstream), the public dashboard for bugs found by the open-source [syz fuzzer](https://github.com/google/syzkaller) provided by Google – this is very common for mentees and is encouraged by the program.

Syzkaller bugs are mostly kernel warnings, and reports from KASAN (Kernel Address Sanitizer), KMSAN (Memory), and UBSAN (Undefined Behavior). Note, Syzkaller bugs can be very challenging, especially for those new to the subsystem the bug is in. Not all reported bugs have reproducers, and even those that do may have very finicky environments and may not reproduce easily, if at all.

During the mentorship, I fixed 2 bugs in the Bluetooth subsystem, 1 bug in XFS, 1 bug in the loop driver,  and 1 bug in NTFS3. I will go over my workflow in the hopes that the reader finds it useful.

### Testing
Before going into my workflow, I will mention that you should always know how to test your potential patch before you begin making changes. This isn't anything complicated; know the subsystem's testing tool. Often, the tester tools live outside of the main Linux repository. For instance, Bluetooth uses [bluez](https://github.com/bluez/bluez), and file systems (in general) use [fstests](https://github.com/tytso/xfstests-bld).

While kselftests are a good fallback option, do not rely on them for anything more than sanity checks.

Testing should not be an afterthought to fixing the bug. During the mentorship, I observed many of my peers having patches rejected for lack of testing and for introducing regressions.

### Tools
- [qemu](https://gitlab.com/qemu-project/qemu/-/tree/master)
- [gdb](https://sourceware.org/git/?p=binutils-gdb.git;a=summary)
- [syzkaller](https://github.com/google/syzkaller/tree/master) 

I will not get into how to set up the tools or the developer environment; I leave that as an exercise to the reader. 

**Note 1**: I will mention I had to install qemu from their gitlab myself since the binary available by debian/ubuntu apt does not include much support for anything (e.g. qemu-xhci for Bluetooth/USB is not enabled). If you are having trouble with the tools, consider configuring and building them for yourself. And obviously, syzkaller was a local install as well; it's useful for its bin executables to reproduce bugs using a syz reproducer if no C reproducer is available.

**Note 2**: Be aware that KASAN bugs may be race conditions, so setting gdb breakpoints usually breaks the timing necessary for the bugs to happen.

## Workflow

***

### Overview
The generic overview of the workflow is as follows:
1. Attempt to reproduce a bug with either a C or syz reproducer on your local setup (using qemu or a test system)
2. Understand the code flow, debug,  and find a fix
3. Test the fix on your local setup
4. Write a commit log explaining what you are fixing (do not document the code, document the actual fix)
5. Send patch to relevant people and mailing lists
6. Repeat the process for *every* reply and new change to your patch

Let's go over one of the easier bugs I fixed during the program. It's a classic KMSAN uninit-value. I will just go over Steps 1 and 2 of the workflow, and leave the rest as an exercise for the reader.

The bug: [KMSAN: uninit-value in hci_cmd_complete_evt](https://syzkaller.appspot.com/bug?extid=a9a4bedfca6aa9d7fa24)

### Reproducing the bug

Syzkaller compiles kernels with the panic-on-warn flag set, along with one of KASAN, KMSAN, or UBSAN. Syzkaller then fuzzes the kernel with a series of test programs, and if one of KASAN, KMSAN, or UBSAN gives a warning, the kernel panics and crashes. Once it finds a crash, Syzkaller sends a bug report to the dashboard and to the appropriate kernel mailing lists.

The first step to fixing a reported Syzkaller bug is to reproduce it. That way, you can test locally, instead of sending a patch test request email to Syzkaller for every fix you make, since those can take over an hour to complete. In general, we reproduce Syzkaller bugs with the reproducer provided in the bug report. We run the reproducer on a virtual machine with qemu or on a special local test system. We will be using qemu.

The first step in reproducing the bug is to download the reproduction assets from Syzkaller. They are specific to the bug and can be found in the Crashes section of the bug report. 

When downloading the reproduction assets from Syzkaller, you're getting the exact compiled kernel image it used to produce the crash, and a C reproducer that *should* reproduce the crash. Syzkaller itself uses Syz to fuzz the kernel, and in some cases, converting a Syz reproducer to C reproducer is unreliable. If that's the case, then you must use the Syz reproducer.

Here is a link to the Syzkaller docs explaining [how to reproduce crashes](https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md).

I use wget to download the assets:
```Bash
wget -O repro.c https://syzkaller.appspot.com/x/repro.c?163c6458580000
wget https://storage.googleapis.com/syzbot-assets/90b0fb888152/disk-9b0d551b.raw.xz
wget https://storage.googleapis.com/syzbot-assets/df9bbfa8cbe6/bzImage-9b0d551b.xz
```
unxz them:
```Bash
unxz bzImage-9b0d551b.xz disk-9b0d551b.raw.xz
```
Compile the C repro:
```Bash
gcc -o repro -lpthread -static repro.c
```
Now run a virtual machine with qemu. My command for this bug was:
```Bash
qemu-system-x86_64 -m 8192 -smp 1 -machine q35,accel=kvm -cpu host \
-kernel bzImage-9b0d551b \
-append "root=/dev/vda1 console=ttyS0" \
-drive file=disk-9b0d551b.raw,format=raw,if=virtio,id=hd0 \
-nographic -enable-kvm \
-netdev user,id=net0,hostfwd=tcp::10022-:22 \
-device qemu-xhci,id=xhci
```
Just 1 CPU is necessary for this bug.

**Note**:
For debugging, you'll want to add the flags `-s -S` which will hang the VM until you connect to it with gdb, e.g. `gdb -tui -ex 'target remote localhost:1234' <the-vmlinux-being-used>`

**Note**: appending `2>&1 | tee vm.log` to the end of the command is helpful; it will copy the vm output into a file called vm.log.

**Note**: having a .gdbinit with the following is also helpful; these will copy the gdb output to a file called gdb.txt:
```Bash
set trace-commands on
set logging enabled
```

In another terminal, you'll want to copy the repro into the vm:
```Bash
scp -O -P 10022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes repro root@127.0.0.1:/root/
```

Now, run the repro in the qemu virtual machine and wait a second for the crash:
```Bash
./repro
```
If the repro doesn't crash the VM, you've done something wrong. Or, the C reproducer is unreliable. However, in this case, the C reproducer is reliable, so you have done something wrong with the environment.

Now that we can reproduce the bug, we can make changes with the belief that when testing locally, we can see if we have fixed it. Then send a patch test request email to Syzkaller later to verify.

If you want to test the kernel with a fix, you'll want to get the .config from the reproduction assets:
```Bash
wget -O .config https://syzkaller.appspot.com/x/.config?x=50fb29d81ff5a3df
```
Then build the kernel with your fix. KMSAN (and KASAN) is a LLVM tool, so you must use Clang and ld.lld. Use -j[number of CPUs] to accelerate the build:
```Bash
make CC=clang LD=ld.lld -j8
```

### Fixing the bug

Let's look at the stack trace of the crash:
```crash
BUG: KMSAN: uninit-value in hci_cmd_complete_evt+0xca3/0xe90 net/bluetooth/hci_event.c:4226
  hci_cmd_complete_evt+0xca3/0xe90 net/bluetooth/hci_event.c:4226
  hci_event_func net/bluetooth/hci_event.c:7556 [inline]
  hci_event_packet+0xcdf/0x1e40 net/bluetooth/hci_event.c:7613
  hci_rx_work+0x9a8/0x12b0 net/bluetooth/hci_core.c:4099
  process_one_work kernel/workqueue.c:3263 [inline]
  process_scheduled_works+0xb8e/0x1d80 kernel/workqueue.c:3346
  worker_thread+0xedf/0x1590 kernel/workqueue.c:3427
  kthread+0xd59/0xf00 kernel/kthread.c:463
  ret_from_fork+0x233/0x380 arch/x86/kernel/process.c:148
  ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
[...]
Uninit was created at:
  slab_post_alloc_hook mm/slub.c:4953 [inline]
  slab_alloc_node mm/slub.c:5245 [inline]
  kmem_cache_alloc_node_noprof+0x989/0x16b0 mm/slub.c:5297
  kmalloc_reserve+0x13c/0x4b0 net/core/skbuff.c:579
  __alloc_skb+0x347/0x7d0 net/core/skbuff.c:670
  alloc_skb include/linux/skbuff.h:1383 [inline]
  bt_skb_alloc include/net/bluetooth/bluetooth.h:510 [inline]
  vhci_get_user drivers/bluetooth/hci_vhci.c:496 [inline]
  vhci_write+0x125/0x960 drivers/bluetooth/hci_vhci.c:616
  new_sync_write fs/read_write.c:593 [inline]
  vfs_write+0xbe2/0x15d0 fs/read_write.c:686
  ksys_write fs/read_write.c:738 [inline]
  __do_sys_write fs/read_write.c:749 [inline]
  __se_sys_write fs/read_write.c:746 [inline]
  __x64_sys_write+0x1fb/0x4d0 fs/read_write.c:746
  x64_sys_call+0x3014/0x3e30 arch/x86/include/generated/asm/syscalls_64.h:2
  do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
  do_syscall_64+0xd9/0x210 arch/x86/entry/syscall_64.c:94
  entry_SYSCALL_64_after_hwframe+0x77/0x7f

CPU: 1 UID: 0 PID: 5079 Comm: kworker/u9:1 Not tainted syzkaller #0 PREEMPT(none) 
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/18/2025
Workqueue: hci0 hci_rx_work
=====================================================
```

Since this is a KMSAN bug, which are typically easy to fix, I'll leave out most of the crash report so we can focus on the crash itself.
The crash event, which we know is an "uninit-value" from the crash log, is at net/bluetooth/hci_event.c:4226. This means that KMSAN detected the use of an uninitialized value on line 4226, and issued a warning. Since the kernel is compiled with panic-on-warn, it panicked and crashed.

**Note**: KASAN and KMSAN track memory by state, not by value. So, it doesn't matter what the *value* is at the address we're going to crash at, it just matters that the kernel did not directly allocate memory for that address.

This is line 4226 in the commit syzkaller is testing:
<span class="margin-note-source">
  [net/bluetooth/hci_event.c:4226](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c?id=9b0d551bcc05fa4786689544a2845024db1d41b6#n4226)
</span>
```C
hci_req_cmd_complete(hdev, *opcode, *status, req_complete,
                 req_complete_skb);
```

What's gone wrong here? Well, since the error is with this line in particular and there is no mention of the req_complete callback (which is hard-coded and assuredly a value), we can safely assume the uninit value is one of `hdev`, `*opcode`, or `*status`. Immediately, we rule out hdev since we would have crashed early if hdev were junk. So, we are crashing on a pointer dereference for either the opcode or the status.

The questions now: what is opcode, and what is status?

Let's look at the entire function in its relevant entirety:
<span class="margin-note-source">
  [net/bluetooth/hci_event.c:4194](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c?id=9b0d551bcc05fa4786689544a2845024db1d41b6#n4194)
</span>
```C
static void hci_cmd_complete_evt(struct hci_dev *hdev, void *data,
                                struct sk_buff *skb, u16 *opcode, u8 *status,
                                hci_req_complete_t *req_complete,
                                hci_req_complete_skb_t *req_complete_skb)
{
    struct hci_ev_cmd_complete *ev = data;
    int i;

    *opcode = __le16_to_cpu(ev->opcode);

    bt_dev_dbg(hdev, "opcode 0x%4.4x", *opcode);

    for (i = 0; i < ARRAY_SIZE(hci_cc_table); i++) {
        if (hci_cc_table[i].op == *opcode) {
            *status = hci_cc_func(hdev, &hci_cc_table[i], skb);
            break;
        }
    }

    if (i == ARRAY_SIZE(hci_cc_table)) {
        /* Unknown opcode, assume byte 0 contains the status, so
         * that e.g. __hci_cmd_sync() properly returns errors
         * for vendor specific commands send by HCI drivers.
         * If a vendor doesn't actually follow this convention we may
         * need to introduce a vendor CC table in order to properly set
         * the status.
         */
        *status = skb->data[0];
    }

    handle_cmd_cnt_and_timer(hdev, ev->ncmd);

    hci_req_cmd_complete(hdev, *opcode, *status, req_complete,
                     req_complete_skb);

    /* ... snip ... */
```

We have the opcode set as the event opcode, and then immediately use it with the debug print:
```C
    *opcode = __le16_to_cpu(ev->opcode);

    bt_dev_dbg(hdev, "opcode 0x%4.4x", *opcode);
```
This means we can rule it out. The uninit error would have occurred at the debug statement if the opcode was uninitialized memory.

We move on to status, which is set by:
```C
    if (i == ARRAY_SIZE(hci_cc_table)) {
        /* Unknown opcode, assume byte 0 contains the status, so
         * that e.g. __hci_cmd_sync() properly returns errors
         * for vendor specific commands send by HCI drivers.
         * If a vendor doesn't actually follow this convention we may
         * need to introduce a vendor CC table in order to properly set
         * the status.
         */
        *status = skb->data[0];
    }
```

Aha, so the status is set to the first byte of the socket buffer's data. And per the comment, this is due to an unknown opcode; we assume that byte 0 contains the status so that the sync command function can properly return errors for vendor-specific commands sent by HCI drivers. In other words, we support vendor-specific commands sent by HCI drivers; therefore, we can't just throw away packets with unknown opcodes - they might be custom commands.

We can verify that the comment is telling the truth about the unknown opcode, since earlier in the function loop variable `i` would be less than hci_cc_table size if the opcode were in the hci_cc_table:
```C
    for (i = 0; i < ARRAY_SIZE(hci_cc_table); i++) {
        if (hci_cc_table[i].op == *opcode) {
            *status = hci_cc_func(hdev, &hci_cc_table[i], skb);
            break;
        }
    }
```

So we hypothesize that `skb->data[0]` is uninitialized memory. But why is it uninitialized? 

We can look at Syzkaller's repro.c to see what's happening that led to this point. Looking at the crash stack trace from earlier, we know that `Uninit was created at:` began with a write syscall. This is what the repro.c is doing:
<span class="margin-note-source">
  [repro.c](https://syzkaller.appspot.com/text?tag=ReproC&x=163c6458580000)
</span>
```C
static long syz_emit_vhci(volatile long a0, volatile long a1)
{
    if (vhci_fd < 0) 
        return (uintptr_t)-1;
    char* data = (char*)a0;
    uint32_t length = a1;
    return write(vhci_fd, data, length);
}

void execute_one(void)
{
    /* snip */
    memcpy((void*)0x200000000080, "\x04\x0e", 2);
    syz_emit_vhci(/*data=*/0x200000000080, /*size=*/6);
}
```
We observe that we're memcpy-ing whatever "\x04\x0e" is, which is of size 2, to 0x200000000080. Then, with a write syscall, we're writing 6 bytes of our data (at 0x200000000080) to a vhci file descriptor. In other words, we're writing a packet to vhci so it can be sent over Bluetooth.

But hold on, we're memcpy-ing 2 bytes but writing 6? That's curious. Are the remaining 4 bytes from junk where the uninit memory is coming from? That *surely* is the case since we're writing a packet containing [0x04 0x0e junk1 junk2 junk3 junk4] to vhci, right? No. The kernel doesn't care about userspace junk. For the kernel, userspace sends it a request, and junk1-junk4 are just potential values that the kernel must check. The KMSAN is on the kernel side, not because of the userspace input.

Hence, we must investigate further. What are we actually sending here? How does our input lead to the scenario that results in the KMSAN uninit value?

Well, from hci_cmd_complete_evt(), we know we're in a Command Complete Event, so let's see what that "\x04\x0e" means.

Let's look up "Host Controller interface (HCI)" in the Bluetooth documentation. I'll spare the reader the pain of finding what we're looking for in the Bluetooth docs.
The HCI docs are [here](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html). 
From reading the docs, the first value of the header is the [Packet Type](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/three-wire-uart-transport-layer.html#UUID-1cf959bb-57a0-e782-4324-a9bc4ee3f134). The value 0x04 means the packet is an [HCI Event Packet](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-f209cdf7-0496-8bcd-b7e1-500831511378). From here, we know that an event packet is of the form:

![](/assets/images/1653f7aca9b561.png){: width="512px" }

Meaning, skb->data is supposed to contain the event code, the parameter total length, and the event parameters. Therefore,  0x0E is the event code, which indeed is [HCI Command Complete Event](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-76d31a33-1a9e-07bc-87c4-8ebffee065fd):

![](/assets/images/command_complete_event.png){: width="896px" }

So we observe that skb->data is supposed to contain the event parameters `Num_HCI_Command_Packets`, `Command_Opcode`, and `Return Parameters`, all of which are junk values. However, recall the code above, in the case of an unknown opcode, skb->data[0] is supposed to be the status. Where have all the other values in the data gone, then?

Let's go up the stack trace into hci_event_func() and hci_event_packet().

**Note**: Since hci_event_packet() is a long function I'll link it [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c?id=9b0d551bcc05fa4786689544a2845024db1d41b6#n7562) and summarize that event code and parameter total length are part of the header, and have both been pulled. Hence, only the event parameters remain in `skb->data` when we reach `hci_event_func()`.

<span class="margin-note-source">
  [net/bluetooth/hci_event.c:7525](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/bluetooth/hci_event.c?id=9b0d551bcc05fa4786689544a2845024db1d41b6#n7525)
</span>
```C
static void hci_event_func(struct hci_dev *hdev, u8 event, struct sk_buff *skb,
                           u16 *opcode, u8 *status,
                           hci_req_complete_t *req_complete,
                           hci_req_complete_skb_t *req_complete_skb)
{
    const struct hci_ev *ev = &hci_ev_table[event];
    void *data;

    if (!ev->func)
        return;

    if (skb->len < ev->min_len) {
        bt_dev_err(hdev, "unexpected event 0x%2.2x length: %u < %u",
        event, skb->len, ev->min_len);
        return;
    }

    /* Just warn if the length is over max_len size it still be
     * possible to partially parse the event so leave to callback to
     * decide if that is acceptable.
     */
    if (skb->len > ev->max_len)
        bt_dev_warn_ratelimited(hdev,
                                "unexpected event 0x%2.2x length: %u > %u",
                                event, skb->len, ev->max_len);

    data = hci_ev_skb_pull(hdev, skb, event, ev->min_len);
    if (!data)
        return;
    
    if (ev->req)
        ev->func_req(hdev, data, skb, opcode, status, req_complete,
                     req_complete_skb);
    else
        ev->func(hdev, data, skb);
}
```

Since all the checks pass in hci_event_packet() and hci_event_func() and we get to the req_complete callback, which is hci_cmd_complete_evt(), we know 2 things:
1. The packet is correct structurally.
2. The event parameters have all been pulled by `hci_ev_skb_pull()`, and therefore the skb->data is empty, and skb->len is 0.
    This is confirmed by debugging with gdb, which is left as an exercise to the reader.

So, to answer our original questions from before,
```txt
Hence, we must investigate further. What are we actually sending here? How does our input lead to the scenario that results in the KMSAN uninit value?
```
What we are actually sending here is:
```C
byte 0 | packet type: 0x04 => HCI Event Packet
byte 1 | Event_Code: 0x0e => HCI Command Complete Event
byte 2 | Num_HCI_Command_Packets: junk 1
byte 3 | Command_Opcode: junk 2 (Note: Command_Opcode is 2 bytes large)
byte 4 | Command_Opcode: junk 3
byte 5 | Return_Parameters: junk 4
```
And what actually matters is that the opcode is some junk value that's not recognized. Curiously, this coincides with the specific scenario we discussed earlier: if an opcode is unknown, byte 0 contains the status. This is done to support vendor-specific commands sent by HCI drivers.

Now we look back at our hypothesis:
```txt
So we hypothesize that `skb->data[0]` is uninitialized memory. But why is it uninitialized? 
```
The answer: we know that skb->data[0] is uninitialized memory because all the data was pulled in hci_event_func(), leaving skb->data empty. Hence, the crash is actually an array-out-of-bounds bug reported as an uninitialized memory bug (by coincidence, skb->data[0] now so happens to point to uninitialized memory).

The crash is clear: skb->data[0] is out of bounds since skb->data is empty, and skb->len is 0.

Hence, the fix in this case is just adding a check for skb length for an unknown Command Complete Event Command_Opcode:
```C
    if (i == ARRAY_SIZE(hci_cc_table)) {
+       if (!skb->len) {
+           bt_dev_err(hdev, "unexpected cc 0x%4.4x with no status",
+                           *opcode);
+           *status = HCI_ERROR_UNSPECIFIED;
+           return;
+       }
+
        /* Unknown opcode, assume byte 0 contains the status, so
         * that e.g. __hci_cmd_sync() properly returns errors
         * for vendor specific commands send by HCI drivers.
         * If a vendor doesn't actually follow this convention we may
         * need to introduce a vendor CC table in order to properly set
         * the status.
         */
        *status = skb->data[0];
    }

    /* snip */
```

Not all bugs are this simple to fix. The other bugs I fixed were too complex to explain concisely in a blog such as this.

Also,  the first patch is usually incorrect. Either it will be incomplete because you didn't take certain things into account due to unfamiliarity with the subsystem, or it was simply wrong. Regardless, if the patch is useful, it will provoke discussion that proposing fixes. In this case, my first patch for this bug was to reject packets with a junk Num_HCI_Command_Packets value, which proved to be too big a hammer for a junk value.

## Reflections

***

I spent my time in the Linux Kernel Mentorship Program fixing Syzkaller bugs.

I deliberately avoided the low-hanging fruit, easy fixes for compiler warnings and Documentation changes, because I find them uninteresting, and also because I observed many of my peers' patches being seen as pointless and rejected by maintainers. You have to empathize with the maintainers here; they receive dozens of patches to their subsystem per day, and adding more to their workload to fix compiler warnings is a waste of their time. Therefore, you should only work on compiler warnings and so on as a last resort if you are unable to understand syzbot bugs – and even then, only until you get a better understanding of the development process. This isn't a program for complete beginners; you should be able to fix some bugs.

However, the direction I took in the program does have a steep learning curve due to the different subsystems. For every subsystem, you must learn how it works and how the maintainer(s) like to do things. How do they test? Do they like patches submitted in a specific way? Moreover, you're not just learning a 'subsystem', you're learning a technology. For example, with Bluetooth, you must know how Bluetooth works in general, and how the the driver works, in addition to figuring out how to fix a bug. The learning curve is why I advise most people to stick to 1-2 subsystems rather than the 4 I did. But if you are willing to spend lots of time learning subsystems, then fixing bugs in several of them is absolutely worth it. I now know how Bluetooth, xfs, ntfs3, and loop/block work to a degree that I can send a cogent patch to them all without further investigation.

In sum, the LKMP was challenging and having mentors there to guide me through sending my first patch proved valuable. I am grateful for my experience in the Linux Kernel Mentorship Program and thank Shuah Khan, David Hunter, and Khalid Aziz for being great mentors and resources to learn from.

