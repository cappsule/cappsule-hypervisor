# Cappsule's hypervisor

This repository is part of [Cappsule](https://github.com/cappsule), and contains
the hypervisor. Please refer to the
[documentation](https://github.com/cappsule/doc/) for more information.



## Overview

CPU and memory are virtualized thanks to hardware virtualization technology
(Intel VT-x and EPT). During the launch of the hypervisor, the running OS is
*bluepilled* and a snapshot of the memory is done.

The hypervisor supports 2 kinds of VM:

- the *trusted guest* (1 instance): this is the bluepilled OS, which has no
  restrictions.
- the cappsules (0 to n instances): no access to the hardware is allowed, and
  the memory is a copy-on-write version of the snapshot.

In order to operate, Cappsule needs to insert 2 kernel modules (`cappsule.ko`
and `cappsule_guest.ko`). A userland daemon (in the
[userland repository](https://github.com/cappsule/userland/)) is responsible of
the communication between userland and the kernel module.


## Architecture

- `common/`: code shared between trusted guest / host / cappsule.
- `guest/`: cappsules. This code is considered unsafe and is **not** trusted by
  the hypervisor. This code is executed in VMX non-root mode.
- `host/`: hypervisor. This code is executed in VMX root mode.
- `include/`: everything under `cuapi/` can be included both from the hypervisor
  and the userland repositories.
- `trusted/`: *trusted guest*. This code is executed in VMX non-root mode, but
  is trusted by the hypervisor.
