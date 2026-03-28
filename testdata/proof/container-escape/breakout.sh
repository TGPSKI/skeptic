#!/bin/bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
chroot /host /bin/sh
