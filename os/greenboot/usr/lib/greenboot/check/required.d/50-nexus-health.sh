#!/bin/bash
# greenboot required check: a failure marks the boot red (greenboot reboots; after
# GREENBOOT_MAX_BOOT_ATTEMPTS red boots of a freshly updated deployment it runs
# `bootc rollback` and reboots into the previous image). See /usr/libexec/nexus/nexus-health.
exec /usr/libexec/nexus/nexus-health
