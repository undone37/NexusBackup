# Login shells on the appliance are break-glass only (the console gate): end idle ones after 15 minutes,
# create files without world access (plan.md Phase 35, docs/cis.md).
typeset -xr TMOUT=900
umask 027
