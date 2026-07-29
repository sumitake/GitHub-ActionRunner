#!/bin/sh
# SPDX-License-Identifier: MPL-2.0

# Resume only one of the closed target actions. The Go authority derives and
# validates the operation ID, journal phase, receipt chain, and replay path.
pghar_resume_operation() {
  [ "$#" -ge 1 ] || pghar_fail 64
  case "$1" in
  install | verify | suspend | resume | rollback | uninstall | \
    watchdog-install | watchdog-uninstall)
    pghar_invoke "$@"
    ;;
  *) pghar_fail 64 ;;
  esac
}
