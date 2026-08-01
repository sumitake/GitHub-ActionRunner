# deploy/systemd

These are inert source templates. Every `/ABSOLUTE/PORTABLE_GHAR/...` and
angle-bracket value must be generated from a separately approved private
overlay. Nothing in this directory enables, starts, installs, or selects a
service, timer, sizing value, user, host, or cadence.

The watchdog unit intentionally has no Docker or network dependency and denies
IP networking. The controller template is the disabled local observer only;
external Worker, hosted-routing, and nonzero acquisition authorities remain
unavailable.
