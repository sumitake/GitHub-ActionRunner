# deploy/qts

The scripts here are fixed shell boundaries around the installed Go
state-machine authority. They parse exact arguments, require Linux and EUID 0,
and emit only the Go authority's canonical success document or one generic
failure line. They do not parse JSON, build Docker argv, evaluate command
files, restore fence snapshots, or invent recovery.

No real target path, identity, schedule, network, sizing value, or private
overlay is defined here. `watchdog.cron.example` contains placeholders and
must not be installed until the operator separately approves cadence and host
configuration.
