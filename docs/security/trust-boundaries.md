# Trust boundaries

This page summarizes the trust model behind Portable GHAR's isolation
design at a level safe for a public repository. It is a truthful summary
of the review-gated design record at
`docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md`
section 4 and section 7, not a replacement for it. See
[Architecture overview](../architecture/overview.md) for how these
components fit together end to end.

## Trusted components

- The host operating system and its **Docker daemon**.
- The **Portable GHAR controller** and its private runtime state.
- The **host watchdog**.
- The **network-policy helper and verifier images**.
- The **Cloudflare Worker**, its per-fleet **Durable Object**, and their
  configured bindings.
- The **controller and failover GitHub Apps**.
- The operator's private deployment overlay and secret stores.

Docker control is host-root-equivalent: whatever can talk to the Docker
daemon can do anything the host's root user can do to that host. The
controller is therefore treated as a trusted host process even when its
own Unix account is not UID 0.

## Untrusted components

- Repository contents checked out for a job.
- Pull-request code, scripts, build tools, and dependencies.
- Action implementations downloaded for a job.
- Job output, artifacts, and any value derived from the job workspace.
- Contributions and issue content submitted to the public repository.

A job's worktree is never promoted into the control plane. Control-plane
code does not import, source, execute, or inspect job-owned configuration
beyond a narrow, schema-defined set of result fields.

## Bounded credentials

The JIT runner configuration used to register each ephemeral runner is
secret and is never logged, placed in Docker container configuration, or
persisted outside controller memory and the ephemeral runner process
itself.

Because Docker host metadata and runner configuration remain inside the
trusted-host/ephemeral-container boundary, the design does not claim a
malicious job can never observe its own one-job runner credential. The
mitigation is scope and lifetime, not secrecy from the job that holds it:

- one JIT configuration per runner and per job;
- no reusable controller GitHub App key inside the container;
- no host Docker access from the runner;
- no cross-job runner reuse; and
- immediate container destruction and credential invalidation after
  completion or error.

Docker `--env`, `--env-file`, labels, command arguments, bind mounts,
named volumes, and Docker config/secret objects are all prohibited as JIT
transport. The value transits a private, per-runner transport and is only
ever placed in the listener process's environment immediately before that
listener starts; the pinned upstream listener removes it from its own
process environment before any job process is created.

## Docker-host-equivalent authority

Because Docker control is host-root-equivalent, every component that can
reach the Docker socket or an equivalent control surface is treated as
fully trusted: the controller, the host watchdog, and the host's own
Docker daemon. No job, runner, adapter, or broker component is ever given
Docker socket access, a host bind mount, a host device, or a control-plane
credential.

## Egress barrier

Every runner starts inside a namespace with no routable interface. A
one-shot, `NET_ADMIN`-only helper installs the runner's egress policy into
a held broker namespace and then exits before the untrusted listener ever
starts; the helper and the listener never run concurrently. An
independent verifier then proves, from the actual runner namespace, that
allowed traffic succeeds and every denied literal, resolved, or
non-proxy-compatible destination fails -- before the controller releases
the runner's job credential.

The bounded egress broker that performs real network dials is split into
a parser (reads untrusted bytes, opens no socket) and a dialer (owns every
socket, consumes a durable dial permit before each connection, and
re-applies the full deny-class check independently of the parser). This
separation means a parser compromise alone cannot open a socket, reach a
denied destination, or exceed the dial budget.

## Shared-kernel boundary

Every runner container on a host shares that host's kernel. Portable GHAR
enforces namespace-creation denial, seccomp restrictions, no runner-owned
socket or mount, and bounded broker resources, and its acceptance gates
include live adversarial probes against those controls -- but a kernel or
container-runtime escape can still bypass container and network controls.
This is the accepted, explicit boundary of container-grade isolation.

## Explicit non-claims

Portable GHAR does **not** claim any of the following:

- **Not VM-grade isolation.** All runner containers share the host
  kernel; operators who need VM-grade or hardware-grade isolation must
  place the Docker host inside an independently isolated VM or network
  segment.
- **Not a hosted service.** Portable GHAR is a self-hosted control plane
  an operator runs on their own Docker host and Cloudflare account; the
  project does not operate a hosted control plane on anyone's behalf.
- **JIT is bounded, not hidden.** The one-job runner credential's scope
  and lifetime are the mitigation; the design does not claim the job that
  holds a JIT credential cannot observe it.
- **Not an official GitHub project.** Portable GHAR wraps a public-preview
  upstream client and is not endorsed by, or a component of, GitHub's own
  runner infrastructure.
