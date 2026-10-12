# GitHub scale set and probe

The controller reaches GitHub through one runner scale set per overlay
repository. Two one-shot `portable-ghar-controller` commands prepare and check
that access before a canary. Neither touches controller state, the fence, or
the Worker. Both run as root on the target, because they read the root-owned
overlay and credential files.

## Overlay inputs

Both commands read the private overlay given by `--config`. It must carry the
optional `github` section (response-size cap, operation timeout, response-header
timeout). Each repository's `credential_name` must name a `file` secret. That
file holds the personal access token, mode `0600`, owned by root, with at most
one trailing newline.

## Token permissions

Use a separate token for each repository. Per GitHub's actions-runner-controller
authentication guide, at the time of writing:

| Scale set level | Fine-grained token                                             | Classic token |
| --------------- | -------------------------------------------------------------- | ------------- |
| Repository      | Administration: read and write                                 | `repo`        |
| Organization    | Administration: read, plus Self-hosted runners: read and write | `admin:org`   |

Confirm against GitHub's current guide before creating the token. Prefer a
fine-grained token scoped to the one repository, with the shortest expiry the
canary allows.

## `create-scale-set` (D7)

```sh
sudo portable-ghar-controller create-scale-set --config=<overlay_path> --alias=<repository_alias>
```

The command looks up the repository's scale set in the default runner group.
If it is missing, the command creates it with exactly one label (its own name)
and in-place runner updates disabled. Either way, it reads the scale set back
and applies the same checks the controller applies before opening a session.
It prints one JSON object:

```json
{
  "alias": "example-fleet",
  "scale_set": "example-scaleset",
  "single_name_label": true,
  "disable_update": true,
  "created": true
}
```

It never updates or deletes an existing scale set. If an existing one fails a
check (for example a second label), the command exits 1 with the reason and
the operator fixes or removes it in GitHub. Running it again after success
changes nothing and reports `"created": false`.

## `external-probe`

```sh
sudo portable-ghar-controller external-probe --config=<overlay_path>
```

The probe opens one GitHub message session per overlay repository, records the
scale-set evidence, and closes every session. It prints:

```json
{
  "repositories": [
    {
      "alias": "example-fleet",
      "scale_set": "example-scaleset",
      "single_name_label": true,
      "disable_update": true
    }
  ]
}
```

GitHub allows one message session per scale set, so the probe fails while a
controller holds that scale set's session. Run it before the canary, not
during. If any repository fails, the probe closes the sessions it opened and
exits 1 with the alias and a reason. Reasons never include GitHub response
text.

The probe does not contact the Worker. The acquiring controller starts with
acquisition disabled, and its first signed heartbeat is the Worker check.
