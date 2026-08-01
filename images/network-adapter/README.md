# images/network-adapter

Task 5 defines the capless, static network-adapter image. Its ignored `build/`
directory is produced with the runner context by:

```sh
repository="$(pwd -P)"
scripts/prepare-task6-images.sh
scripts/prepare-task5-images.sh \
  --generation <nonzero-integer> \
  --ca-bundle "$repository/images/trust/build/ca-bundle.pem"
```

Task 6 first publishes the exact locked CA bundle required by the paired runner
context; the adapter context does not consume it. The deny-all `.dockerignore`
admits only this Dockerfile and the final static Linux binary. A referenced
context-audit stage checks the effective Docker context, and the final
`scratch` image contains only the binary, required empty tmpfs mount points,
and a nonsecret audit marker. It has no environment, shell, package manager,
or mutable default filesystem and runs as numeric UID/GID `65532`.

Source construction does not claim Linux namespace, seccomp, peer-identity, or
relay target-conformance; those remain later target gates.
