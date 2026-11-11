# Overflow watcher checklist

Each row names the fail-closed test and the mutation that was applied, run, and restored. Every mutation killed its test (non-zero exit).

Clean re-run on `7ae0727d7fbfb260425da8f494814d306b2bb2f5` (main, base of this closeout), 2026-11-10 PT. Every section below was applied on that clean tree and restored with `git checkout`. `git status` was clean after every row.

## #150

| Finding                                              | Negative test                                                          | Mutation                                      | Result                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------- | --------------------------------------------- |
| H1 recompute, no survivor watermark                  | `test_h1_estimate_change_stops_instance_spared_by_earlier_poll`        | `select_minimum` returns `[]` unconditionally | Killed: cancel list `[] != ['2']`             |
| H2 empty exclusions fail closed                      | `test_h2_empty_exclusions_fail_closed`                                 | drop the empty-string exclusion error         | Killed: `True is not false` (config accepted) |
| H3 JSON alert before the claim                       | `test_h3_budget_and_grace_alerts_are_one_json_line_and_once_per_month` | skip `write_alert_line`                       | Killed: budget line count `0 != 1`            |
| M1 launch template and user data                     | `test_m1_run_instances_uses_launch_template_and_user_data`             | omit `UserData`                               | Killed: test error, `UserData` missing        |
| M2 keep reservation after ambiguous capacity refusal | `test_m2_capacity_refusal_after_ambiguous_keeps_reservation`           | release the reservation on that path          | Killed: open reservations `0 != 1`            |
| L1 follow `NextToken`                                | `test_l1_list_tagged_ids_follows_next_token`                           | stop after the first page (`token = None`)    | Killed: ids `['i-a'] != ['i-a', 'i-b']`       |
| L2 `/proc` read error is not "no worker"             | `test_l2_proc_read_error_is_not_no_worker`                             | return `False` on `OSError`                   | Killed: `False is not None`                   |
| L3 `CreateTags` is not `Resource: "*"`               | `test_l3_create_tags_is_not_unscoped`                                  | remove `ec2:CreateAction`                     | Killed: action string not in the window       |
| L4 pinned DynamoDB Local and Java                    | `test_l4_dynamodb_local_and_java_are_pinned`                           | change the jar sha256                         | Killed: test error, pin string missing        |

## #151

| Finding                                             | Negative test                                                      | Mutation                                         | Result                                        |
| --------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------ | --------------------------------------------- |
| H1 `finished_during_wait` still running             | `test_finished_during_wait_does_not_spare_a_running_instance`      | return `"spared"` for that phase                 | Killed: terminate calls `[] != [['i-live']]`  |
| H2 ambiguous GitHub read (`None`)                   | `test_ambiguous_workflow_read_alerts_and_does_not_terminate`       | terminate when completion is `None`              | Killed: terminate calls `[['i-wait']] != []`  |
| H3 quota retry is not a self-compare                | `test_c_quota_refusal_is_recorded_without_retry_storm`             | ignore the cooldown                              | Killed: two `RunInstances` tokens             |
| H3 pin is not a self-compare                        | `test_l4_dynamodb_local_and_java_are_pinned`                       | change the workflow pin                          | Killed: fixture pin not found in the workflow |
| H3 tests read keys the code writes                  | `test_h1_estimate_change_stops_instance_spared_by_earlier_poll`    | skip the `cancel_wait` claim                     | Killed: phase `None != 'cancel_wait'`         |
| M1 emit failure before the claim                    | `test_alert_line_is_printed_before_the_claim`                      | claim `ALERT#BUDGET` before `write_alert_line`   | Killed: confirmed marker is not `None`        |
| M2 do not override block devices                    | `test_m1_run_instances_uses_launch_template_and_user_data`         | put `BlockDeviceMappings` back on `RunInstances` | Killed: key unexpectedly present              |
| M2 supervisor is in the Lambda zip                  | `test_lambda_package_has_supervisor_at_the_userdata_path`          | omit `boot/supervisor.sh` from the package       | Killed: script `is_file()` is false           |
| M3 only excluded runners over the projection        | `test_excluded_runners_over_projection_alert_once_and_do_not_stop` | ignore workflow exclusion rules                  | Killed: cancel list is not empty              |
| L1 tag scan includes `stopping` and `shutting-down` | `test_l1_list_tagged_ids_follows_next_token`                       | filter only `pending` and `running`              | Killed: state list missing the two states     |

## #151 continued

Same clean tree `7ae0727d7fbfb260425da8f494814d306b2bb2f5`. On that tree the small id is not terminated when this poll's minimum set is only the larger runner. Reintroducing the unselected `cancel_wait` union makes `test_unselected_cancel_wait_does_not_terminate_and_reselection_is_fresh` fail with `terminate_calls` `[['i-a']] != []`.

| Finding                                                                     | Negative test                                                             | Mutation                                          | Result                                                              |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------- |
| H1 advance only the current minimum set and reset an unselected cancel-wait | `test_unselected_cancel_wait_does_not_terminate_and_reselection_is_fresh` | no-op `delete_marker` for an unselected claim     | Killed: `INST#i-a` `cancel_wait` marker was not `None`              |
| M1 guest package import with no source checkout on `PYTHONPATH`             | `test_guest_bootstrap_imports_without_the_source_tree`                    | skip extracting the payload into the guest root   | Killed: `import overflow_watcher.supervisor` exited 1               |
| L1 past-allowance line before the claim                                     | `test_past_allowance_alert_is_not_claimed_when_emit_fails`                | claim `ALERT#ALLOWANCE` before `write_alert_line` | Killed: confirmed marker was not `None`                             |
| L2 decisive `True`/`False` versus ambiguous `None`                          | `test_readme_states_none_does_not_terminate`                              | remove the `None` sentence                        | Killed: the sentence was absent                                     |
| L3 owned `stopping` and `shutting-down` stay exposure                       | `test_owned_stopping_is_exposure_not_an_unknown`                          | drop the transitional branch                      | Killed: `block_launch` became true                                  |
| L3 uncertain describe still fails closed                                    | `test_uncertain_owned_instance_still_blocks_launch`                       | ignore `view.uncertain`                           | Killed: a launch was admitted (`1 != 0`)                            |
| retry-held line before the claim                                            | `test_retry_held_alert_is_not_claimed_when_emit_fails`                    | claim `ALERT#RETRY` before `write_alert_line`     | Killed: `{'pk': 'RES#tok-old', 'sk': 'ALERT#RETRY'}` was not `None` |
| zip is not a deployment key                                                 | `test_built_zip_is_not_bound_to_a_deployment_key`                         | give `CodeS3Key` a `Default`                      | Killed: `Default:` was present                                      |

## #151 offline zip binding

Same clean tree `7ae0727d7fbfb260425da8f494814d306b2bb2f5`.

| Finding                                                  | Negative test                                                   | Mutation                         | Result                                                  |
| -------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------- | ------------------------------------------------------- |
| Generated zip sha256 must match the binding              | `test_package_binding_rejects_missing_mismatch_and_stale_input` | skip the digest and size compare | Killed: checker returned 0 (`0 == 0`)                   |
| Template must still pass bucket, key, and object version | `test_package_binding_matches_zip_and_template_parameters`      | remove `S3ObjectVersion`         | Killed: `1 != 0`, `substituted or stale template input` |

## UNPROVEN/HOLD

Offline, `package-lambda.sh` binds the generated zip sha256 to the parameter names `CodeS3Bucket`, `CodeS3Key`, and `CodeS3ObjectVersion`. Those parameters have no defaults. This is not an S3 object attestation: no bucket, key, or version id was read or written. The live object linkage remains UNPROVEN/HOLD. README documents a read-only `aws s3api head-object` pre-deploy check that Nova approves and Ops runs (bucket, key, version, then compare `ContentLength` and `ChecksumSHA256` to the recorded size and sha256). That command was not run. This packet is not READY.

## Spend rulings

No runner-count cap of any kind (C5): `test_c_no_runner_count_limit` launches 25 runners and asserts no `MAX_RUNNERS` in `src/`. Budget `MonthlySoftCapCents` 3000 ($30), 10% grace, `ContinueActiveUntilCents` 3300 ($33). `TerminateInstances` takes one id per call and IAM allows it only with `aws:ResourceTag/overflow-watcher` = `owned` (`test_static_terminate_instances_only_on_budget_stop_with_tag_condition`). `ReservedConcurrentExecutions: 1` limits the controller Lambda, not runners.
