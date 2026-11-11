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

## v2 UserData, checksum, and Java

Each row was a negative test on the unfixed tree, 2026-11-10 PT. The same test passed after the fix. Detail is in `_build/fix-mutations.log`.

| Finding                                                                      | Negative test                                                                                                      | Mutation                                             | Result                                                                                                                                                                                                                                                 |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HIGH user data exceeds 16384 raw bytes and is base64-encoded before botocore | `test_m1_run_instances_uses_launch_template_and_user_data`; `test_guest_bootstrap_imports_without_the_source_tree` | pack every module and base64-encode `UserData`       | Killed: raw length `40312 > 16384`; round trip `b'IyEvYmluL3No'` does not start with `#!`; archive included `budget.py`. After the fix, raw `UserData` is 3920 bytes, starts with `#!`, and the archive is `__init__.py`, `supervisor.py`, `types.py`. |
| LOW `ChecksumSHA256` compared with base64 of the hex string                  | `test_readme_checksum_is_base64_of_raw_digest`                                                                     | README said base64 of the recorded `artifact_sha256` | Killed: `base64 encoding of the raw 32-byte digest` was absent. After the fix, README compares `ChecksumSHA256` with base64 of `bytes.fromhex` of `artifact_sha256`.                                                                                   |
| CI OpenJDK exact distro build is no longer in Ubuntu                         | `test_l4_dynamodb_local_and_java_are_pinned`                                                                       | pin `openjdk-21-jre-headless` to that exact build    | Killed: package-name install was absent; the step still pinned the dropped exact build. After the fix, CI installs `openjdk-21-jre-headless` by name. Fixture records that package and major `21`. DynamoDB Local jar pin unchanged.                   |
| LOW README checksum command used `<artifact_sha256>` (shell redirection)     | `test_readme_checksum_is_base64_of_raw_digest`                                                                     | restore `<artifact_sha256>` in the README command    | Killed: line does not end with `"$artifact_sha256"`. After the fix the README command run with the empty-input digest prints `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`.                                                                           |

## UNPROVEN/HOLD

Offline, `package-lambda.sh` binds the generated zip sha256 to the parameter names `CodeS3Bucket`, `CodeS3Key`, and `CodeS3ObjectVersion`. Those parameters have no defaults. This is not an S3 object attestation: no bucket, key, or version id was read or written. The live object linkage remains UNPROVEN/HOLD. README documents a read-only `aws s3api head-object` pre-deploy check that Nova approves and Ops runs (bucket, key, version, then compare `ContentLength` to `artifact_bytes` and `ChecksumSHA256` to the base64 of the raw 32-byte digest). That command was not run. This packet is not READY.

## Spend rulings

No runner-count cap of any kind (C5): `test_c_no_runner_count_limit` launches 25 runners and asserts no `MAX_RUNNERS` in `src/`. Budget `MonthlySoftCapCents` 3000 ($30), 10% grace, `ContinueActiveUntilCents` 3300 ($33). `TerminateInstances` takes one id per call and IAM allows it only with `aws:ResourceTag/overflow-watcher` = `owned` (`test_static_terminate_instances_only_on_budget_stop_with_tag_condition`). `ReservedConcurrentExecutions: 1` limits the controller Lambda, not runners.

## B1-B3 and alarm

Each row is one mutation of the fix on this branch, run on 2026-11-10 PT, then restored with `git checkout`. Every mutation killed its test (non-zero exit). Detail is in `_build/build-mutations.log`.

| Finding                                          | Negative test                                                                          | Mutation                                            | Result                                                              |
| ------------------------------------------------ | -------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------- |
| Mint failure refunds and does not launch         | `test_b1_mint_failure_does_not_launch_and_refunds`                                     | bad mint continues to RunInstances                  | Killed: launched `1 != 0`                                           |
| Put failure refunds and does not launch          | `test_b1_put_failure_refunds_without_launch`                                           | put exception continues to RunInstances             | Killed: launched `1 != 0`                                           |
| Existing parameter is not overwritten            | `test_b1_existing_parameter_is_kept_and_not_overwritten`                               | PutParameter `Overwrite=True`                       | Killed: `'fresh-minted-secret' != 'kept-original-bytes'`            |
| Definitive refusal deletes the parameter         | `test_b1_definitive_runinstances_refusal_deletes_parameter_and_does_not_delete_runner` | skip parameter delete on capacity refusal           | Killed: SSM map was not empty                                       |
| Ambiguous retry does not remint                  | `test_b1_ambiguous_retry_reuses_client_token_without_remint`                           | clear `jitReady` when marking the attempt ambiguous | Killed: mint count `2 != 1`                                         |
| Secret stays out of user data and the store      | `test_b1_userdata_and_store_do_not_contain_jit_secret`                                 | store `encodedJitConfig` on the reservation         | Killed: secret found in the instance record                         |
| JIT mint Content-Type is JSON                    | `test_b1_mint_request_content_type_is_json`                                            | omit the `Content-Type` header                      | Killed: `'application/x-www-form-urlencoded' != 'application/json'` |
| Same job does not debit twice                    | `test_b2_second_poll_same_job_does_not_double_debit`                                   | drop the open-instance pre-check and the JOB# lock  | Killed: `'launched' != 'duplicate'`                                 |
| Two jobs debit twice                             | `test_b2_two_jobs_two_debits`                                                          | return cap when any instance is already open        | Killed: `'cap' != 'launched'`                                       |
| Ambiguous launch is not refunded                 | `test_b2_ambiguous_attempt_is_not_refunded`                                            | `release_reservation` on AmbiguousLaunch            | Killed: ledger `0 != 6`                                             |
| Capacity refusal refunds once                    | `test_b2_capacity_refusal_refunds_once`                                                | skip `release_reservation` on capacity refusal      | Killed: `quota_failures` `0 != 1`                                   |
| Launched instance is not refunded                | `test_b2_launched_instance_is_not_refunded`                                            | `convert_reservation` subtracts the allowance       | Killed: ledger `0 != 6`                                             |
| Open instance blocks a second debit              | `test_b2_open_instance_blocks_a_second_debit_even_if_job_key_is_gone`                  | remove the open-instance pre-check                  | Killed: second poll launched `1 != 0`                               |
| Job lock held until close                        | `test_b2_job_key_held_until_closed_and_not_queued`                                     | delete the job lock while the instance is open      | Killed: lock count `0 != 1`                                         |
| Relaunch after close uses a new token            | `test_b2_relaunch_after_close_uses_a_new_client_token`                                 | attempt is always 0                                 | Killed: `TransactionCanceledException` on the second convert        |
| All-busy runners launch once                     | `test_b3_all_busy_launches_once`                                                       | treat `busy: true` as available                     | Killed: eligible jobs `0 != 1`                                      |
| One idle online runner does not launch           | `test_b3_one_idle_online_does_not_launch`                                              | treat `busy: false` as unavailable                  | Killed: jobs was not `()`                                           |
| Busy plus dedupe is one instance                 | `test_b3_busy_and_dedupe_one_instance`                                                 | drop the open-instance pre-check and the JOB# lock  | Killed: second poll launched `1 != 0`                               |
| Non-boolean busy fails closed                    | `test_b3_non_boolean_busy_is_malformed_no_launch`                                      | ignore a missing or non-boolean `busy`              | Killed: `uncertain` was false                                       |
| Runner API errors do not launch                  | `test_b3_runner_api_error_does_not_launch`                                             | treat HTTP 401 and 403 as an empty success          | Killed: 401 case `uncertain` was false                              |
| Alarm filters match budget and grace only        | `test_alarm_filter_matches_budget_and_grace_lines_only`                                | change the budget FilterPattern kind to `other`     | Killed: pattern list started with `other`                           |
| Alarm topic is encrypted for CloudWatch          | `test_alarm_topic_is_encrypted_for_cloudwatch`                                         | omit `KmsMasterKeyId` on the SNS topic              | Killed: `'KmsMasterKeyId' not found`                                |
| JIT parameter IAM is path scoped                 | `test_static_jit_parameter_iam_is_path_scoped`                                         | add `ssm:GetParametersByPath` on the runner role    | Killed: runner actions included `GetParametersByPath`               |
| No deregister and no runner DELETE               | `test_static_no_deregister_or_runner_delete`                                           | add the string `config.sh` to `controller.py`       | Killed: `'config.sh' unexpectedly found`                            |
| No runner-count cap                              | `test_c_no_runner_count_limit`                                                         | add `MAX_RUNNERS = 1` to `controller.py`            | Killed: `'MAX_RUNNERS' unexpectedly found`                          |
| Crash retry reuses the token and does not remint | `test_f7e_crash_before_transaction_retries_same_client_token_once`                     | ignore `jitReady`                                   | Killed: `ec2.calls` `[] != ['tok-crash']`                           |
