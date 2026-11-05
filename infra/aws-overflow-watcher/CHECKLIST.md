# Overflow watcher checklist

Each row names the fail-closed test and the mutation that was applied, run, and restored. Every mutation killed its test (non-zero exit).

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
