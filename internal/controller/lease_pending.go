package controller

import "errors"

// ErrAcquisitionLeasePending denies acquisition after a local policy transition
// cleared a non-poisoned cache. Only a pre-effect poll may wait; issued permits still fail closed.
var ErrAcquisitionLeasePending = errors.New("controller: acquisition lease pending")

var errPollAwaitLease = errors.New("controller: poll awaits Worker lease")
