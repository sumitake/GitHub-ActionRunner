package controller

import "errors"

// ErrAcquisitionLeasePending denies acquisition while a non-poisoned cache has
// no lease. Only a pre-effect poll may wait; issued permits still fail closed.
var ErrAcquisitionLeasePending = errors.New("controller: acquisition lease pending")

var errPollAwaitLease = errors.New("controller: poll awaits Worker lease")
