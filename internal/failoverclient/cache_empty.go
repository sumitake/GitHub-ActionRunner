package failoverclient

import "errors"

var errLeaseCacheAwaiting = errors.New("failoverclient: awaiting transition lease")
