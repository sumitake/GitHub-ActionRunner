package failoverclient

import "errors"

var errLeaseCacheEmpty = errors.New("failoverclient: no current lease")
