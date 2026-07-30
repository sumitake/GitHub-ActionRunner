package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, defaultListenerRuntime()))
}

func defaultListenerRuntime() listenerRuntime {
	return listenerRuntime{
		environ:              os.Environ,
		lookupEnv:            os.LookupEnv,
		unsetEnv:             os.Unsetenv,
		newObserver:          newSystemObserver,
		createRegistration:   createRegistrationMarker,
		exchangeHTTPS:        exchangeHTTPS,
		prepareSeed:          prepareSeed,
		createUpgradeStaging: createUpgradeStaging,
	}
}
