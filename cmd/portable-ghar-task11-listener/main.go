package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	status := run(ctx, os.Args[1:], os.Stdout, defaultListenerRuntime())
	stop()
	os.Exit(status)
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
