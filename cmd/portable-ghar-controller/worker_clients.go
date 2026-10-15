package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/controller"
	"github.com/sumitake/portable-ghar/internal/failoverclient"
	"github.com/sumitake/portable-ghar/internal/health"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

// productionWorkerClients is the controller's link to the failover Worker.
// The service publishes health through Health; each publish runs one
// heartbeat session exchange, which enrolls if needed and refreshes the lease
// cache. Permits grant an acquisition only under a lease in that cache.
type productionWorkerClients struct {
	Health  *health.Publisher
	Permits failoverclient.CachedLeasePermitProvider
	session *failoverclient.HeartbeatSession
}

type productionWorkerConfig struct {
	Overlay     hostruntime.PrivateOverlay
	HMACKeyHex  string
	FleetGuards controller.FleetGuardProvider
	BuildID     string
	Fence       uint64
	// AttemptInterval is the longest gap between heartbeat attempts: the
	// service publishes health once per reconciliation cycle.
	AttemptInterval time.Duration
	Clock           failoverclient.AuthorityClock
	Transport       http.RoundTripper
	// OnLeaseOverrun ends the process. It runs when a permit is still open
	// leaseOverrunSlice before its lease ends locally, so a controller that
	// has not finished terminating stops before the Worker lease expires.
	OnLeaseOverrun func(controller.AcquisitionPermitBinding)
}

// leaseOverrunSlice is how long before a permit's local lease deadline the
// process exits if the permit is still open. The termination tail must
// exceed it: a permit stops granting at the tail, and the controller has
// until the slice to finish terminating on its own.
const leaseOverrunSlice = 2 * time.Second

func newProductionWorkerClients(
	config productionWorkerConfig,
) (productionWorkerClients, error) {
	worker := config.Overlay.Worker
	if worker == nil || config.AttemptInterval <= 0 || config.OnLeaseOverrun == nil {
		return productionWorkerClients{}, errCommandUnavailable
	}
	hmacKey, err := decodeWorkerHMACKey(config.HMACKeyHex)
	if err != nil {
		return productionWorkerClients{}, err
	}
	// The overlay validated every duration as canonical and positive.
	window, _ := time.ParseDuration(worker.TimestampWindow)
	lease, _ := time.ParseDuration(worker.LeaseDuration)
	deadline, _ := time.ParseDuration(worker.HeartbeatDeadline)
	margin, _ := time.ParseDuration(worker.ShorteningMargin)
	tail, _ := time.ParseDuration(worker.TerminationTail)
	// A permit lasts as long as the controller operation that holds it: the
	// call plus its durable and acknowledgement work.
	callDuration, callErr := time.ParseDuration(config.Overlay.Controller.OperationTimeout)
	// Every installed lease ends at lease - margin locally; a tail that
	// reaches that far leaves no permit any slack.
	if callErr != nil || callDuration <= 0 || tail <= leaseOverrunSlice ||
		margin >= lease || tail >= lease-margin {
		return productionWorkerClients{}, errCommandUnavailable
	}

	client, err := failoverclient.NewProtocolClient(failoverclient.ProtocolClientConfig{
		BaseURL:         worker.BaseURL,
		HMACKey:         hmacKey,
		RoundTripper:    config.Transport,
		AuthorityClock:  config.Clock,
		UTCNow:          time.Now,
		AttemptTimeout:  deadline,
		TimestampWindow: window,
	})
	if err != nil {
		return productionWorkerClients{}, err
	}
	cache := &failoverclient.LeaseCache{}
	session, err := failoverclient.NewHeartbeatSession(failoverclient.HeartbeatSessionConfig{
		Client:          client,
		Cache:           cache,
		FleetGuards:     config.FleetGuards,
		FleetID:         worker.FleetID,
		BuildID:         config.BuildID,
		Holder:          failoverclient.HeartbeatHolderPortable,
		FenceGeneration: config.Fence,
		Budget: failoverclient.HeartbeatBudget{
			LeaseDuration:      lease,
			MaxAttemptInterval: config.AttemptInterval,
			Deadline:           deadline,
			ShorteningMargin:   margin,
			LostRenewals:       uint(worker.LostRenewals),
		},
		NextNonce: randomWorkerNonce,
	})
	if err != nil {
		return productionWorkerClients{}, err
	}
	publisher, err := health.NewPublisher(session)
	if err != nil {
		return productionWorkerClients{}, errors.Join(err, session.Close())
	}
	permits, err := failoverclient.NewCachedLeasePermitProvider(
		failoverclient.CachedLeasePermitConfig{
			Cache:           cache,
			Clock:           config.Clock,
			Holder:          failoverclient.HolderPortable,
			Fence:           config.Fence,
			CallDuration:    callDuration,
			TerminationTail: tail,
			OverrunSlice:    leaseOverrunSlice,
			OnLeaseOverrun:  config.OnLeaseOverrun,
		},
	)
	if err != nil {
		return productionWorkerClients{}, errors.Join(err, session.Close())
	}
	return productionWorkerClients{
		Health:  publisher,
		Permits: permits,
		session: session,
	}, nil
}

func (clients productionWorkerClients) Close() error {
	if clients.session == nil {
		return nil
	}
	return clients.session.Close()
}

// decodeWorkerHMACKey reads the Worker's HMAC_KEY credential: lowercase hex
// of at least 32 bytes, the same text the Worker deployment binds.
func decodeWorkerHMACKey(value string) ([]byte, error) {
	if value != strings.ToLower(value) {
		return nil, errCommandUnavailable
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) < 32 {
		return nil, errCommandUnavailable
	}
	return key, nil
}

func randomWorkerNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}
