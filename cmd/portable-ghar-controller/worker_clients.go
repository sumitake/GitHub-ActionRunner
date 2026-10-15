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
}

func newProductionWorkerClients(
	config productionWorkerConfig,
) (productionWorkerClients, error) {
	worker := config.Overlay.Worker
	if worker == nil || config.AttemptInterval <= 0 {
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
	join, joinErr := time.ParseDuration(config.Overlay.Controller.TransitionJoinTimeout)
	finish, finishErr := time.ParseDuration(config.Overlay.Controller.DurableFinishTimeout)
	fatalPath, fatalOK := fatalPathBound(join, finish)
	// Every installed lease ends at lease - margin locally; a tail that
	// reaches that far leaves no permit any slack.
	if callErr != nil || joinErr != nil || finishErr != nil ||
		callDuration <= 0 || !fatalOK || tail <= fatalPath ||
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

// fatalPathBound is the longest the controller can take, after a permit's
// cancel deadline, to reach the terminator. J is the transition join
// timeout and F the durable finish timeout. The worst path is an
// acquisition whose call ignores cancellation and never returns: the
// tracked call's join (J), marking the batch ambiguous (F), the fatal
// transition's compare-and-set under the caller's join (J), its wait for
// the still-open old epoch (J), the post-CAS failure's second wait (J), and
// the secondary fatal persist (J): 5J + F. A call that returns late takes
// at most J + F + F + J. The bound 5J + 2F covers both. The termination tail
// must exceed it so termination keeps a slice before the Worker lease
// expires.
func fatalPathBound(join, finish time.Duration) (time.Duration, bool) {
	if join <= 0 || finish <= 0 {
		return 0, false
	}
	var total time.Duration
	for _, term := range []time.Duration{join, join, join, join, join, finish, finish} {
		next := total + term
		if next < total {
			return 0, false
		}
		total = next
	}
	return total, true
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
