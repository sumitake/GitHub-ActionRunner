package main

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sumitake/portable-ghar/internal/controller"
)

type localSocketIdentity struct {
	device uint64
	inode  uint64
}

type localAdminClient struct {
	mu          sync.Mutex
	path        string
	expectedUID uint32
	timeout     time.Duration
	identity    localSocketIdentity
	closed      bool
}

var _ controller.LiveAdmin = (*localAdminClient)(nil)

func newLocalAdminClient(
	path string,
	expectedUID uint32,
	timeout time.Duration,
) (*localAdminClient, error) {
	if timeout <= 0 {
		return nil, errLocalProtocol
	}
	identity, err := observeLocalSocketIdentity(path, expectedUID)
	if err != nil {
		return nil, err
	}
	return &localAdminClient{
		path:        path,
		expectedUID: expectedUID,
		timeout:     timeout,
		identity:    identity,
	}, nil
}

func (client *localAdminClient) Probe(
	ctx context.Context,
) (controller.PolicyStatus, error) {
	response, err := client.call(ctx, localRequest{
		SchemaVersion: localProtocolSchemaVersion,
		Method:        localMethodProbe,
	})
	if err != nil {
		return controller.PolicyStatus{}, err
	}
	return controller.PolicyStatus{
		Mode:     response.Policy.Mode,
		Epoch:    response.Policy.Epoch,
		Digest:   response.Policy.Digest,
		Capacity: response.Policy.Capacity,
	}, nil
}

func (client *localAdminClient) ReconcileOnce(
	ctx context.Context,
) (controller.CycleReceipt, error) {
	response, err := client.call(ctx, localRequest{
		SchemaVersion: localProtocolSchemaVersion,
		Method:        localMethodReconcileOnce,
	})
	if err != nil {
		return controller.CycleReceipt{}, err
	}
	completedAt, err := time.Parse(
		time.RFC3339Nano,
		response.Receipt.CompletedAt,
	)
	if err != nil ||
		response.Receipt.AssignmentCount > uint64(^uint(0)>>1) {
		return controller.CycleReceipt{}, errLocalProtocol
	}
	return controller.CycleReceipt{
		CycleID:         response.Receipt.CycleID,
		CompletedAt:     completedAt,
		AssignmentCount: int(response.Receipt.AssignmentCount),
		OldestAge: time.Duration(
			response.Receipt.OldestAgeNanoseconds,
		),
	}, nil
}

func (client *localAdminClient) Drain(
	ctx context.Context,
	policy controller.DrainPolicy,
) error {
	_, err := client.call(ctx, localRequest{
		SchemaVersion: localProtocolSchemaVersion,
		Method:        localMethodDrain,
		DrainPolicy:   &policy,
	})
	return err
}

func (client *localAdminClient) SetAcquisition(
	ctx context.Context,
	change controller.AcquisitionChange,
) (controller.PolicyStatus, error) {
	wireChange := &localAcquisitionChange{
		Set:      change.Set,
		Expected: change.Expected,
	}
	if change.EligibleScaleSet != "" {
		eligible := change.EligibleScaleSet
		wireChange.EligibleScaleSet = &eligible
	}
	response, err := client.call(ctx, localRequest{
		SchemaVersion: localProtocolSchemaVersion,
		Method:        localMethodSetAcquisition,
		Acquisition:   wireChange,
	})
	if err != nil {
		return controller.PolicyStatus{}, err
	}
	return controller.PolicyStatus{
		Mode:     response.Policy.Mode,
		Epoch:    response.Policy.Epoch,
		Digest:   response.Policy.Digest,
		Capacity: response.Policy.Capacity,
	}, nil
}

func (client *localAdminClient) Close() error {
	if client == nil {
		return errLocalProtocol
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closed = true
	return nil
}

func (client *localAdminClient) call(
	parent context.Context,
	request localRequest,
) (localResponse, error) {
	if client == nil || parent == nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	path := client.path
	expectedUID := client.expectedUID
	timeout := client.timeout
	expectedIdentity := client.identity
	client.mu.Unlock()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.UnixNano() <= 0 {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	request.DeadlineUnixNano = deadline.UnixNano()
	document, err := marshalLocalRequest(request)
	if err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := requireLocalSocketIdentity(
		path,
		expectedUID,
		expectedIdentity,
	); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := requireLocalUnixPeerUID(
		unixConnection,
		expectedUID,
	); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := requireLocalSocketIdentity(
		path,
		expectedUID,
		expectedIdentity,
	); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := writeAll(connection, document); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	responseDocument, err := io.ReadAll(
		io.LimitReader(connection, maxLocalResponseBytes+1),
	)
	if err != nil || len(responseDocument) > maxLocalResponseBytes {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	if err := requireLocalSocketIdentity(
		path,
		expectedUID,
		expectedIdentity,
	); err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	response, err := parseLocalResponse(request.Method, responseDocument)
	if err != nil {
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
	switch response.Status {
	case localStatusOK:
		return response, nil
	case localStatusUnavailable:
		return localResponse{}, controller.ErrRuntimeUnavailable
	case localStatusConflict:
		return localResponse{}, controller.ErrAdminConflict
	default:
		return localResponse{}, controller.ErrRuntimeUnavailable
	}
}

func observeLocalSocketIdentity(
	path string,
	expectedUID uint32,
) (localSocketIdentity, error) {
	if !canonicalAbsolutePath(path) {
		return localSocketIdentity{}, errLocalProtocol
	}
	parent := filepath.Dir(path)
	var parentStat unix.Stat_t
	if err := unix.Lstat(parent, &parentStat); err != nil ||
		uint32(parentStat.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(parentStat.Mode)&0o777 != 0o700 ||
		parentStat.Uid != expectedUID {
		return localSocketIdentity{}, errLocalProtocol
	}
	var socketStat unix.Stat_t
	if err := unix.Lstat(path, &socketStat); err != nil ||
		uint32(socketStat.Mode)&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(socketStat.Mode)&0o777 != 0o600 ||
		socketStat.Uid != expectedUID ||
		uint64(socketStat.Nlink) != 1 ||
		socketStat.Ino == 0 {
		return localSocketIdentity{}, errLocalProtocol
	}
	return localSocketIdentity{
		device: uint64(socketStat.Dev),
		inode:  socketStat.Ino,
	}, nil
}

func requireLocalSocketIdentity(
	path string,
	expectedUID uint32,
	expected localSocketIdentity,
) error {
	actual, err := observeLocalSocketIdentity(path, expectedUID)
	if err != nil || actual != expected {
		return errLocalProtocol
	}
	return nil
}

func writeAll(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		written, err := writer.Write(document)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(document) {
			return io.ErrShortWrite
		}
		document = document[written:]
	}
	return nil
}
