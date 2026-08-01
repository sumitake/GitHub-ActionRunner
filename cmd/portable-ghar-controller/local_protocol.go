package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const (
	localProtocolSchemaVersion = uint32(1)
	maxLocalRequestBytes       = 4 << 10
	maxLocalResponseBytes      = 16 << 10
	maxLocalScalarBytes        = 128
)

var errLocalProtocol = errors.New(
	"portable-ghar-controller: local protocol invalid",
)

type localMethod string

const (
	localMethodProbe          localMethod = "probe"
	localMethodReconcileOnce  localMethod = "reconcile_once"
	localMethodDrain          localMethod = "drain"
	localMethodSetAcquisition localMethod = "set_acquisition"
	localMethodHealth         localMethod = "health"
)

type localStatus string

const (
	localStatusOK          localStatus = "ok"
	localStatusUnavailable localStatus = "unavailable"
	localStatusConflict    localStatus = "conflict"
)

type localReason string

const (
	localReasonNone                 localReason = "none"
	localReasonNotReady             localReason = "not_ready"
	localReasonPolicyDrift          localReason = "policy_drift"
	localReasonProjectionIncomplete localReason = "projection_incomplete"
	localReasonMethodUnavailable    localReason = "method_unavailable"
	localReasonDeadlineExceeded     localReason = "deadline_exceeded"
	localReasonIdentityMismatch     localReason = "identity_mismatch"
	localReasonInternalFailure      localReason = "internal_failure"
)

type localAcquisitionChange struct {
	Set              controller.AcquisitionMode `json:"set"`
	Expected         controller.AcquisitionMode `json:"expected"`
	EligibleScaleSet *string                    `json:"eligible_scale_set,omitempty"`
}

type localRequest struct {
	SchemaVersion    uint32                  `json:"schema_version"`
	Method           localMethod             `json:"method"`
	DeadlineUnixNano int64                   `json:"deadline_unix_nano"`
	DrainPolicy      *controller.DrainPolicy `json:"drain_policy,omitempty"`
	Acquisition      *localAcquisitionChange `json:"acquisition,omitempty"`
}

type localPolicyStatus struct {
	Mode     controller.AcquisitionMode `json:"mode"`
	Epoch    uint64                     `json:"epoch"`
	Digest   string                     `json:"digest"`
	Capacity int                        `json:"capacity"`
}

type localCycleReceipt struct {
	CycleID              string `json:"cycle_id"`
	CompletedAt          string `json:"completed_at"`
	AssignmentCount      uint64 `json:"assignment_count"`
	OldestAgeNanoseconds int64  `json:"oldest_age_nanoseconds"`
}

type localResponse struct {
	SchemaVersion uint32             `json:"schema_version"`
	Status        localStatus        `json:"status"`
	Reason        localReason        `json:"reason"`
	Policy        *localPolicyStatus `json:"policy,omitempty"`
	Receipt       *localCycleReceipt `json:"receipt,omitempty"`
}

func marshalLocalRequest(request localRequest) ([]byte, error) {
	if err := validateLocalRequest(request); err != nil {
		return nil, err
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) == 0 || len(document) > maxLocalRequestBytes {
		return nil, errLocalProtocol
	}
	return document, nil
}

func parseLocalRequest(document []byte) (localRequest, error) {
	if len(document) == 0 || len(document) > maxLocalRequestBytes {
		return localRequest{}, errLocalProtocol
	}
	var request localRequest
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return localRequest{}, errLocalProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localRequest{}, errLocalProtocol
	}
	canonical, err := marshalLocalRequest(request)
	if err != nil || !bytes.Equal(canonical, document) {
		return localRequest{}, errLocalProtocol
	}
	return request, nil
}

func validateLocalRequest(request localRequest) error {
	if request.SchemaVersion != localProtocolSchemaVersion ||
		request.DeadlineUnixNano <= 0 {
		return errLocalProtocol
	}
	switch request.Method {
	case localMethodProbe, localMethodReconcileOnce, localMethodHealth:
		if request.DrainPolicy != nil || request.Acquisition != nil {
			return errLocalProtocol
		}
	case localMethodDrain:
		if request.DrainPolicy == nil ||
			request.Acquisition != nil ||
			(*request.DrainPolicy != controller.DrainWait &&
				*request.DrainPolicy != controller.DrainCancel) {
			return errLocalProtocol
		}
	case localMethodSetAcquisition:
		if request.DrainPolicy != nil ||
			!validLocalAcquisitionChange(request.Acquisition) {
			return errLocalProtocol
		}
	default:
		return errLocalProtocol
	}
	return nil
}

func validLocalAcquisitionChange(change *localAcquisitionChange) bool {
	if change == nil ||
		!validOperatorAcquisitionMode(change.Set) ||
		!validOperatorAcquisitionMode(change.Expected) {
		return false
	}
	if change.Set == controller.AcquisitionCanaryOnly {
		return change.EligibleScaleSet != nil &&
			validLocalScalar(*change.EligibleScaleSet)
	}
	return change.EligibleScaleSet == nil
}

func validOperatorAcquisitionMode(mode controller.AcquisitionMode) bool {
	switch mode {
	case controller.AcquisitionDisabled,
		controller.AcquisitionCanaryOnly,
		controller.AcquisitionEnabled:
		return true
	default:
		return false
	}
}

func marshalLocalResponse(
	method localMethod,
	response localResponse,
) ([]byte, error) {
	if err := validateLocalResponse(method, response); err != nil {
		return nil, err
	}
	document, err := json.Marshal(response)
	if err != nil || len(document) == 0 || len(document) > maxLocalResponseBytes {
		return nil, errLocalProtocol
	}
	return document, nil
}

func parseLocalResponse(
	method localMethod,
	document []byte,
) (localResponse, error) {
	if len(document) == 0 || len(document) > maxLocalResponseBytes {
		return localResponse{}, errLocalProtocol
	}
	var response localResponse
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return localResponse{}, errLocalProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return localResponse{}, errLocalProtocol
	}
	canonical, err := marshalLocalResponse(method, response)
	if err != nil || !bytes.Equal(canonical, document) {
		return localResponse{}, errLocalProtocol
	}
	return response, nil
}

func validateLocalResponse(
	method localMethod,
	response localResponse,
) error {
	if response.SchemaVersion != localProtocolSchemaVersion ||
		!validLocalMethod(method) ||
		!validLocalStatus(response.Status) ||
		!validLocalReason(response.Reason) {
		return errLocalProtocol
	}
	if response.Status != localStatusOK {
		if response.Reason == localReasonNone ||
			response.Policy != nil ||
			response.Receipt != nil ||
			(method == localMethodHealth &&
				response.Status != localStatusUnavailable) {
			return errLocalProtocol
		}
		return nil
	}
	if response.Reason != localReasonNone {
		return errLocalProtocol
	}
	switch method {
	case localMethodProbe, localMethodSetAcquisition:
		if !validLocalPolicyStatus(response.Policy) ||
			response.Receipt != nil {
			return errLocalProtocol
		}
	case localMethodReconcileOnce:
		if response.Policy != nil ||
			!validLocalCycleReceipt(response.Receipt) {
			return errLocalProtocol
		}
	case localMethodDrain, localMethodHealth:
		if response.Policy != nil || response.Receipt != nil {
			return errLocalProtocol
		}
	default:
		return errLocalProtocol
	}
	return nil
}

func validLocalMethod(method localMethod) bool {
	switch method {
	case localMethodProbe,
		localMethodReconcileOnce,
		localMethodDrain,
		localMethodSetAcquisition,
		localMethodHealth:
		return true
	default:
		return false
	}
}

func validLocalStatus(status localStatus) bool {
	switch status {
	case localStatusOK, localStatusUnavailable, localStatusConflict:
		return true
	default:
		return false
	}
}

func validLocalReason(reason localReason) bool {
	switch reason {
	case localReasonNone,
		localReasonNotReady,
		localReasonPolicyDrift,
		localReasonProjectionIncomplete,
		localReasonMethodUnavailable,
		localReasonDeadlineExceeded,
		localReasonIdentityMismatch,
		localReasonInternalFailure:
		return true
	default:
		return false
	}
}

func validLocalPolicyStatus(status *localPolicyStatus) bool {
	if status == nil ||
		status.Epoch == 0 ||
		len(status.Digest) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(status.Digest)
	if err != nil || len(decoded) != 32 ||
		strings.ToLower(status.Digest) != status.Digest {
		return false
	}
	switch status.Mode {
	case controller.AcquisitionDisabled:
		return status.Capacity == 0
	case controller.AcquisitionCanaryOnly:
		return status.Capacity == 1
	case controller.AcquisitionEnabled:
		return status.Capacity > 0
	default:
		return false
	}
}

func validLocalCycleReceipt(receipt *localCycleReceipt) bool {
	if receipt == nil ||
		!validLocalScalar(receipt.CycleID) ||
		receipt.OldestAgeNanoseconds < 0 {
		return false
	}
	completedAt, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	return err == nil &&
		!completedAt.IsZero() &&
		completedAt.Location() == time.UTC &&
		completedAt.Format(time.RFC3339Nano) == receipt.CompletedAt
}

func validLocalScalar(value string) bool {
	if value == "" ||
		len(value) > maxLocalScalarBytes ||
		!utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
