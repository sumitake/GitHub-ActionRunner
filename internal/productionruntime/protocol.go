package productionruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	MaxDocumentBytes = 3 << 20
	MaxWireBytes     = MaxDocumentBytes + 1

	protocolSchemaVersion = uint32(1)
	requestDigestDomain   = "portable-ghar-production-request-v1"
	responseDigestDomain  = "portable-ghar-production-response-v1"
)

var ErrProtocol = errors.New("productionruntime: protocol failed")

type ProtocolAction string

const (
	ProtocolProveTarget  ProtocolAction = "prove-target"
	ProtocolStageRelease ProtocolAction = "stage-release"
	ProtocolInvoke       ProtocolAction = "invoke"
)

type InvokeArguments struct {
	Acquisition        string `json:"acquisition"`
	DrainPolicy        string `json:"drain_policy"`
	HostedConfirmation string `json:"hosted_confirmation"`
	RequireZero        bool   `json:"require_zero"`
	ManifestDigest     string `json:"manifest_digest"`
	StageProofDigest   string `json:"stage_proof_digest"`
	TargetProofDigest  string `json:"target_proof_digest"`
}

type ProveRequest struct{}

type StageRequest struct {
	TargetProof    cli.TargetProof             `json:"target_proof"`
	Manifest       hostruntime.RuntimeManifest `json:"manifest"`
	ManifestDigest string                      `json:"manifest_digest"`
}

type InvokeRequest struct {
	TargetProof cli.TargetProof `json:"target_proof"`
	Action      string          `json:"action"`
	Arguments   InvokeArguments `json:"arguments"`
}

type Request struct {
	SchemaVersion          uint32                     `json:"schema_version"`
	Action                 ProtocolAction             `json:"action"`
	RequestDigest          string                     `json:"request_digest"`
	PrivateOverlayRevision string                     `json:"private_overlay_revision"`
	TargetProofDigest      string                     `json:"target_proof_digest"`
	PrivateOverlay         hostruntime.PrivateOverlay `json:"private_overlay"`
	Prove                  *ProveRequest              `json:"prove,omitempty"`
	Stage                  *StageRequest              `json:"stage,omitempty"`
	Invoke                 *InvokeRequest             `json:"invoke,omitempty"`
}

type Response struct {
	SchemaVersion          uint32                        `json:"schema_version"`
	Action                 ProtocolAction                `json:"action"`
	RequestDigest          string                        `json:"request_digest"`
	ResponseDigest         string                        `json:"response_digest"`
	PrivateOverlayRevision string                        `json:"private_overlay_revision"`
	TargetProofDigest      string                        `json:"target_proof_digest"`
	Target                 *cli.TargetProof              `json:"target,omitempty"`
	Stage                  *cli.StageProof               `json:"stage,omitempty"`
	Invoke                 *hostruntime.HostActionResult `json:"invoke,omitempty"`
}

type TargetHandler interface {
	ProveTarget(
		context.Context,
		hostruntime.PrivateOverlay,
		string,
	) (cli.TargetProof, error)
	StageRelease(
		context.Context,
		hostruntime.PrivateOverlay,
		string,
		cli.TargetProof,
		hostruntime.RuntimeManifest,
		string,
	) (cli.StageProof, error)
	Invoke(
		context.Context,
		hostruntime.PrivateOverlay,
		string,
		cli.TargetProof,
		cli.HostAction,
		InvokeArguments,
	) (hostruntime.HostActionResult, error)
}

func NewProveRequest(
	overlay hostruntime.PrivateOverlay,
	revision string,
) (Request, error) {
	request := Request{
		SchemaVersion:          protocolSchemaVersion,
		Action:                 ProtocolProveTarget,
		PrivateOverlayRevision: revision,
		PrivateOverlay:         overlay,
		Prove:                  &ProveRequest{},
	}
	return sealRequest(request)
}

func NewStageRequest(
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	manifest hostruntime.RuntimeManifest,
	manifestDigest string,
) (Request, error) {
	request := Request{
		SchemaVersion:          protocolSchemaVersion,
		Action:                 ProtocolStageRelease,
		PrivateOverlayRevision: revision,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlay:         overlay,
		Stage: &StageRequest{
			TargetProof:    target,
			Manifest:       manifest,
			ManifestDigest: manifestDigest,
		},
	}
	return sealRequest(request)
}

func NewInvokeRequest(
	overlay hostruntime.PrivateOverlay,
	revision string,
	target cli.TargetProof,
	action cli.HostAction,
	arguments InvokeArguments,
) (Request, error) {
	actionName, ok := hostActionName(action)
	if !ok {
		return Request{}, ErrProtocol
	}
	request := Request{
		SchemaVersion:          protocolSchemaVersion,
		Action:                 ProtocolInvoke,
		PrivateOverlayRevision: revision,
		TargetProofDigest:      target.ProofDigest,
		PrivateOverlay:         overlay,
		Invoke: &InvokeRequest{
			TargetProof: target,
			Action:      actionName,
			Arguments:   arguments,
		},
	}
	return sealRequest(request)
}

func MarshalRequest(request Request) ([]byte, error) {
	if !validRequest(request) {
		return nil, ErrProtocol
	}
	return marshalFrame(request)
}

func ParseRequest(wire []byte) (Request, error) {
	var request Request
	document, ok := frameDocument(wire)
	if !ok || !decodeClosed(document, &request) {
		return Request{}, ErrProtocol
	}
	canonical, err := json.Marshal(request)
	if err != nil ||
		!bytes.Equal(canonical, document) ||
		!validRequest(request) {
		return Request{}, ErrProtocol
	}
	return request, nil
}

func NewTargetResponse(
	request Request,
	target cli.TargetProof,
) (Response, error) {
	response := responseFor(request)
	response.TargetProofDigest = target.ProofDigest
	response.Target = &target
	return sealResponse(response, request)
}

func NewStageResponse(
	request Request,
	stage cli.StageProof,
) (Response, error) {
	response := responseFor(request)
	response.Stage = &stage
	return sealResponse(response, request)
}

func NewInvokeResponse(
	request Request,
	result hostruntime.HostActionResult,
) (Response, error) {
	response := responseFor(request)
	response.Invoke = &result
	return sealResponse(response, request)
}

func MarshalResponse(response Response, request Request) ([]byte, error) {
	if !validResponse(response, request) {
		return nil, ErrProtocol
	}
	return marshalFrame(response)
}

func ParseResponse(wire []byte, request Request) (Response, error) {
	var response Response
	document, ok := frameDocument(wire)
	if !ok || !decodeClosed(document, &response) {
		return Response{}, ErrProtocol
	}
	canonical, err := json.Marshal(response)
	if err != nil ||
		!bytes.Equal(canonical, document) ||
		!validResponse(response, request) {
		return Response{}, ErrProtocol
	}
	return response, nil
}

func Serve(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	tty bool,
	handler TargetHandler,
) error {
	if ctx == nil ||
		stdin == nil ||
		stdout == nil ||
		tty ||
		handler == nil ||
		ctx.Err() != nil {
		return ErrProtocol
	}
	wire, err := io.ReadAll(io.LimitReader(stdin, int64(MaxWireBytes)+1))
	if err != nil || len(wire) > MaxWireBytes {
		return ErrProtocol
	}
	request, err := ParseRequest(wire)
	if err != nil {
		return ErrProtocol
	}
	timeout, err := time.ParseDuration(
		request.PrivateOverlay.ManagementTransport.OperationTimeout,
	)
	if err != nil || timeout <= 0 {
		return ErrProtocol
	}
	operationContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var response Response
	switch request.Action {
	case ProtocolProveTarget:
		target, callErr := handler.ProveTarget(
			operationContext,
			request.PrivateOverlay,
			request.PrivateOverlayRevision,
		)
		if callErr != nil {
			return ErrProtocol
		}
		response, err = NewTargetResponse(request, target)
	case ProtocolStageRelease:
		stage, callErr := handler.StageRelease(
			operationContext,
			request.PrivateOverlay,
			request.PrivateOverlayRevision,
			request.Stage.TargetProof,
			request.Stage.Manifest,
			request.Stage.ManifestDigest,
		)
		if callErr != nil {
			return ErrProtocol
		}
		response, err = NewStageResponse(request, stage)
	case ProtocolInvoke:
		action, ok := parseHostAction(request.Invoke.Action)
		if !ok {
			return ErrProtocol
		}
		result, callErr := handler.Invoke(
			operationContext,
			request.PrivateOverlay,
			request.PrivateOverlayRevision,
			request.Invoke.TargetProof,
			action,
			request.Invoke.Arguments,
		)
		if callErr != nil {
			return ErrProtocol
		}
		response, err = NewInvokeResponse(request, result)
	default:
		return ErrProtocol
	}
	if err != nil {
		return ErrProtocol
	}
	output, err := MarshalResponse(response, request)
	if err != nil || !writeFull(stdout, output) {
		return ErrProtocol
	}
	return nil
}

func sealRequest(request Request) (Request, error) {
	request.RequestDigest = ""
	if !validRequestShape(request, false) {
		return Request{}, ErrProtocol
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > MaxDocumentBytes {
		return Request{}, ErrProtocol
	}
	request.RequestDigest = digestArtifact(requestDigestDomain, document)
	if !validRequest(request) {
		return Request{}, ErrProtocol
	}
	return request, nil
}

func validRequest(request Request) bool {
	if !validRequestShape(request, true) {
		return false
	}
	digest := request.RequestDigest
	request.RequestDigest = ""
	document, err := json.Marshal(request)
	return err == nil &&
		len(document) <= MaxDocumentBytes &&
		digest == digestArtifact(requestDigestDomain, document)
}

func validRequestShape(request Request, requireDigest bool) bool {
	if request.SchemaVersion != protocolSchemaVersion ||
		requireDigest && !lowerHexDigest(request.RequestDigest) ||
		!requireDigest && request.RequestDigest != "" {
		return false
	}
	_, revision, err := hostruntime.MarshalPrivateOverlay(
		request.PrivateOverlay,
	)
	if err != nil || revision != request.PrivateOverlayRevision {
		return false
	}
	payloadCount := boolCount(
		request.Prove != nil,
		request.Stage != nil,
		request.Invoke != nil,
	)
	if payloadCount != 1 {
		return false
	}
	switch request.Action {
	case ProtocolProveTarget:
		return request.Prove != nil &&
			request.TargetProofDigest == ""
	case ProtocolStageRelease:
		if request.Stage == nil ||
			!validTargetProof(
				request.Stage.TargetProof,
				request.PrivateOverlay,
				request.PrivateOverlayRevision,
			) ||
			request.TargetProofDigest !=
				request.Stage.TargetProof.ProofDigest {
			return false
		}
		_, digest, marshalErr := hostruntime.MarshalRuntimeManifest(
			request.Stage.Manifest,
		)
		return marshalErr == nil &&
			digest == request.Stage.ManifestDigest &&
			digest == request.PrivateOverlay.Manifest.Digest
	case ProtocolInvoke:
		if request.Invoke == nil ||
			!validTargetProof(
				request.Invoke.TargetProof,
				request.PrivateOverlay,
				request.PrivateOverlayRevision,
			) ||
			request.TargetProofDigest !=
				request.Invoke.TargetProof.ProofDigest {
			return false
		}
		action, ok := parseHostAction(request.Invoke.Action)
		return ok && validInvokeArguments(
			action,
			request.Invoke.Arguments,
			request.PrivateOverlay,
			request.TargetProofDigest,
		)
	default:
		return false
	}
}

func responseFor(request Request) Response {
	return Response{
		SchemaVersion:          protocolSchemaVersion,
		Action:                 request.Action,
		RequestDigest:          request.RequestDigest,
		PrivateOverlayRevision: request.PrivateOverlayRevision,
		TargetProofDigest:      request.TargetProofDigest,
	}
}

func sealResponse(
	response Response,
	request Request,
) (Response, error) {
	response.ResponseDigest = ""
	if !validResponseAgainstRequest(response, request, false) {
		return Response{}, ErrProtocol
	}
	document, err := json.Marshal(response)
	if err != nil || len(document) > MaxDocumentBytes {
		return Response{}, ErrProtocol
	}
	response.ResponseDigest = digestArtifact(responseDigestDomain, document)
	if !validResponse(response, request) {
		return Response{}, ErrProtocol
	}
	return response, nil
}

func validResponse(response Response, request Request) bool {
	if !validResponseAgainstRequest(response, request, true) {
		return false
	}
	digest := response.ResponseDigest
	response.ResponseDigest = ""
	document, err := json.Marshal(response)
	return err == nil &&
		len(document) <= MaxDocumentBytes &&
		digest == digestArtifact(responseDigestDomain, document)
}

func validResponseAgainstRequest(
	response Response,
	request Request,
	requireDigest bool,
) bool {
	if !validRequest(request) ||
		response.SchemaVersion != protocolSchemaVersion ||
		response.Action != request.Action ||
		response.RequestDigest != request.RequestDigest ||
		response.PrivateOverlayRevision !=
			request.PrivateOverlayRevision ||
		requireDigest && !lowerHexDigest(response.ResponseDigest) ||
		!requireDigest && response.ResponseDigest != "" ||
		boolCount(
			response.Target != nil,
			response.Stage != nil,
			response.Invoke != nil,
		) != 1 {
		return false
	}
	switch request.Action {
	case ProtocolProveTarget:
		return response.Target != nil &&
			validTargetProof(
				*response.Target,
				request.PrivateOverlay,
				request.PrivateOverlayRevision,
			) &&
			response.TargetProofDigest == response.Target.ProofDigest
	case ProtocolStageRelease:
		if response.Stage == nil ||
			response.TargetProofDigest != request.TargetProofDigest {
			return false
		}
		sealed, err := cli.SealStageProof(*response.Stage)
		return err == nil &&
			reflect.DeepEqual(sealed, *response.Stage) &&
			response.Stage.TargetProofDigest ==
				request.TargetProofDigest &&
			response.Stage.PrivateOverlayRevision ==
				request.PrivateOverlayRevision &&
			response.Stage.ManifestDigest ==
				request.Stage.ManifestDigest
	case ProtocolInvoke:
		if response.Invoke == nil ||
			response.TargetProofDigest != request.TargetProofDigest ||
			response.Invoke.Status != hostruntime.HostActionComplete ||
			response.Invoke.TargetProofDigest == nil ||
			*response.Invoke.TargetProofDigest !=
				request.TargetProofDigest {
			return false
		}
		_, _, err := hostruntime.MarshalHostActionResult(*response.Invoke)
		return err == nil
	default:
		return false
	}
}

func validTargetProof(
	proof cli.TargetProof,
	overlay hostruntime.PrivateOverlay,
	revision string,
) bool {
	sealed, err := cli.SealTargetProof(proof)
	return err == nil &&
		reflect.DeepEqual(sealed, proof) &&
		proof.PrivateOverlayRevision == revision &&
		proof.HostIdentityDigest == overlay.Target.HostIdentityDigest &&
		proof.ControlIdentityDigest ==
			overlay.Target.ControlHostIdentityDigest &&
		proof.OS == overlay.Target.OS &&
		proof.Architecture == overlay.Target.Architecture &&
		proof.ExpectedEUID == overlay.Target.ExpectedEUID
}

func validInvokeArguments(
	action cli.HostAction,
	arguments InvokeArguments,
	overlay hostruntime.PrivateOverlay,
	targetProofDigest string,
) bool {
	if arguments.ManifestDigest != overlay.Manifest.Digest ||
		arguments.TargetProofDigest != targetProofDigest ||
		!lowerHexDigest(arguments.ManifestDigest) ||
		!lowerHexDigest(arguments.TargetProofDigest) {
		return false
	}
	switch action {
	case cli.ActionInstall:
		return arguments.Acquisition == "disabled" &&
			arguments.DrainPolicy == "" &&
			arguments.HostedConfirmation == "" &&
			!arguments.RequireZero &&
			lowerHexDigest(arguments.StageProofDigest)
	case cli.ActionVerify:
		return arguments.Acquisition == "" &&
			arguments.DrainPolicy == "" &&
			arguments.HostedConfirmation == "" &&
			arguments.RequireZero &&
			arguments.StageProofDigest == ""
	case cli.ActionSuspend:
		return arguments.Acquisition == "" &&
			(arguments.DrainPolicy == "wait" ||
				arguments.DrainPolicy == "cancel") &&
			canonicalPath(arguments.HostedConfirmation) &&
			arguments.RequireZero &&
			arguments.StageProofDigest == ""
	case cli.ActionResume:
		return arguments.Acquisition == "disabled" &&
			arguments.DrainPolicy == "" &&
			arguments.HostedConfirmation == "" &&
			!arguments.RequireZero &&
			arguments.StageProofDigest == ""
	default:
		return false
	}
}

func hostActionName(action cli.HostAction) (string, bool) {
	switch action {
	case cli.ActionInstall:
		return "install", true
	case cli.ActionVerify:
		return "verify", true
	case cli.ActionSuspend:
		return "suspend", true
	case cli.ActionResume:
		return "resume", true
	default:
		return "", false
	}
}

func parseHostAction(value string) (cli.HostAction, bool) {
	switch value {
	case "install":
		return cli.ActionInstall, true
	case "verify":
		return cli.ActionVerify, true
	case "suspend":
		return cli.ActionSuspend, true
	case "resume":
		return cli.ActionResume, true
	default:
		return 0, false
	}
}

func marshalFrame(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil ||
		len(document) == 0 ||
		len(document) > MaxDocumentBytes {
		return nil, ErrProtocol
	}
	return append(document, '\n'), nil
}

func frameDocument(wire []byte) ([]byte, bool) {
	if len(wire) < 2 ||
		len(wire) > MaxWireBytes ||
		wire[len(wire)-1] != '\n' ||
		bytes.Contains(wire[:len(wire)-1], []byte{'\n'}) ||
		len(wire[:len(wire)-1]) > MaxDocumentBytes {
		return nil, false
	}
	return wire[:len(wire)-1], true
}

func decodeClosed(document []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func digestArtifact(domain string, document []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(document)
	return hex.EncodeToString(hasher.Sum(nil))
}

func lowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func canonicalPath(value string) bool {
	return filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		!strings.ContainsRune(value, 0)
}

func writeFull(writer io.Writer, data []byte) bool {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if count < 0 || count > len(data) ||
			err != nil ||
			count == 0 {
			return false
		}
		data = data[count:]
	}
	return true
}
