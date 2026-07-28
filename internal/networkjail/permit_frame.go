package networkjail

import (
	"encoding/binary"
	"errors"
)

const (
	dialPermitRequestVersion     = 1
	dialPermitRequestFrameBytes  = 22
	dialPermitResponseVersion    = 1
	dialPermitResponseFrameBytes = 40
)

var dialPermitResponseMagic = [8]byte{'P', 'G', 'H', 'P', 'R', 'M', 'T', '1'}

type CapacitySlotID uint32
type JobGeneration uint64
type PermitSequence uint64

// DialPermitRequest is the complete client-controlled authority request. Time,
// boot identity, refill state, token counts, and permit counters are
// deliberately absent; the controller-owned authority supplies all of them.
type DialPermitRequest struct {
	SlotID        CapacitySlotID
	JobGeneration JobGeneration
	Class         DialClass
	Sequence      PermitSequence
}

func (request DialPermitRequest) MarshalBinary() ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	frame := make([]byte, dialPermitRequestFrameBytes)
	frame[0] = dialPermitRequestVersion
	binary.BigEndian.PutUint32(frame[1:5], uint32(request.SlotID))
	binary.BigEndian.PutUint64(frame[5:13], uint64(request.JobGeneration))
	frame[13] = byte(request.Class)
	binary.BigEndian.PutUint64(frame[14:22], uint64(request.Sequence))
	return frame, nil
}

func ParseDialPermitRequest(frame []byte) (DialPermitRequest, error) {
	if len(frame) != dialPermitRequestFrameBytes ||
		frame[0] != dialPermitRequestVersion {
		return DialPermitRequest{}, errors.New("networkjail: permit request frame invalid")
	}
	request := DialPermitRequest{
		SlotID:        CapacitySlotID(binary.BigEndian.Uint32(frame[1:5])),
		JobGeneration: JobGeneration(binary.BigEndian.Uint64(frame[5:13])),
		Class:         DialClass(frame[13]),
		Sequence:      PermitSequence(binary.BigEndian.Uint64(frame[14:22])),
	}
	if err := request.validate(); err != nil {
		return DialPermitRequest{}, err
	}
	return request, nil
}

func (request DialPermitRequest) validate() error {
	if request.SlotID == 0 || request.JobGeneration == 0 ||
		request.Sequence == 0 ||
		(request.Class != DialClassJob && request.Class != DialClassDoH) {
		return errors.New("networkjail: permit request invalid")
	}
	return nil
}

func marshalDialPermitResponse(
	request DialPermitRequest,
	permit Permit,
) ([]byte, error) {
	if err := request.validate(); err != nil ||
		!permit.validFor(request.SlotID, request.Class) {
		return nil, errors.New("networkjail: permit response invalid")
	}
	frame := make([]byte, dialPermitResponseFrameBytes)
	copy(frame[:8], dialPermitResponseMagic[:])
	frame[8] = dialPermitResponseVersion
	frame[9] = byte(request.Class)
	binary.BigEndian.PutUint32(frame[12:16], uint32(request.SlotID))
	binary.BigEndian.PutUint64(frame[16:24], uint64(request.JobGeneration))
	binary.BigEndian.PutUint64(frame[24:32], uint64(request.Sequence))
	binary.BigEndian.PutUint64(frame[32:40], permit.number)
	return frame, nil
}

func parseDialPermitResponse(
	frame []byte,
	request DialPermitRequest,
) (Permit, error) {
	if err := request.validate(); err != nil ||
		len(frame) != dialPermitResponseFrameBytes ||
		string(frame[:8]) != string(dialPermitResponseMagic[:]) ||
		frame[8] != dialPermitResponseVersion ||
		frame[9] != byte(request.Class) ||
		frame[10] != 0 || frame[11] != 0 ||
		CapacitySlotID(binary.BigEndian.Uint32(frame[12:16])) != request.SlotID ||
		JobGeneration(binary.BigEndian.Uint64(frame[16:24])) != request.JobGeneration ||
		PermitSequence(binary.BigEndian.Uint64(frame[24:32])) != request.Sequence {
		return Permit{}, errors.New("networkjail: permit response invalid")
	}
	permit := Permit{
		slot:   request.SlotID,
		class:  request.Class,
		number: binary.BigEndian.Uint64(frame[32:40]),
	}
	if !permit.validFor(request.SlotID, request.Class) {
		return Permit{}, errors.New("networkjail: permit response invalid")
	}
	return permit, nil
}
