package networkjail

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	ParserControlFD     = 3
	ParserFilterVersion = 1
	ParserSocketErrno   = 1
	maxParserProofBytes = 4096
)

var parserPolicyMagic = [8]byte{'P', 'G', 'H', 'P', 'C', 'F', 'G', '1'}

type ParserReadiness struct {
	Version       uint8  `json:"version"`
	ControlFD     uint32 `json:"control_fd"`
	FilterVersion uint32 `json:"filter_version"`
	FilterTSYNC   bool   `json:"filter_tsync"`
	AFINETErrno   uint32 `json:"af_inet_errno"`
	AFINET6Errno  uint32 `json:"af_inet6_errno"`
	UnexpectedFDs uint32 `json:"unexpected_fds"`
	TaskCount     uint32 `json:"task_count"`
	TasksVerified uint32 `json:"tasks_verified"`
}

func WriteParserPolicy(writer io.Writer, document []byte) error {
	if writer == nil || len(document) == 0 || len(document) > maxDecisionGraphBytes {
		return errors.New("networkjail: parser policy unavailable")
	}
	frame := make([]byte, 12+len(document))
	copy(frame[:8], parserPolicyMagic[:])
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(document)))
	copy(frame[12:], document)
	err := writeAll(writer, frame)
	zeroBytes(frame)
	return err
}

func ReadParserPolicy(reader io.Reader) ([]byte, error) {
	var header [12]byte
	if reader == nil {
		return nil, errors.New("networkjail: parser policy unavailable")
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil ||
		!bytes.Equal(header[:8], parserPolicyMagic[:]) {
		return nil, errors.New("networkjail: parser policy header invalid")
	}
	length := int(binary.BigEndian.Uint32(header[8:12]))
	if length <= 0 || length > maxDecisionGraphBytes {
		return nil, errors.New("networkjail: parser policy length invalid")
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(reader, document); err != nil {
		zeroBytes(document)
		return nil, errors.New("networkjail: parser policy body invalid")
	}
	return document, nil
}

func WriteParserReadiness(writer io.Writer, proof ParserReadiness) error {
	if err := validateParserReadiness(proof); err != nil {
		return err
	}
	document, err := json.Marshal(proof)
	if err != nil || len(document)+1 > maxParserProofBytes {
		return errors.New("networkjail: parser readiness encoding failed")
	}
	document = append(document, '\n')
	err = writeAll(writer, document)
	zeroBytes(document)
	return err
}

func ReadParserReadiness(reader io.Reader) (ParserReadiness, error) {
	if reader == nil {
		return ParserReadiness{}, errors.New("networkjail: parser readiness unavailable")
	}
	document, err := readLineBounded(reader, maxParserProofBytes)
	if err != nil {
		return ParserReadiness{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var proof ParserReadiness
	if err := decoder.Decode(&proof); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		validateParserReadiness(proof) != nil {
		zeroBytes(document)
		return ParserReadiness{}, errors.New("networkjail: parser readiness invalid")
	}
	canonical, _ := json.Marshal(proof)
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, document) {
		zeroBytes(document)
		zeroBytes(canonical)
		return ParserReadiness{}, errors.New("networkjail: parser readiness noncanonical")
	}
	zeroBytes(document)
	zeroBytes(canonical)
	return proof, nil
}

func validateParserReadiness(proof ParserReadiness) error {
	if proof.Version != 1 ||
		proof.ControlFD != ParserControlFD ||
		proof.FilterVersion != ParserFilterVersion ||
		!proof.FilterTSYNC ||
		proof.AFINETErrno != ParserSocketErrno ||
		proof.AFINET6Errno != ParserSocketErrno ||
		proof.UnexpectedFDs != 0 ||
		proof.TaskCount == 0 ||
		proof.TasksVerified != proof.TaskCount {
		return errors.New("networkjail: parser readiness fields invalid")
	}
	return nil
}

func readLineBounded(reader io.Reader, maximum int) ([]byte, error) {
	document := make([]byte, 0, maximum)
	var one [1]byte
	for len(document) < maximum {
		count, err := reader.Read(one[:])
		if count == 1 {
			document = append(document, one[0])
			if one[0] == '\n' {
				return document, nil
			}
		}
		if err != nil {
			zeroBytes(document)
			return nil, errors.New("networkjail: bounded line incomplete")
		}
		if count == 0 {
			zeroBytes(document)
			return nil, errors.New("networkjail: bounded line stalled")
		}
	}
	zeroBytes(document)
	return nil, errors.New("networkjail: bounded line too large")
}

func writeAll(writer io.Writer, document []byte) error {
	written := 0
	for written < len(document) {
		count, err := writer.Write(document[written:])
		if err != nil || count <= 0 {
			return errors.New("networkjail: bounded write failed")
		}
		written += count
	}
	return nil
}
