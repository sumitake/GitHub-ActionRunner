package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	seccompErrno = "SCMP_ACT_ERRNO"
	seccompAllow = "SCMP_ACT_ALLOW"
	maskedEqual  = "SCMP_CMP_MASKED_EQ"
	equal        = "SCMP_CMP_EQ"
)

var requiredCloneNamespaceFlags = [...]uint64{
	0x00020000, // CLONE_NEWNS
	0x02000000, // CLONE_NEWCGROUP
	0x04000000, // CLONE_NEWUTS
	0x08000000, // CLONE_NEWIPC
	0x10000000, // CLONE_NEWUSER
	0x20000000, // CLONE_NEWPID
	0x40000000, // CLONE_NEWNET
}

type seccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []seccompRule `json:"syscalls"`
}

type seccompRule struct {
	Names    []string     `json:"names"`
	Action   string       `json:"action"`
	ErrnoRet uint32       `json:"errnoRet"`
	Args     []seccompArg `json:"args"`
}

type seccompArg struct {
	Index    uint32 `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

func validateSeccompJSON(data []byte) error {
	if err := rejectDuplicateSeccompFields(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile seccompProfile
	if err := decoder.Decode(&profile); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("hostruntime: seccomp json invalid")
	}
	if profile.DefaultAction != seccompAllow ||
		!equalStrings(profile.Architectures, []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}) ||
		len(profile.Syscalls) == 0 {
		return errors.New("hostruntime: seccomp baseline invalid")
	}

	alwaysDenied := map[string]bool{
		"unshare": false,
		"setns":   false,
		"clone3":  false,
		"bpf":     false,
	}
	cloneDenied := make(map[uint64]bool, len(requiredCloneNamespaceFlags))
	packetSocketDenied := false
	rawSocketDenied := false
	for _, rule := range profile.Syscalls {
		if len(rule.Names) == 0 || rule.Action != seccompErrno || rule.ErrnoRet != 1 {
			return errors.New("hostruntime: seccomp rule action invalid")
		}
		for _, name := range rule.Names {
			if _, protected := alwaysDenied[name]; protected {
				if len(rule.Args) != 0 {
					return errors.New("hostruntime: seccomp unconditional denial weakened")
				}
				alwaysDenied[name] = true
			}
		}
		if len(rule.Names) != 1 {
			continue
		}
		switch rule.Names[0] {
		case "clone":
			if len(rule.Args) != 1 {
				return errors.New("hostruntime: clone denial invalid")
			}
			arg := rule.Args[0]
			if arg.Index != 0 || arg.Op != maskedEqual || arg.Value == 0 || arg.Value != arg.ValueTwo {
				return errors.New("hostruntime: clone denial mask invalid")
			}
			cloneDenied[arg.Value] = true
		case "socket":
			if len(rule.Args) != 1 {
				return errors.New("hostruntime: socket denial invalid")
			}
			arg := rule.Args[0]
			if arg.Index == 0 && arg.Op == equal && arg.Value == 17 && arg.ValueTwo == 0 {
				packetSocketDenied = true
			}
			if arg.Index == 1 && arg.Op == maskedEqual && arg.Value == 0x0f && arg.ValueTwo == 3 {
				rawSocketDenied = true
			}
		}
	}
	for _, denied := range alwaysDenied {
		if !denied {
			return errors.New("hostruntime: required syscall denial missing")
		}
	}
	for _, flag := range requiredCloneNamespaceFlags {
		if !cloneDenied[flag] {
			return errors.New("hostruntime: namespace clone denial missing")
		}
	}
	if !packetSocketDenied || !rawSocketDenied {
		return errors.New("hostruntime: raw socket denial missing")
	}
	return nil
}

func rejectDuplicateSeccompFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanSeccompValue(decoder); err != nil {
		return errors.New("hostruntime: seccomp duplicate or malformed field")
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("hostruntime: seccomp trailing data")
	}
	return nil
}

func scanSeccompValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("hostruntime: seccomp key invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("hostruntime: seccomp key duplicated")
			}
			seen[key] = struct{}{}
			if err := scanSeccompValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("hostruntime: seccomp object invalid")
		}
	case '[':
		for decoder.More() {
			if err := scanSeccompValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("hostruntime: seccomp array invalid")
		}
	default:
		return errors.New("hostruntime: seccomp delimiter invalid")
	}
	return nil
}
