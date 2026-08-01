package networkjail

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
)

type Budget struct {
	NFConntrackMax   uint64
	NFConntrackCount uint64
	TailTimeoutID    string
}

type ConntrackBudget struct {
	JobClassEntries     uint64
	DoHClassEntries     uint64
	PerRunnerEntries    uint64
	FleetEntries        uint64
	RequiredWithReserve uint64
	AvailableEntries    uint64
	Digest              Digest
}

func (b Budget) Compute(
	manifest PolicyManifest,
	maxRunnerCapacity uint64,
) (ConntrackBudget, error) {
	if b.NFConntrackMax == 0 || b.TailTimeoutID == "" ||
		b.NFConntrackCount > b.NFConntrackMax || maxRunnerCapacity == 0 ||
		manifest.HostReserveEntries >= b.NFConntrackMax {
		return ConntrackBudget{}, errors.New("networkjail: conntrack inputs unavailable")
	}
	job, err := computeClassBudget(
		manifest.ConntrackEntriesPerActualDial,
		manifest.JobOpenCap,
		manifest.JobDialBurst,
		manifest.JobDialRate,
		manifest.TailTimeoutSeconds,
	)
	if err != nil {
		return ConntrackBudget{}, err
	}
	doh, err := computeClassBudget(
		manifest.ConntrackEntriesPerActualDial,
		manifest.DoHOpenCap,
		manifest.DoHDialBurst,
		manifest.DoHDialRate,
		manifest.TailTimeoutSeconds,
	)
	if err != nil {
		return ConntrackBudget{}, err
	}
	perRunner, ok := checkedAdd64(job, doh)
	if !ok {
		return ConntrackBudget{}, errors.New("networkjail: conntrack arithmetic overflow")
	}
	fleet, ok := checkedMultiply64(perRunner, maxRunnerCapacity)
	if !ok {
		return ConntrackBudget{}, errors.New("networkjail: conntrack arithmetic overflow")
	}
	required, ok := checkedAdd64(fleet, manifest.HostReserveEntries)
	if !ok {
		return ConntrackBudget{}, errors.New("networkjail: conntrack arithmetic overflow")
	}
	available := b.NFConntrackMax - b.NFConntrackCount
	if required > available {
		return ConntrackBudget{}, errors.New("networkjail: conntrack headroom unavailable")
	}
	result := ConntrackBudget{
		JobClassEntries:     job,
		DoHClassEntries:     doh,
		PerRunnerEntries:    perRunner,
		FleetEntries:        fleet,
		RequiredWithReserve: required,
		AvailableEntries:    available,
	}
	result.Digest = digestBudget(b, manifest, maxRunnerCapacity, result)
	return result, nil
}

func computeClassBudget(
	factor, openCap, burst, rate, tailSeconds uint64,
) (uint64, error) {
	twiceOpen, ok := checkedMultiply64(openCap, 2)
	if !ok {
		return 0, errors.New("networkjail: conntrack arithmetic overflow")
	}
	rateTail, ok := checkedMultiply64(rate, tailSeconds)
	if !ok {
		return 0, errors.New("networkjail: conntrack arithmetic overflow")
	}
	total, ok := checkedAdd64(twiceOpen, burst)
	if !ok {
		return 0, errors.New("networkjail: conntrack arithmetic overflow")
	}
	total, ok = checkedAdd64(total, rateTail)
	if !ok {
		return 0, errors.New("networkjail: conntrack arithmetic overflow")
	}
	total, ok = checkedMultiply64(factor, total)
	if !ok {
		return 0, errors.New("networkjail: conntrack arithmetic overflow")
	}
	return total, nil
}

func checkedAdd64(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}

func checkedMultiply64(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func digestBudget(
	input Budget,
	manifest PolicyManifest,
	capacity uint64,
	result ConntrackBudget,
) Digest {
	var buffer bytes.Buffer
	writePolicyString(&buffer, "portable-ghar.conntrack-budget.v1")
	writePolicyUint64(&buffer, input.NFConntrackMax)
	writePolicyUint64(&buffer, input.NFConntrackCount)
	writePolicyString(&buffer, input.TailTimeoutID)
	writePolicyUint64(&buffer, capacity)
	writePolicyString(&buffer, digestManifest(manifest).String())
	for _, value := range []uint64{
		result.JobClassEntries,
		result.DoHClassEntries,
		result.PerRunnerEntries,
		result.FleetEntries,
		result.RequiredWithReserve,
		result.AvailableEntries,
	} {
		writePolicyUint64(&buffer, value)
	}
	return sha256.Sum256(buffer.Bytes())
}
