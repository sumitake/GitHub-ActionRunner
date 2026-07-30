package main

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestParseCgroupLayoutV2(t *testing.T) {
	t.Parallel()

	got, err := parseCgroupLayout(
		[]byte(observerFixture("{v2}/portable/runner\n")),
		[]byte(
			observerFixture(
				"36 25 {dev32} / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime ",
			)+
				"- cgroup2 cgroup rw\n",
		),
	)
	if err != nil {
		t.Fatalf("parseCgroupLayout() error = %v", err)
	}
	want := cgroupLayout{
		version:     task11synthetic.CgroupV2,
		unifiedPath: "/sys/fs/cgroup/portable/runner",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("layout = %#v, want %#v", got, want)
	}
}

func TestParseCgroupLayoutV1SeparateAndComounted(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cgroup    string
		mountinfo string
		want      cgroupLayout
	}{
		"separate": {
			cgroup: "8:cpu,cpuacct:/portable/runner\n" +
				"7:memory:/portable/runner\n" +
				"6:pids:/portable/runner\n",
			mountinfo: observerFixture(
				"31 25 {dev31} / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct\n" +
					"32 25 {dev32} /portable /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
					"33 25 {dev33} / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n",
			),
			want: cgroupLayout{
				version:    task11synthetic.CgroupV1,
				memoryPath: "/sys/fs/cgroup/memory/runner",
				pidsPath:   "/sys/fs/cgroup/pids/portable/runner",
			},
		},
		"co-mounted": {
			cgroup: "7:memory,pids:/portable/runner\n",
			mountinfo: observerFixture(
				"32 25 {dev32} / /sys/fs/cgroup/memory-pids rw ",
			) + "- cgroup cgroup rw,memory,pids\n",
			want: cgroupLayout{
				version:    task11synthetic.CgroupV1,
				memoryPath: "/sys/fs/cgroup/memory-pids/portable/runner",
				pidsPath:   "/sys/fs/cgroup/memory-pids/portable/runner",
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseCgroupLayout(
				[]byte(test.cgroup),
				[]byte(test.mountinfo),
			)
			if err != nil {
				t.Fatalf("parseCgroupLayout() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("layout = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseCgroupLayoutRejectsAmbiguity(t *testing.T) {
	t.Parallel()

	validV2Cgroup := []byte(observerFixture("{v2}/portable/runner\n"))
	validV2Mount := []byte(
		observerFixture(
			"36 25 {dev32} / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
		),
	)
	tests := map[string]struct {
		cgroup    []byte
		mountinfo []byte
	}{
		"hybrid membership": {
			cgroup: []byte(
				observerFixture("{v2}/portable/runner\n") +
					"7:memory:/portable/runner\n" +
					"6:pids:/portable/runner\n",
			),
			mountinfo: []byte(
				string(validV2Mount) +
					observerFixture(
						"37 25 {dev33} / /sys/fs/cgroup/memory rw ",
					) +
					"- cgroup cgroup rw,memory\n" +
					observerFixture(
						"38 25 {dev34} / /sys/fs/cgroup/pids rw ",
					) +
					"- cgroup cgroup rw,pids\n",
			),
		},
		"duplicate unified mount": {
			cgroup: validV2Cgroup,
			mountinfo: []byte(
				string(validV2Mount) +
					observerFixture(
						"37 25 {dev33} / /other rw - cgroup2 cgroup rw\n",
					),
			),
		},
		"duplicate memory membership": {
			cgroup: []byte(
				"7:memory:/portable/runner\n" +
					"6:memory:/portable/runner\n" +
					"5:pids:/portable/runner\n",
			),
			mountinfo: []byte(
				observerFixture(
					"37 25 {dev33} / /sys/fs/cgroup/memory rw ",
				) +
					"- cgroup cgroup rw,memory\n" +
					observerFixture(
						"38 25 {dev34} / /sys/fs/cgroup/pids rw ",
					) +
					"- cgroup cgroup rw,pids\n",
			),
		},
		"unrelated co-mount": {
			cgroup: []byte(
				"7:memory,cpu:/portable/runner\n" +
					"5:pids:/portable/runner\n",
			),
			mountinfo: []byte(
				observerFixture(
					"37 25 {dev33} / /sys/fs/cgroup/memory rw ",
				) +
					"- cgroup cgroup rw,memory,cpu\n" +
					observerFixture(
						"38 25 {dev34} / /sys/fs/cgroup/pids rw ",
					) +
					"- cgroup cgroup rw,pids\n",
			),
		},
		"traversal": {
			cgroup: []byte(
				observerFixture("{v2}/portable/../runner\n"),
			),
			mountinfo: validV2Mount,
		},
		"noncanonical mountinfo spacing": {
			cgroup: validV2Cgroup,
			mountinfo: []byte(
				observerFixture(
					"36  25 {dev32} / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
				),
			),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCgroupLayout(
				test.cgroup,
				test.mountinfo,
			); err == nil {
				t.Fatal("parseCgroupLayout accepted ambiguous layout")
			}
		})
	}
}

func observerFixture(document string) string {
	return strings.NewReplacer(
		"{v2}",
		strconv.Itoa(0)+":"+":",
		"{dev31}",
		strconv.Itoa(0)+":"+strconv.Itoa(31),
		"{dev32}",
		strconv.Itoa(0)+":"+strconv.Itoa(32),
		"{dev33}",
		strconv.Itoa(0)+":"+strconv.Itoa(33),
		"{dev34}",
		strconv.Itoa(0)+":"+strconv.Itoa(34),
	).Replace(document)
}

func TestParseCanonicalUint64Document(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		document string
		want     uint64
		valid    bool
	}{
		"zero":     {document: "0\n", valid: true},
		"positive": {document: "18446744073709551615\n", want: ^uint64(0), valid: true},
		"leading zero": {
			document: "01\n",
		},
		"missing LF": {
			document: "1",
		},
		"overflow": {
			document: "18446744073709551616\n",
		},
		"space": {
			document: "1 \n",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseCanonicalUint64Document(
				[]byte(test.document),
			)
			if test.valid {
				if err != nil || got != test.want {
					t.Fatalf("parse = %d, %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("parse accepted %q", test.document)
			}
		})
	}
}

func TestParseCanonicalPIDDocument(t *testing.T) {
	t.Parallel()

	got, err := parseCanonicalPIDDocument([]byte("9\n2\n17\n"))
	if err != nil || !reflect.DeepEqual(got, []uint64{9, 2, 17}) {
		t.Fatalf("parse = %#v, %v", got, err)
	}
	for _, document := range []string{
		"",
		"1",
		"0\n",
		"01\n",
		"1\n1\n",
		"1\n\n",
	} {
		if _, err := parseCanonicalPIDDocument(
			[]byte(document),
		); err == nil {
			t.Fatalf("parse accepted %q", document)
		}
	}
}

func TestParseV1MemorySampleRequiresStablePair(t *testing.T) {
	t.Parallel()

	memory, swap, err := parseV1MemorySample(
		[]byte("120\n"),
		[]byte("100\n"),
		[]byte("130\n"),
		[]byte("100\n"),
		[]byte("130\n"),
	)
	if err != nil || memory != 120 || swap != 30 {
		t.Fatalf("sample = %d, %d, %v", memory, swap, err)
	}
	tests := [][][]byte{
		{
			[]byte("120\n"),
			[]byte("100\n"),
			[]byte("130\n"),
			[]byte("101\n"),
			[]byte("130\n"),
		},
		{
			[]byte("120\n"),
			[]byte("100\n"),
			[]byte("130\n"),
			[]byte("100\n"),
			[]byte("131\n"),
		},
		{
			[]byte("120\n"),
			[]byte("131\n"),
			[]byte("130\n"),
			[]byte("131\n"),
			[]byte("130\n"),
		},
	}
	for _, documents := range tests {
		if _, _, err := parseV1MemorySample(
			documents[0],
			documents[1],
			documents[2],
			documents[3],
			documents[4],
		); err == nil {
			t.Fatal("parseV1MemorySample accepted unstable sample")
		}
	}
}

func TestHighWaterObserverEnforcesOrderAndVector(t *testing.T) {
	t.Parallel()

	samples := []listenerMeasurement{
		{
			memoryBytes:      10,
			swapBytes:        1,
			runnerTmpfsBytes: 3,
			tmpBytes:         4,
			scratchBytes:     5,
			containers:       1,
			processes:        2,
			fileDescriptors:  8,
			namespaces:       4,
			conntrackRows:    1,
			inodes:           6,
		},
		{
			memoryBytes:      20,
			swapBytes:        0,
			runnerTmpfsBytes: 2,
			tmpBytes:         8,
			scratchBytes:     3,
			containers:       1,
			processes:        3,
			fileDescriptors:  7,
			namespaces:       5,
			conntrackRows:    2,
			inodes:           9,
		},
	}
	index := 0
	observer := newHighWaterObserver(
		task11synthetic.CgroupV2,
		func() (listenerMeasurement, error) {
			if index >= len(samples) {
				return listenerMeasurement{}, errors.New("extra sample")
			}
			result := samples[index]
			index++
			return result, nil
		},
	)
	if observer.Sample(observationListenerEntry) != nil ||
		observer.Sample(observationBeforeTerminal) != nil {
		t.Fatal("valid samples failed")
	}
	vector, err := observer.HighWater()
	if err != nil {
		t.Fatalf("HighWater() error = %v", err)
	}
	want := []task11synthetic.ResourceHighWater{
		{Resource: task11synthetic.ResourceMemoryBytes, HighWater: 20},
		{Resource: task11synthetic.ResourceSwapBytes, HighWater: 1},
		{Resource: task11synthetic.ResourceRunnerTmpfsBytes, HighWater: 3},
		{Resource: task11synthetic.ResourceTmpBytes, HighWater: 8},
		{Resource: task11synthetic.ResourceScratchBytes, HighWater: 5},
		{Resource: task11synthetic.ResourceContainers, HighWater: 1},
		{Resource: task11synthetic.ResourceProcesses, HighWater: 3},
		{Resource: task11synthetic.ResourceFileDescriptors, HighWater: 8},
		{Resource: task11synthetic.ResourceNamespaces, HighWater: 5},
		{Resource: task11synthetic.ResourceConntrackRows, HighWater: 2},
		{Resource: task11synthetic.ResourceInodes, HighWater: 9},
	}
	if !reflect.DeepEqual(vector, want) {
		t.Fatalf("vector = %#v, want %#v", vector, want)
	}
	if observer.Sample(observationProxyComplete) == nil {
		t.Fatal("observer accepted an event after before-terminal")
	}
}

func TestHighWaterObserverRejectsInvalidSample(t *testing.T) {
	t.Parallel()

	observer := newHighWaterObserver(
		task11synthetic.CgroupV2,
		func() (listenerMeasurement, error) {
			return listenerMeasurement{containers: 2}, nil
		},
	)
	if observer.Sample(observationListenerEntry) == nil {
		t.Fatal("observer accepted non-single-container sample")
	}
	if _, err := observer.HighWater(); err == nil {
		t.Fatal("HighWater accepted failed observer")
	}
}
