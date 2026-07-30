package testenv

import (
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestParseTask11SyntheticStructuralInspectIsClosed(t *testing.T) {
	t.Parallel()

	id := strings.Repeat("a", 64)
	image := strings.Repeat("b", 64)
	document := []byte(
		`{"id":"` + id +
			`","name":"/pghar-runner-example","image":"sha256:` +
			image +
			`","running":true,"pid":701,"sandbox_key":"/run/docker/netns/example","mounts":[],"tmpfs":{"/runner":"rw,size=1","/tmp":"rw,size=1"}}` +
			"\n",
	)
	observation, err := parseTask11SyntheticStructuralInspect(document)
	if err != nil {
		t.Fatalf("parse structural inspect: %v", err)
	}
	if observation.ID != id ||
		observation.ImageID != image ||
		observation.Name != "pghar-runner-example" ||
		!observation.Running ||
		observation.PID != 701 ||
		observation.SandboxKey != "/run/docker/netns/example" ||
		len(observation.Mounts) != 0 ||
		len(observation.Tmpfs) != 2 {
		t.Fatalf("observation = %+v", observation)
	}

	mutations := map[string][]byte{
		"missing lf": document[:len(document)-1],
		"unknown": []byte(
			strings.TrimSuffix(string(document), "}\n") +
				`,"unknown":true}` + "\n",
		),
		"relative sandbox": []byte(strings.Replace(
			string(document),
			`"/run/docker/netns/example"`,
			`"relative"`,
			1,
		)),
		"tag image": []byte(strings.Replace(
			string(document),
			`"sha256:`+image+`"`,
			`"runner:latest"`,
			1,
		)),
		"zero pid running": []byte(strings.Replace(
			string(document),
			`"pid":701`,
			`"pid":0`,
			1,
		)),
	}
	for name, candidate := range mutations {
		name, candidate := name, candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseTask11SyntheticStructuralInspect(
				candidate,
			); err == nil {
				t.Fatal("invalid inspect was accepted")
			}
		})
	}
}

func TestTask11SyntheticCgroupPathsResolveV2AndV1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		version   task11synthetic.CgroupVersion
		cgroup    string
		mountinfo string
		want      []string
	}{
		{
			name:      "v2",
			version:   task11synthetic.CgroupV2,
			cgroup:    "0::/system.slice/docker-example.scope\n",
			mountinfo: "29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n",
			want: []string{
				"/sys/fs/cgroup/system.slice/docker-example.scope",
			},
		},
		{
			name:    "v1 distinct",
			version: task11synthetic.CgroupV1,
			cgroup: "7:memory:/docker/example\n" +
				"5:pids:/docker/example\n",
			mountinfo: "31 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
				"32 23 0:29 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n",
			want: []string{
				"/sys/fs/cgroup/memory/docker/example",
				"/sys/fs/cgroup/pids/docker/example",
			},
		},
		{
			name:      "v1 co-mounted",
			version:   task11synthetic.CgroupV1,
			cgroup:    "7:memory,pids:/docker/example\n",
			mountinfo: "31 23 0:28 / /sys/fs/cgroup/memory-pids rw - cgroup cgroup rw,memory,pids\n",
			want: []string{
				"/sys/fs/cgroup/memory-pids/docker/example",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := task11SyntheticCgroupPaths(
				[]byte(test.cgroup),
				[]byte(test.mountinfo),
				test.version,
			)
			if err != nil {
				t.Fatalf("task11SyntheticCgroupPaths: %v", err)
			}
			if strings.Join(got, "\n") !=
				strings.Join(test.want, "\n") {
				t.Fatalf("paths = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTask11SyntheticCgroupPathsRejectAmbiguity(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		version   task11synthetic.CgroupVersion
		cgroup    string
		mountinfo string
	}{
		"missing v2": {
			version:   task11synthetic.CgroupV2,
			cgroup:    "7:memory:/docker/example\n",
			mountinfo: "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
		},
		"v2 root": {
			version:   task11synthetic.CgroupV2,
			cgroup:    "0::/\n",
			mountinfo: "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
		},
		"missing pids": {
			version:   task11synthetic.CgroupV1,
			cgroup:    "7:memory:/docker/example\n",
			mountinfo: "31 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
		},
		"duplicate memory mount": {
			version: task11synthetic.CgroupV1,
			cgroup: "7:memory:/docker/example\n" +
				"5:pids:/docker/example\n",
			mountinfo: "31 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n" +
				"32 23 0:29 / /sys/fs/cgroup/also-memory rw - cgroup cgroup rw,memory\n" +
				"33 23 0:30 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n",
		},
		"escaped traversal": {
			version:   task11synthetic.CgroupV2,
			cgroup:    "0::/system.slice/docker-example.scope\n",
			mountinfo: "29 23 0:26 / /sys/fs/cgroup\\057escape rw - cgroup2 cgroup rw\n",
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := task11SyntheticCgroupPaths(
				[]byte(test.cgroup),
				[]byte(test.mountinfo),
				test.version,
			); !errors.Is(err, ErrFixtureStart) {
				t.Fatalf("ambiguity error = %v", err)
			}
		})
	}
}

func TestParseTask11SyntheticCgroupMembersIsBoundedAndCanonical(
	t *testing.T,
) {
	t.Parallel()

	got, err := parseTask11SyntheticCgroupMembers(
		[]byte("701\n702\n"),
		2,
	)
	if err != nil || len(got) != 2 || got[0] != 701 || got[1] != 702 {
		t.Fatalf("members = %v, error = %v", got, err)
	}
	for _, document := range [][]byte{
		[]byte(""),
		[]byte("701"),
		[]byte("0701\n"),
		[]byte("701\n701\n"),
		[]byte("702\n701\n"),
		[]byte("701\n702\n703\n"),
	} {
		if _, err := parseTask11SyntheticCgroupMembers(
			document,
			2,
		); !errors.Is(err, ErrFixtureStart) {
			t.Fatalf("invalid members %q error = %v", document, err)
		}
	}
}
