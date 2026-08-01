package main

import "testing"

func TestCountSocketRowsAcceptsOnlyCanonicalProcSocketTables(t *testing.T) {
	empty := []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
	)
	count, err := countSocketRows(empty)
	if err != nil || count != 0 {
		t.Fatalf("countSocketRows(empty)=(%d,%v)", count, err)
	}
	one := append(
		append([]byte{}, empty...),
		[]byte("   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n")...,
	)
	count, err = countSocketRows(one)
	if err != nil || count != 1 {
		t.Fatalf("countSocketRows(one)=(%d,%v)", count, err)
	}
	for name, document := range map[string][]byte{
		"missing header": {},
		"bad header":     []byte("untrusted\n"),
		"bad row": append(
			append([]byte{}, empty...),
			[]byte("untrusted\n")...,
		),
		"no newline": empty[:len(empty)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := countSocketRows(document); err == nil {
				t.Fatal("countSocketRows accepted invalid table")
			}
		})
	}
}
