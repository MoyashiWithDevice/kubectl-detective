package throughput

import (
	"net"
	"testing"
	"time"
)

type stubResolver struct{}

func (s stubResolver) Resolve(ip net.IP) string {
	ipStr := ip.String()
	switch ipStr {
	case "10.0.1.1":
		return "frontend"
	case "10.0.1.2":
		return "api"
	case "10.0.1.3":
		return "redis"
	}
	return ipStr
}

func (s stubResolver) Close() {}

func TestTrackerSnapshotAndTopTalkers(t *testing.T) {
	tracker := New()

	tracker.flows[FlowKey{SrcIP: "10.0.1.1", DstIP: "10.0.1.2", SrcPort: 80, DstPort: 8080}] = &FlowStats{TxBytes: 1000, RxBytes: 500}
	tracker.flows[FlowKey{SrcIP: "10.0.1.1", DstIP: "10.0.1.2", SrcPort: 90, DstPort: 9090}] = &FlowStats{TxBytes: 2000, RxBytes: 300}
	tracker.flows[FlowKey{SrcIP: "10.0.1.2", DstIP: "10.0.1.3", SrcPort: 80, DstPort: 6379}] = &FlowStats{TxBytes: 500, RxBytes: 8000}

	var r stubResolver
	talkers := tracker.TopTalkers(r)

	if len(talkers) != 2 {
		t.Fatalf("expected 2 talkers, got %d", len(talkers))
	}

	if talkers[0].Source != "api" || talkers[0].Destination != "redis" {
		t.Fatalf("expected api→redis first, got %s→%s", talkers[0].Source, talkers[0].Destination)
	}
	if talkers[0].TotalBytes != 8500 {
		t.Fatalf("expected 8500 total bytes, got %d", talkers[0].TotalBytes)
	}

	if talkers[1].Source != "frontend" || talkers[1].Destination != "api" {
		t.Fatalf("expected frontend→api second, got %s→%s", talkers[1].Source, talkers[1].Destination)
	}
	if talkers[1].TxBytes != 3000 || talkers[1].RxBytes != 800 {
		t.Fatalf("expected tx=3000 rx=800, got tx=%d rx=%d", talkers[1].TxBytes, talkers[1].RxBytes)
	}
}

func TestTrackerTopEndpoints(t *testing.T) {
	tracker := New()

	tracker.flows[FlowKey{SrcIP: "10.0.1.1", DstIP: "10.0.1.2"}] = &FlowStats{TxBytes: 1000, RxBytes: 500}
	tracker.flows[FlowKey{SrcIP: "10.0.1.2", DstIP: "10.0.1.3"}] = &FlowStats{TxBytes: 200, RxBytes: 300}

	var r stubResolver
	endpoints := tracker.TopEndpoints(r)

	if len(endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].Name != "frontend" || endpoints[0].TotalBytes != 1000 {
		t.Fatalf("expected frontend first with 1000 total, got %s total=%d", endpoints[0].Name, endpoints[0].TotalBytes)
	}
	if endpoints[1].Name != "api" || endpoints[1].TotalBytes != 700 {
		t.Fatalf("expected api second with 700 total, got %s total=%d", endpoints[1].Name, endpoints[1].TotalBytes)
	}
	if endpoints[2].Name != "redis" || endpoints[2].TotalBytes != 300 {
		t.Fatalf("expected redis third with 300 total, got %s total=%d", endpoints[2].Name, endpoints[2].TotalBytes)
	}
}

func TestComputeMbps(t *testing.T) {
	talkers := []Talker{
		{Source: "a", Destination: "b", TxBytes: 1000000, RxBytes: 500000, TotalBytes: 1500000},
	}
	elapsed := 2 * time.Second
	result := ComputeMbps(talkers, elapsed)

	// 1000000 bytes * 8 / (2 * 1000000) = 4 Mbps
	// 500000 bytes * 8 / (2 * 1000000) = 2 Mbps
	if result[0].TxMbps != 4.0 {
		t.Fatalf("expected 4.0 Mbps TX, got %f", result[0].TxMbps)
	}
	if result[0].RxMbps != 2.0 {
		t.Fatalf("expected 2.0 Mbps RX, got %f", result[0].RxMbps)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		input uint64
		unit  byte
		want  string
	}{
		{500, 'B', "500 B"},
		{500, 'K', "0 KB"},
		{1500, 'K', "1 KB"},
		{1048576, 'M', "1 MB"},
		{1500000, 'M', "1.43 MB"},
		{1048576, 'K', "1024 KB"},
		{500, 0, "500 B"},
		{1500, 0, "1 KB"},
		{1048576, 0, "1 MB"},
		{1572864, 0, "1536 KB"},
		{20971520, 0, "20 MB"},
		{10485760, 0, "10 MB"},
	}
	for _, c := range cases {
		got := FormatBytes(c.input, c.unit)
		if got != c.want {
			t.Errorf("FormatBytes(%d, %c) = %q, want %q", c.input, c.unit, got, c.want)
		}
	}
}

func TestBestUnit(t *testing.T) {
	cases := []struct {
		vals []uint64
		want byte
	}{
		{[]uint64{500}, 'B'},
		{[]uint64{1024}, 'K'},
		{[]uint64{1048576}, 'M'},
		{[]uint64{1500000}, 'K'},
		{[]uint64{10485760}, 'M'},
		{[]uint64{500, 1048576, 1500000}, 'K'},
	}
	for _, c := range cases {
		got := BestUnit(c.vals...)
		if got != c.want {
			t.Errorf("BestUnit(%v) = %c, want %c", c.vals, got, c.want)
		}
	}
}

func TestFormatTalkersEmpty(t *testing.T) {
	result := FormatTalkers([]Talker{}, 5*time.Second, 0)
	if result != "(no data)" {
		t.Fatalf("expected (no data), got %s", result)
	}
}

func TestFormatEndpointsEmpty(t *testing.T) {
	result := FormatEndpoints([]PerNameStats{}, 5*time.Second, 0)
	if result != "(no data)" {
		t.Fatalf("expected (no data), got %s", result)
	}
}

func TestTopTalkersNoData(t *testing.T) {
	tracker := New()
	var r stubResolver
	talkers := tracker.TopTalkers(r)
	if len(talkers) != 0 {
		t.Fatalf("expected 0 talkers, got %d", len(talkers))
	}
}

func TestTopEndpointsNoData(t *testing.T) {
	tracker := New()
	var r stubResolver
	eps := tracker.TopEndpoints(r)
	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints, got %d", len(eps))
	}
}
