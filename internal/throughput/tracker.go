package throughput

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"
)

type ThroughputReader interface {
	ReadThroughput(func(flow.ThroughputKey, flow.ThroughputVal) error) error
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type FlowStats struct {
	TxBytes uint64
	RxBytes uint64
}

type Tracker struct {
	flows map[FlowKey]*FlowStats
	prev  map[FlowKey]*FlowStats
}

func New() *Tracker {
	return &Tracker{
		flows: make(map[FlowKey]*FlowStats),
		prev:  make(map[FlowKey]*FlowStats),
	}
}

func (t *Tracker) Snapshot(collector ThroughputReader) error {
	return collector.ReadThroughput(func(key flow.ThroughputKey, val flow.ThroughputVal) error {
		fk := FlowKey{
			SrcIP:   net.IP(key.SrcIP[:]).String(),
			DstIP:   net.IP(key.DstIP[:]).String(),
			SrcPort: key.SrcPort,
			DstPort: key.DstPort,
		}
		if existing, ok := t.flows[fk]; ok {
			if val.TxBytes > existing.TxBytes {
				existing.TxBytes = val.TxBytes
			}
			if val.RxBytes > existing.RxBytes {
				existing.RxBytes = val.RxBytes
			}
		} else {
			t.flows[fk] = &FlowStats{
				TxBytes: val.TxBytes,
				RxBytes: val.RxBytes,
			}
		}
		return nil
	})
}

func (t *Tracker) Watch(collector ThroughputReader) error {
	cur := make(map[FlowKey]*FlowStats)
	err := collector.ReadThroughput(func(key flow.ThroughputKey, val flow.ThroughputVal) error {
		fk := FlowKey{
			SrcIP:   net.IP(key.SrcIP[:]).String(),
			DstIP:   net.IP(key.DstIP[:]).String(),
			SrcPort: key.SrcPort,
			DstPort: key.DstPort,
		}
		cur[fk] = &FlowStats{TxBytes: val.TxBytes, RxBytes: val.RxBytes}
		return nil
	})
	if err != nil {
		return err
	}

	t.flows = make(map[FlowKey]*FlowStats)
	for k, v := range cur {
		if prev, ok := t.prev[k]; ok {
			tx := v.TxBytes - prev.TxBytes
			rx := v.RxBytes - prev.RxBytes
			if tx > 0 || rx > 0 {
				t.flows[k] = &FlowStats{TxBytes: tx, RxBytes: rx}
			}
		} else {
			if v.TxBytes > 0 || v.RxBytes > 0 {
				t.flows[k] = &FlowStats{TxBytes: v.TxBytes, RxBytes: v.RxBytes}
			}
		}
	}

	t.prev = cur
	return nil
}

type Talker struct {
	Source      string
	Destination string
	TxBytes     uint64
	RxBytes     uint64
	TotalBytes  uint64
	TxMbps      float64
	RxMbps      float64
}

func (t *Tracker) TopTalkers(r resolver.Resolver) []Talker {
	pairMap := make(map[string]*Talker)
	for key, stats := range t.flows {
		src := r.Resolve(net.ParseIP(key.SrcIP))
		dst := r.Resolve(net.ParseIP(key.DstIP))
		pk := src + "\x00" + dst
		if existing, ok := pairMap[pk]; ok {
			existing.TxBytes += stats.TxBytes
			existing.RxBytes += stats.RxBytes
		} else {
			pairMap[pk] = &Talker{
				Source:      src,
				Destination: dst,
				TxBytes:     stats.TxBytes,
				RxBytes:     stats.RxBytes,
			}
		}
	}

	result := make([]Talker, 0, len(pairMap))
	for _, talker := range pairMap {
		talker.TotalBytes = talker.TxBytes + talker.RxBytes
		result = append(result, *talker)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBytes > result[j].TotalBytes
	})

	return result
}

type PerNameStats struct {
	Name       string
	TxBytes    uint64
	RxBytes    uint64
	TotalBytes uint64
}

func (t *Tracker) TopEndpoints(r resolver.Resolver) []PerNameStats {
	nameMap := make(map[string]*PerNameStats)
	for key, stats := range t.flows {
		src := r.Resolve(net.ParseIP(key.SrcIP))
		dst := r.Resolve(net.ParseIP(key.DstIP))

		if _, ok := nameMap[src]; !ok {
			nameMap[src] = &PerNameStats{Name: src}
		}
		nameMap[src].TxBytes += stats.TxBytes

		if _, ok := nameMap[dst]; !ok {
			nameMap[dst] = &PerNameStats{Name: dst}
		}
		nameMap[dst].RxBytes += stats.RxBytes
	}

	result := make([]PerNameStats, 0, len(nameMap))
	for _, s := range nameMap {
		s.TotalBytes = s.TxBytes + s.RxBytes
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalBytes > result[j].TotalBytes
	})

	return result
}

func ComputeMbps(talkers []Talker, elapsed time.Duration) []Talker {
	if elapsed <= 0 {
		return talkers
	}
	secs := elapsed.Seconds()
	for i := range talkers {
		talkers[i].TxMbps = float64(talkers[i].TxBytes) * 8 / (secs * 1000000)
		talkers[i].RxMbps = float64(talkers[i].RxBytes) * 8 / (secs * 1000000)
	}
	return talkers
}

func BestUnit(totalBytes ...uint64) byte {
	var max uint64
	for _, v := range totalBytes {
		if v > max {
			max = v
		}
	}
	const mb = uint64(1 << 20)
	const kb = uint64(1 << 10)
	if max < kb {
		return 'B'
	}
	if max < mb {
		return 'K'
	}
	if max%mb == 0 {
		return 'M'
	}
	if max < 10*mb {
		return 'K'
	}
	return 'M'
}

func FormatBytes(b uint64, unit byte) string {
	const mb = uint64(1 << 20)
	const kb = uint64(1 << 10)

	switch unit {
	case 'B':
		return fmt.Sprintf("%d B", b)
	case 'M':
		if b%mb == 0 {
			return fmt.Sprintf("%d MB", b/mb)
		}
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	case 'K':
		return fmt.Sprintf("%d KB", b/kb)
	default:
		if b >= mb && b%mb == 0 {
			return fmt.Sprintf("%d MB", b/mb)
		}
		if b >= kb {
			return fmt.Sprintf("%d KB", b/kb)
		}
		return fmt.Sprintf("%d B", b)
	}
}

func FormatMbps(mbps float64) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%.2f Gbps", mbps/1000)
	}
	return fmt.Sprintf("%.2f Mbps", mbps)
}

func FormatTalkers(talkers []Talker, elapsed time.Duration, unit byte) string {
	if len(talkers) == 0 {
		return "(no data)"
	}
	table := ComputeMbps(talkers, elapsed)

	var b strings.Builder
	fmt.Fprintf(&b, "Top Talkers (%s)\n", elapsed.Round(time.Second))
	fmt.Fprintf(&b, "%-4s %-24s %-14s %-14s %s\n", "Rank", "Source → Destination", "TX", "RX", "Total")
	b.WriteString(strings.Repeat("─", 80) + "\n")
	for i, talker := range table {
		rank := i + 1
		label := fmt.Sprintf("%s → %s", talker.Source, talker.Destination)
		fmt.Fprintf(&b, "%-4d %-24s %-14s %-14s %s\n",
			rank, label,
			FormatMbps(talker.TxMbps),
			FormatMbps(talker.RxMbps),
			FormatBytes(talker.TotalBytes, unit),
		)
	}
	return b.String()
}

func FormatEndpoints(endpoints []PerNameStats, elapsed time.Duration, unit byte) string {
	if len(endpoints) == 0 {
		return "(no data)"
	}
	secs := elapsed.Seconds()

	var b strings.Builder
	fmt.Fprintf(&b, "Top Endpoints (%s)\n", elapsed.Round(time.Second))
	fmt.Fprintf(&b, "%-4s %-24s %-14s %-14s %s\n", "Rank", "Name", "TX", "RX", "Total")
	b.WriteString(strings.Repeat("─", 80) + "\n")
	for i, ep := range endpoints {
		rank := i + 1
		txMbps := float64(ep.TxBytes) * 8 / (secs * 1000000)
		rxMbps := float64(ep.RxBytes) * 8 / (secs * 1000000)
		fmt.Fprintf(&b, "%-4d %-24s %-14s %-14s %s\n",
			rank, ep.Name,
			FormatMbps(txMbps),
			FormatMbps(rxMbps),
			FormatBytes(ep.TotalBytes, unit),
		)
	}
	return b.String()
}
