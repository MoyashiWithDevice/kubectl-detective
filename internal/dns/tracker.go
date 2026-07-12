package dns

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/latency"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"
)

type DNSStatsReader interface {
	ReadDNSStats(func(flow.DNSStatsKey, flow.DNSStatsVal) error) error
}

type Record struct {
	Source      string
	Destination string
	AvgUs       float64
	P95Us       float64
	P99Us       float64
	MinUs       uint32
	MaxUs       uint32
	Queries     uint64
}

type Tracker struct {
	entries []Record
}

func New() *Tracker {
	return &Tracker{}
}

func (t *Tracker) Read(collector DNSStatsReader, r resolver.Resolver) error {
	type agg struct {
		sumUs uint64
		count uint64
		minUs uint32
		maxUs uint32
		hist  [flow.RTTHistBuckets]uint32
	}

	pairMap := make(map[string]*agg)
	err := collector.ReadDNSStats(func(key flow.DNSStatsKey, val flow.DNSStatsVal) error {
		if val.Count == 0 {
			return nil
		}
		src := r.Resolve(net.IP(key.SrcIP[:]))
		dst := r.Resolve(net.IP(key.DstIP[:]))
		pk := src + "\x00" + dst
		a, ok := pairMap[pk]
		if !ok {
			a = &agg{minUs: val.MinUs, maxUs: val.MaxUs}
			pairMap[pk] = a
		}
		a.sumUs += val.SumUs
		a.count += val.Count
		if val.MinUs > 0 && (a.minUs == 0 || val.MinUs < a.minUs) {
			a.minUs = val.MinUs
		}
		if val.MaxUs > a.maxUs {
			a.maxUs = val.MaxUs
		}
		for i := 0; i < flow.RTTHistBuckets; i++ {
			a.hist[i] += val.Hist[i]
		}
		return nil
	})
	if err != nil {
		return err
	}

	result := make([]Record, 0, len(pairMap))
	for pk, a := range pairMap {
		parts := strings.SplitN(pk, "\x00", 2)
		src, dst := parts[0], ""
		if len(parts) == 2 {
			dst = parts[1]
		}
		p95 := latency.PercentileFromHist(a.hist[:], a.count, 0.95)
		p99 := latency.PercentileFromHist(a.hist[:], a.count, 0.99)
		if a.maxUs > 0 {
			if p95 > float64(a.maxUs) {
				p95 = float64(a.maxUs)
			}
			if p99 > float64(a.maxUs) {
				p99 = float64(a.maxUs)
			}
		}
		rec := Record{
			Source:      src,
			Destination: dst,
			AvgUs:       float64(a.sumUs) / float64(a.count),
			P95Us:       p95,
			P99Us:       p99,
			MinUs:       a.minUs,
			MaxUs:       a.maxUs,
			Queries:     a.count,
		}
		result = append(result, rec)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].P95Us > result[j].P95Us
	})

	t.entries = result
	return nil
}

func (t *Tracker) Entries() []Record {
	return t.entries
}

func FormatDNS(entries []Record, elapsed time.Duration) string {
	if len(entries) == 0 {
		return "(no DNS data)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "DNS Latency Ranking (%s)\n", elapsed.Round(time.Second))
	fmt.Fprintf(&b, "%-4s %-30s %-10s %-10s %-10s %-8s %s\n",
		"Rank", "Source → DNS Server", "Avg", "p95", "p99", "Max", "Queries")
	b.WriteString(strings.Repeat("─", 96) + "\n")
	for i, rec := range entries {
		rank := i + 1
		label := fmt.Sprintf("%s → %s", rec.Source, rec.Destination)
		fmt.Fprintf(&b, "%-4d %-30s %-10s %-10s %-10s %-8s %d\n",
			rank, label,
			latency.FormatDuration(rec.AvgUs),
			latency.FormatDuration(rec.P95Us),
			latency.FormatDuration(rec.P99Us),
			latency.FormatDuration(float64(rec.MaxUs)),
			rec.Queries,
		)
	}
	return b.String()
}
