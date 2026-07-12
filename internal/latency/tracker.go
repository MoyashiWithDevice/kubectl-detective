package latency

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"
)

type RTTReader interface {
	ReadRTT(func(flow.RTTKey, flow.RTTVal) error) error
}

type Record struct {
	Source      string
	Destination string
	AvgUs       float64
	P95Us       float64
	P99Us       float64
	MinUs       uint32
	MaxUs       uint32
	Samples     uint64
}

type Tracker struct {
	entries []Record
}

func New() *Tracker {
	return &Tracker{}
}

func (t *Tracker) Read(collector RTTReader, r resolver.Resolver) error {
	type agg struct {
		sumUs uint64
		count uint64
		minUs uint32
		maxUs uint32
		hist  [flow.RTTHistBuckets]uint32
	}

	pairMap := make(map[string]*agg)
	err := collector.ReadRTT(func(key flow.RTTKey, val flow.RTTVal) error {
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
		p95 := PercentileFromHist(a.hist[:], a.count, 0.95)
		p99 := PercentileFromHist(a.hist[:], a.count, 0.99)
		// Histogram midpoints can overshoot the true max; clamp for display.
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
			Samples:     a.count,
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

// PercentileFromHist estimates a percentile from a log2 microsecond histogram.
// Bucket i covers [2^i, 2^(i+1)) microseconds; the upper edge is returned.
func PercentileFromHist(hist []uint32, count uint64, p float64) float64 {
	if count == 0 || p <= 0 {
		return 0
	}
	if p > 1 {
		p = 1
	}
	target := uint64(float64(count) * p)
	if target == 0 {
		target = 1
	}
	if target > count {
		target = count
	}

	var cum uint64
	for i, n := range hist {
		cum += uint64(n)
		if cum >= target {
			// Return geometric midpoint of the bucket for a smoother estimate.
			lo := uint64(1) << uint(i)
			if i == 0 {
				return float64(lo)
			}
			hi := uint64(1) << uint(i+1)
			return float64(lo+hi) / 2
		}
	}
	// Fallback: top of last non-empty style bound.
	last := len(hist) - 1
	return float64(uint64(1) << uint(last))
}

// PercentileFromSamples computes an exact percentile from sorted sample values (µs).
// p is in (0,1]; used by tests and any callers that hold raw samples.
func PercentileFromSamples(samples []uint64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	if p <= 0 {
		return float64(samples[0])
	}
	if p > 1 {
		p = 1
	}
	sorted := make([]uint64, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Nearest-rank method.
	rank := int(float64(len(sorted))*p+0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return float64(sorted[rank])
}

func FormatLatency(entries []Record, elapsed time.Duration) string {
	if len(entries) == 0 {
		return "(no latency data)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Latency Ranking (%s)\n", elapsed.Round(time.Second))
	fmt.Fprintf(&b, "%-4s %-30s %-10s %-10s %-10s %-8s %s\n",
		"Rank", "Source → Destination", "Avg", "p95", "p99", "Max", "Samples")
	b.WriteString(strings.Repeat("─", 96) + "\n")
	for i, rec := range entries {
		rank := i + 1
		label := fmt.Sprintf("%s → %s", rec.Source, rec.Destination)
		fmt.Fprintf(&b, "%-4d %-30s %-10s %-10s %-10s %-8s %d\n",
			rank, label,
			FormatDuration(rec.AvgUs),
			FormatDuration(rec.P95Us),
			FormatDuration(rec.P99Us),
			FormatDuration(float64(rec.MaxUs)),
			rec.Samples,
		)
	}
	return b.String()
}

// FormatDuration formats a microsecond value as a human-readable latency string.
func FormatDuration(us float64) string {
	if us < 0 {
		us = 0
	}
	switch {
	case us < 1000:
		return fmt.Sprintf("%.0fµs", us)
	case us < 1_000_000:
		return fmt.Sprintf("%.2fms", us/1000)
	default:
		return fmt.Sprintf("%.2fs", us/1_000_000)
	}
}
