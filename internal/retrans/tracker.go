package retrans

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"
)

type RetransReader interface {
	ReadRetrans(func(flow.RetransKey, flow.RetransVal) error) error
}

type Record struct {
	Source      string
	Destination string
	Count       uint64
}

type Tracker struct {
	entries []Record
}

func New() *Tracker {
	return &Tracker{}
}

func (t *Tracker) Read(collector RetransReader, r resolver.Resolver) error {
	pairMap := make(map[string]*Record)
	err := collector.ReadRetrans(func(key flow.RetransKey, val flow.RetransVal) error {
		src := r.Resolve(net.IP(key.SrcIP[:]))
		dst := r.Resolve(net.IP(key.DstIP[:]))
		pk := src + "\x00" + dst
		if existing, ok := pairMap[pk]; ok {
			existing.Count += val.Count
		} else {
			pairMap[pk] = &Record{
				Source:      src,
				Destination: dst,
				Count:       val.Count,
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	result := make([]Record, 0, len(pairMap))
	for _, rec := range pairMap {
		result = append(result, *rec)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	t.entries = result
	return nil
}

func (t *Tracker) Entries() []Record {
	return t.entries
}

func FormatRetrans(entries []Record, elapsed time.Duration) string {
	if len(entries) == 0 {
		return "(no retransmissions detected)"
	}

	secs := elapsed.Seconds()

	var b strings.Builder
	fmt.Fprintf(&b, "Retransmission Ranking (%s)\n", elapsed.Round(time.Second))
	fmt.Fprintf(&b, "%-4s %-30s %-16s %s\n", "Rank", "Source → Destination", "Retransmits", "Rate")
	b.WriteString(strings.Repeat("─", 80) + "\n")
	for i, rec := range entries {
		rank := i + 1
		label := fmt.Sprintf("%s → %s", rec.Source, rec.Destination)
		rate := float64(rec.Count) / secs
		fmt.Fprintf(&b, "%-4d %-30s %-16d %s\n",
			rank, label, rec.Count, formatRate(rate))
	}
	return b.String()
}

func formatRate(rate float64) string {
	if rate >= 1 {
		return fmt.Sprintf("%.2f /s", rate)
	}
	return fmt.Sprintf("%.4f /s", rate)
}
