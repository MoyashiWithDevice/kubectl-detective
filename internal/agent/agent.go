package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	detectivev1 "github.com/moyashiwithdevice/kubectl-detective/api/detective/v1"
	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Agent struct {
	nodeName   string
	interval   time.Duration
	aggregator string
}

func New(nodeName string, interval time.Duration, aggregator string) *Agent {
	return &Agent{
		nodeName:   nodeName,
		interval:   interval,
		aggregator: aggregator,
	}
}

func (a *Agent) Run(ctx context.Context) error {
	c, err := flow.NewCollector()
	if err != nil {
		return fmt.Errorf("eBPF collector: %w", err)
	}
	defer c.Close()

	// Drain the ring buffer so bpf_ringbuf_submit in kprobe__tcp_connect
	// does not block when the buffer is full.
	go func() {
		for {
			if _, err := c.Read(); err != nil {
				return
			}
		}
	}()

	conn, err := grpc.NewClient(a.aggregator,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect aggregator: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := detectivev1.NewAgentServiceClient(conn)

	fmt.Fprintf(os.Stderr, "agent %s: sending snapshots to %s every %s\n",
		a.nodeName, a.aggregator, a.interval)

	// Force a connection attempt to verify connectivity.
	if _, err := client.SendSnapshot(ctx, &detectivev1.SnapshotRequest{
		Snapshot: &detectivev1.AgentSnapshot{NodeName: a.nodeName, Timestamp: time.Now().UnixNano()},
	}); err != nil {
		return fmt.Errorf("initial handshake: %w", err)
	}

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			snapshot := a.collect(c)
			resp, err := client.SendSnapshot(ctx, &detectivev1.SnapshotRequest{Snapshot: snapshot})
			if err != nil {
				fmt.Fprintf(os.Stderr, "agent: send snapshot: %v\n", err)
				continue
			}
			_ = resp
		}
	}
}

func (a *Agent) collect(c *flow.Collector) *detectivev1.AgentSnapshot {
	snap := &detectivev1.AgentSnapshot{
		NodeName:  a.nodeName,
		Timestamp: time.Now().UnixNano(),
	}

	_ = c.ReadThroughput(func(k flow.ThroughputKey, v flow.ThroughputVal) error {
		snap.Throughput = append(snap.Throughput, &detectivev1.ThroughputEntry{
			SrcIp:   k.SrcIP[:],
			DstIp:   k.DstIP[:],
			SrcPort: uint32(k.SrcPort),
			DstPort: uint32(k.DstPort),
			TxBytes: v.TxBytes,
			RxBytes: v.RxBytes,
		})
		return nil
	})

	_ = c.ReadRetrans(func(k flow.RetransKey, v flow.RetransVal) error {
		snap.Retrans = append(snap.Retrans, &detectivev1.RetransEntry{
			SrcIp:   k.SrcIP[:],
			DstIp:   k.DstIP[:],
			SrcPort: uint32(k.SrcPort),
			DstPort: uint32(k.DstPort),
			Count:   v.Count,
		})
		return nil
	})

	_ = c.ReadRTT(func(k flow.RTTKey, v flow.RTTVal) error {
		snap.Rtt = append(snap.Rtt, &detectivev1.RTTEntry{
			SrcIp:   k.SrcIP[:],
			DstIp:   k.DstIP[:],
			SrcPort: uint32(k.SrcPort),
			DstPort: uint32(k.DstPort),
			SumUs:   v.SumUs,
			Count:   v.Count,
			MinUs:   v.MinUs,
			MaxUs:   v.MaxUs,
			Hist:    v.Hist[:],
		})
		return nil
	})

	_ = c.ReadDNSStats(func(k flow.DNSStatsKey, v flow.DNSStatsVal) error {
		snap.Dns = append(snap.Dns, &detectivev1.DNSEntry{
			SrcIp: k.SrcIP[:],
			DstIp: k.DstIP[:],
			Count: v.Count,
			SumUs: v.SumUs,
			MinUs: v.MinUs,
			MaxUs: v.MaxUs,
			Hist:  v.Hist[:],
		})
		return nil
	})

	return snap
}

func DefaultNodeName() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}


