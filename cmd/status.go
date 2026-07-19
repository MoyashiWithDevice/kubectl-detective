package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	detectivev1 "github.com/moyashiwithdevice/kubectl-detective/api/detective/v1"
	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	statusAddr       string
	statusOutput     string
	statusInKind     bool   // set when running inside kind to prevent recursion
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cluster-wide network status from the aggregator",
	Long: `Connect to the detective aggregator and display aggregated
network metrics collected from all node agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// If user explicitly set --aggregator, connect directly.
		if cmd.Flags().Changed("aggregator") {
			return runStatusDirectly(statusAddr, statusOutput)
		}

		// Auto-discover: try localhost (port-forward), then in-cluster service, then kind.
		if err := probeAggregator(statusAddr); err == nil {
			return runStatusDirectly(statusAddr, statusOutput)
		}

		if aggAddr, cleanup, err := forwardToInClusterAggregator(); err == nil {
			defer cleanup()
			return runStatusDirectly(aggAddr, statusOutput)
		}

		if !statusInKind {
			return runStatusInKind(statusAddr, statusOutput)
		}

		return fmt.Errorf("no reachable aggregator\n  deploy: kubectl apply -f deploy/\n  or:    kubectl port-forward -n detective svc/detective-aggregator 50051:50051")
	},
}

func showAll(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	top, err := client.GetTop(ctx, &detectivev1.Empty{})
	if err != nil {
		return fmt.Errorf("get top: %w", err)
	}
	printTop(top)

	retrans, err := client.GetRetrans(ctx, &detectivev1.Empty{})
	if err != nil {
		return fmt.Errorf("get retrans: %w", err)
	}
	printRetrans(retrans)

	lat, err := client.GetLatency(ctx, &detectivev1.Empty{})
	if err != nil {
		return fmt.Errorf("get latency: %w", err)
	}
	printLatency(lat)

	dns, err := client.GetDNS(ctx, &detectivev1.Empty{})
	if err != nil {
		return fmt.Errorf("get dns: %w", err)
	}
	printDNS(dns)

	return nil
}

func runStatus(ctx context.Context, client detectivev1.DetectiveServiceClient, output string) error {
	switch output {
	case "top":
		return showTop(ctx, client)
	case "retrans":
		return showRetrans(ctx, client)
	case "latency":
		return showLatency(ctx, client)
	case "dns":
		return showDNS(ctx, client)
	case "flows":
		return showFlows(ctx, client)
	default:
		return showAll(ctx, client)
	}
}

// probeAggregator returns nil if the gRPC address responds.
func probeAggregator(addr string) error {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := detectivev1.NewDetectiveServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.GetTop(ctx, &detectivev1.Empty{})
	return err
}

// runStatusDirectly connects to the given aggregator address and runs status.
func runStatusDirectly(addr string, output string) error {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect aggregator at %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	client := detectivev1.NewDetectiveServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return runStatus(ctx, client, output)
}

// forwardToInClusterAggregator discovers the detective-aggregator service
// across all namespaces and sets up kubectl port-forward to it.
func forwardToInClusterAggregator() (string, func(), error) {
	nsOut, err := exec.Command("kubectl", "get", "svc", "detective-aggregator",
		"-A", "-o", "jsonpath={.metadata.namespace}").Output()
	if err != nil {
		return "", nil, fmt.Errorf("aggregator service not found: %w", err)
	}
	namespace := strings.TrimSpace(string(nsOut))
	if namespace == "" {
		return "", nil, fmt.Errorf("aggregator service namespace is empty")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	aggAddr := fmt.Sprintf("127.0.0.1:%d", port)
	ctx, cancel := context.WithCancel(context.Background())
	pf := exec.CommandContext(ctx, "kubectl", "port-forward",
		"-n", namespace,
		"svc/detective-aggregator",
		fmt.Sprintf("%d:50051", port))
	pf.Stdout = nil
	pf.Stderr = nil
	_ = pf.Start()

	// Wait for the forward to become ready by probing.
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		if probeAggregator(aggAddr) == nil {
			cleanup := func() { cancel(); _ = pf.Process.Kill() }
			return aggAddr, cleanup, nil
		}
	}
	cancel()
	_ = pf.Process.Kill()
	return "", nil, fmt.Errorf("port-forward did not become ready")
}

// runStatusInKind runs the status command inside a kind node where the
// in-kind aggregator is listening.
func runStatusInKind(hostAggAddr string, output string) error {
	_, port, _ := net.SplitHostPort(hostAggAddr)
	if port == "" {
		port = "50051"
	}
	kindAgg := "localhost:" + port

	var buf bytes.Buffer
	extra := []string{"--aggregator", kindAgg, "-o", output, "--in-kind"}
	if err := flow.RunInKindTo("status", &buf, extra...); err != nil {
		return err
	}
	if buf.Len() == 0 {
		fmt.Println("(no data — agent may not be running)")
		return nil
	}
	fmt.Print(buf.String())
	return nil
}

func showTop(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	top, err := client.GetTop(ctx, &detectivev1.Empty{})
	if err != nil {
		return err
	}
	printTop(top)
	return nil
}

func showRetrans(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	retrans, err := client.GetRetrans(ctx, &detectivev1.Empty{})
	if err != nil {
		return err
	}
	printRetrans(retrans)
	return nil
}

func showLatency(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	lat, err := client.GetLatency(ctx, &detectivev1.Empty{})
	if err != nil {
		return err
	}
	printLatency(lat)
	return nil
}

func showDNS(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	dns, err := client.GetDNS(ctx, &detectivev1.Empty{})
	if err != nil {
		return err
	}
	printDNS(dns)
	return nil
}

func showFlows(ctx context.Context, client detectivev1.DetectiveServiceClient) error {
	flows, err := client.GetFlows(ctx, &detectivev1.Empty{})
	if err != nil {
		return err
	}
	if len(flows.Flows) == 0 {
		fmt.Println("(no flows)")
		return nil
	}
	fmt.Printf("%-4s %-24s %-14s\n", "No.", "Source → Destination", "Process")
	fmt.Println("──────────────────────────────────────────────────────")
	for i, f := range flows.Flows {
		fmt.Printf("%-4d %s:%d → %s:%d [%s]\n",
			i+1,
			fmtIP(f.SrcIp), f.SrcPort,
			fmtIP(f.DstIp), f.DstPort,
			f.Comm)
	}
	return nil
}

func printTop(top *detectivev1.TopTalkerList) {
	if len(top.Talkers) == 0 {
		fmt.Println("(no throughput data)")
		return
	}
	fmt.Println("Throughput Top Talkers")
	fmt.Printf("%-4s %-30s %-14s %-14s %s\n", "Rank", "Source → Destination", "TX", "RX", "Total")
	fmt.Println("──────────────────────────────────────────────────────────────────────")
	for i, t := range top.Talkers {
		fmt.Printf("%-4d %-30s %-14s %-14s %s\n",
			i+1,
			fmt.Sprintf("%s → %s", t.Source, t.Destination),
			formatBytes(t.TxBytes),
			formatBytes(t.RxBytes),
			formatBytes(t.TotalBytes))
	}
	fmt.Println()
}

func printRetrans(retrans *detectivev1.RetransList) {
	if len(retrans.Records) == 0 {
		fmt.Println("(no retransmissions)")
		return
	}
	fmt.Println("Retransmission Ranking")
	fmt.Printf("%-4s %-30s %s\n", "Rank", "Source → Destination", "Retransmits")
	fmt.Println("──────────────────────────────────────────────")
	for i, r := range retrans.Records {
		fmt.Printf("%-4d %-30s %d\n",
			i+1,
			fmt.Sprintf("%s → %s", r.Source, r.Destination),
			r.Count)
	}
	fmt.Println()
}

func printLatency(lat *detectivev1.LatencyList) {
	if len(lat.Records) == 0 {
		fmt.Println("(no latency data)")
		return
	}
	fmt.Println("Latency Ranking")
	fmt.Printf("%-4s %-30s %-10s %-10s %-10s %-8s %s\n",
		"Rank", "Source → Destination", "Avg", "p95", "p99", "Max", "Samples")
	fmt.Println("──────────────────────────────────────────────────────────────────────────────")
	for i, r := range lat.Records {
		fmt.Printf("%-4d %-30s %-10s %-10s %-10s %-8s %d\n",
			i+1,
			fmt.Sprintf("%s → %s", r.Source, r.Destination),
			formatDuration(r.AvgUs),
			formatDuration(r.P95Us),
			formatDuration(r.P99Us),
			formatDuration(float64(r.MaxUs)),
			r.Samples)
	}
	fmt.Println()
}

func printDNS(dnsList *detectivev1.DNSList) {
	if len(dnsList.Records) == 0 {
		fmt.Println("(no DNS data)")
		return
	}
	fmt.Println("DNS Latency Ranking")
	fmt.Printf("%-4s %-30s %-10s %-10s %-10s %-8s %s\n",
		"Rank", "Source → DNS Server", "Avg", "p95", "p99", "Max", "Queries")
	fmt.Println("──────────────────────────────────────────────────────────────────────────────")
	for i, r := range dnsList.Records {
		fmt.Printf("%-4d %-30s %-10s %-10s %-10s %-8s %d\n",
			i+1,
			fmt.Sprintf("%s → %s", r.Source, r.Destination),
			formatDuration(r.AvgUs),
			formatDuration(r.P95Us),
			formatDuration(r.P99Us),
			formatDuration(float64(r.MaxUs)),
			r.Queries)
	}
	fmt.Println()
}

func fmtIP(ip []byte) string {
	if len(ip) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
	return fmt.Sprintf("%x", ip)
}

func formatBytes(b uint64) string {
	const mb = uint64(1 << 20)
	const kb = uint64(1 << 10)
	if b >= mb {
		return fmt.Sprintf("%.2f MB", float64(b)/float64(mb))
	}
	if b >= kb {
		return fmt.Sprintf("%.2f KB", float64(b)/float64(kb))
	}
	return fmt.Sprintf("%d B", b)
}

func formatDuration(us float64) string {
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

func init() {
	statusCmd.Flags().StringVar(&statusAddr, "aggregator", "localhost:50051", "Aggregator gRPC address")
	statusCmd.Flags().StringVarP(&statusOutput, "output", "o", "all", "Output section: all, top, retrans, latency, dns, flows")
	statusCmd.Flags().BoolVar(&statusInKind, "in-kind", false, "internal: running inside kind node")
	_ = statusCmd.Flags().MarkHidden("in-kind")
	rootCmd.AddCommand(statusCmd)
}
