package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"Kubernetes-plugin/internal/flow"
	"Kubernetes-plugin/internal/kubernetes"
	"Kubernetes-plugin/internal/resolver"
	"Kubernetes-plugin/internal/throughput"

	"github.com/spf13/cobra"
)

var (
	topDuration   time.Duration
	topNoResolve  bool
	topResolvePod bool
	topResolveSvc bool
	topByEndpoint bool
	topNoHeaders  bool
	topUnitMB     bool
	topUnitKB     bool
	topUnitB      bool
)

var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Show throughput top talkers",
	Long: `Collect throughput data and display traffic volume ranking.
Default output shows per-connection top talkers. Use --endpoints for per-endpoint view.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if topDuration > 0 {
					extra = append(extra, "--duration", topDuration.String())
				}
				if topNoResolve {
					extra = append(extra, "-n")
				}
				if topResolvePod {
					extra = append(extra, "--pod")
				}
				if topByEndpoint {
					extra = append(extra, "--endpoints")
				}
				if topNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if topUnitMB {
					extra = append(extra, "-M")
				}
				if topUnitKB {
					extra = append(extra, "-K")
				}
				if topUnitB {
					extra = append(extra, "-B")
				}
				return flow.RunInKind("top", extra...)
			}
			return err
		}
		defer c.Close()

		if !c.HasThroughput() {
			return fmt.Errorf("throughput tracking not available in this build")
		}

		var log io.Writer = os.Stderr
		if topNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case topNoResolve:
			fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case topResolvePod:
			fmt.Fprintln(log, "resolver: pod mode")
			client, err := kubernetes.NewClient()
			if err != nil {
				return fmt.Errorf("kubernetes client: %w", err)
			}
			r = resolver.NewPod(client, true)
		default:
			fmt.Fprintln(log, "resolver: service mode")
			client, err := kubernetes.NewClient()
			if err != nil {
				return fmt.Errorf("kubernetes client: %w", err)
			}
			r = resolver.NewService(client, true)
		}
		defer r.Close()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)

		tracker := throughput.New()

		if topDuration > 0 {
			fmt.Fprintf(log, "Collecting throughput for %s...\n", topDuration)
			timer := time.After(topDuration)
		loop:
			for {
				select {
				case <-timer:
					break loop
				case <-sig:
					break loop
				default:
				}
				ev, err := c.Read()
				if err != nil {
					return err
				}
				_ = ev
			}
		} else {
			fmt.Fprintln(log, "Collecting throughput... Press Ctrl+C to stop.")
			go func() {
				<-sig
				c.Close()
			}()
			for {
				ev, err := c.Read()
				if err != nil {
					return err
				}
				_ = ev
			}
		}

		if err := tracker.Snapshot(c); err != nil {
			return fmt.Errorf("read throughput: %w", err)
		}

		elapsed := topDuration
		if elapsed <= 0 {
			elapsed = 5 * time.Second
		}

		var unit byte
		switch {
		case topUnitMB:
			unit = 'M'
		case topUnitKB:
			unit = 'K'
		case topUnitB:
			unit = 'B'
		}

		if topByEndpoint {
			endpoints := tracker.TopEndpoints(r)
			if unit == 0 {
				vals := make([]uint64, len(endpoints))
				for i, ep := range endpoints {
					vals[i] = ep.TotalBytes
				}
				unit = throughput.BestUnit(vals...)
			}
			fmt.Print(throughput.FormatEndpoints(endpoints, elapsed, unit))
		} else {
			talkers := tracker.TopTalkers(r)
			if unit == 0 {
				vals := make([]uint64, len(talkers))
				for i, t := range talkers {
					vals[i] = t.TotalBytes
				}
				unit = throughput.BestUnit(vals...)
			}
			fmt.Print(throughput.FormatTalkers(talkers, elapsed, unit))
		}

		return nil
	},
}

func init() {
	topCmd.Flags().DurationVarP(&topDuration, "duration", "d", 10*time.Second, "Collection duration (0 = continuous)")
	topCmd.Flags().BoolVarP(&topNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	topCmd.Flags().BoolVarP(&topResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	topCmd.Flags().BoolVarP(&topResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	topCmd.Flags().BoolVarP(&topByEndpoint, "endpoints", "", false, "Aggregate by endpoint (per-name) instead of per-connection")
	topCmd.Flags().BoolVarP(&topNoHeaders, "no-headers", "", false, "Suppress progress messages")
	topCmd.Flags().BoolVarP(&topUnitMB, "mb", "M", false, "Display in MB units")
	topCmd.Flags().BoolVarP(&topUnitKB, "kb", "K", false, "Display in KB units")
	topCmd.Flags().BoolVarP(&topUnitB, "bytes", "B", false, "Display in bytes")
	topCmd.MarkFlagsMutuallyExclusive("mb", "kb", "bytes")
	rootCmd.AddCommand(topCmd)
}
