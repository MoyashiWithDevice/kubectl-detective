package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/kubernetes"
	"github.com/moyashiwithdevice/kubectl-detective/internal/latency"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"

	"github.com/spf13/cobra"
)

var (
	latencyDuration   time.Duration
	latencyNoResolve  bool
	latencyResolvePod bool
	latencyResolveSvc bool
	latencyNoHeaders  bool
	latencyWatch      bool
)

var latencyCmd = &cobra.Command{
	Use:   "latency",
	Short: "Show Pod-to-Pod TCP latency (RTT) ranking",
	Long: `Collect TCP smoothed RTT samples and display latency ranking with average, p95, and p99.
Requires eBPF privileges or kind cluster.

Use -w for live updating display (like Linux top).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if latencyDuration > 0 {
					extra = append(extra, "--duration", latencyDuration.String())
				}
				if latencyNoResolve {
					extra = append(extra, "-n")
				}
				if latencyResolvePod {
					extra = append(extra, "--pod")
				}
				if latencyResolveSvc {
					extra = append(extra, "--svc")
				}
				if latencyNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if latencyWatch {
					extra = append(extra, "-w")
				}
				return flow.RunInKind("latency", extra...)
			}
			return err
		}
		defer c.Close()

		if !c.HasRTT() {
			return fmt.Errorf("RTT tracking not available in this build")
		}

		var log io.Writer = os.Stderr
		if latencyNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case latencyNoResolve:
			_, _ = fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case latencyResolvePod:
			_, _ = fmt.Fprintln(log, "resolver: pod mode")
			client, err := kubernetes.NewClient()
			if err != nil {
				return fmt.Errorf("kubernetes client: %w", err)
			}
			r = resolver.NewPod(client, true)
		default:
			_, _ = fmt.Fprintln(log, "resolver: service mode")
			client, err := kubernetes.NewClient()
			if err != nil {
				return fmt.Errorf("kubernetes client: %w", err)
			}
			r = resolver.NewService(client, true)
		}
		defer r.Close()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		defer signal.Stop(sig)

		if latencyWatch {
			return runWatchLatency(c, r, sig, log)
		}

		_, _ = fmt.Fprintf(log, "Collecting RTT samples for %s...\n", latencyDuration)
		timer := time.After(latencyDuration)
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

		tracker := latency.New()
		if err := tracker.Read(c, r); err != nil {
			return fmt.Errorf("read RTT: %w", err)
		}

		fmt.Print(latency.FormatLatency(tracker.Entries(), latencyDuration))
		return nil
	},
}

func runWatchLatency(c *flow.Collector, r resolver.Resolver, sig <-chan os.Signal, log io.Writer) error {
	go func() {
		for {
			ev, err := c.Read()
			if err != nil {
				return
			}
			_ = ev
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	_, _ = fmt.Fprintln(log, "Watching latency... Press Ctrl+C to stop.")

	for {
		select {
		case <-ticker.C:
			tracker := latency.New()
			if err := tracker.Read(c, r); err != nil {
				return err
			}
			fmt.Print("\033[2J\033[H" + latency.FormatLatency(tracker.Entries(), 2*time.Second))
		case <-sig:
			fmt.Println()
			return nil
		}
	}
}

func init() {
	latencyCmd.Flags().DurationVarP(&latencyDuration, "duration", "d", 10*time.Second, "Collection duration")
	latencyCmd.Flags().BoolVarP(&latencyNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	latencyCmd.Flags().BoolVarP(&latencyResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	latencyCmd.Flags().BoolVarP(&latencyResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	latencyCmd.Flags().BoolVarP(&latencyNoHeaders, "no-headers", "", false, "Suppress progress messages")
	latencyCmd.Flags().BoolVarP(&latencyWatch, "watch", "w", false, "Live updating display (like Linux top)")
	rootCmd.AddCommand(latencyCmd)
}
