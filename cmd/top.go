package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/kubernetes"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"
	"github.com/moyashiwithdevice/kubectl-detective/internal/throughput"

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
	topWatch      bool
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
			if topResolveSvc {
				extra = append(extra, "--svc")
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
			if topWatch {
				extra = append(extra, "-w")
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
			_, _ = fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case topResolvePod:
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

		tracker := throughput.New()

		if topWatch {
			return runWatch(c, r, tracker, sig)
		}

		if topDuration > 0 {
			_, _ = fmt.Fprintf(log, "Collecting throughput for %s...\n", topDuration)
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

func runWatch(c *flow.Collector, r resolver.Resolver, tracker *throughput.Tracker, sig <-chan os.Signal) error {
	go func() {
		for {
			_, err := c.Read()
			if err != nil {
				return
			}
		}
	}()

	if err := tracker.Watch(c); err != nil {
		return fmt.Errorf("initial watch: %w", err)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	interval := 2 * time.Second

	var unit byte
	switch {
	case topUnitMB:
		unit = 'M'
	case topUnitKB:
		unit = 'K'
	case topUnitB:
		unit = 'B'
	}

	for {
		select {
		case <-ticker.C:
			if err := tracker.Watch(c); err != nil {
				return fmt.Errorf("watch: %w", err)
			}

			var elapsed time.Duration
			if topDuration > 0 {
				elapsed = topDuration
			} else {
				elapsed = interval
			}

			u := unit
			if topByEndpoint {
				endpoints := tracker.TopEndpoints(r)
				if u == 0 {
					vals := make([]uint64, len(endpoints))
					for i, ep := range endpoints {
						vals[i] = ep.TotalBytes
					}
					u = throughput.BestUnit(vals...)
				}
				fmt.Print("\033[2J\033[H" + throughput.FormatEndpoints(endpoints, elapsed, u))
			} else {
				talkers := tracker.TopTalkers(r)
				if u == 0 {
					vals := make([]uint64, len(talkers))
					for i, t := range talkers {
						vals[i] = t.TotalBytes
					}
					u = throughput.BestUnit(vals...)
				}
				fmt.Print("\033[2J\033[H" + throughput.FormatTalkers(talkers, elapsed, u))
			}
		case <-sig:
			fmt.Println()
			return nil
		}
	}
}

func init() {
	topCmd.Flags().DurationVarP(&topDuration, "duration", "d", 10*time.Second, "Collection duration")
	topCmd.Flags().BoolVarP(&topNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	topCmd.Flags().BoolVarP(&topResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	topCmd.Flags().BoolVarP(&topResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	topCmd.Flags().BoolVarP(&topByEndpoint, "endpoints", "", false, "Aggregate by endpoint (per-name) instead of per-connection")
	topCmd.Flags().BoolVarP(&topNoHeaders, "no-headers", "", false, "Suppress progress messages")
	topCmd.Flags().BoolVarP(&topUnitMB, "mb", "M", false, "Display in MB units")
	topCmd.Flags().BoolVarP(&topUnitKB, "kb", "K", false, "Display in KB units")
	topCmd.Flags().BoolVarP(&topUnitB, "bytes", "B", false, "Display in bytes")
	topCmd.Flags().BoolVarP(&topWatch, "watch", "w", false, "Live updating display (like Linux top)")
	topCmd.MarkFlagsMutuallyExclusive("mb", "kb", "bytes")
	rootCmd.AddCommand(topCmd)
}
