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
	"Kubernetes-plugin/internal/retrans"

	"github.com/spf13/cobra"
)

var (
	retransDuration   time.Duration
	retransNoResolve  bool
	retransResolvePod bool
	retransResolveSvc bool
	retransNoHeaders  bool
	retransWatch      bool
)

var retransCmd = &cobra.Command{
	Use:   "retrans",
	Short: "Show TCP retransmission ranking",
	Long: `Collect TCP retransmission events and display ranking.
Requires eBPF privileges or kind cluster.

Use -w for live updating display (like Linux top).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if retransDuration > 0 {
					extra = append(extra, "--duration", retransDuration.String())
				}
				if retransNoResolve {
					extra = append(extra, "-n")
				}
				if retransResolvePod {
					extra = append(extra, "--pod")
				}
				if retransResolveSvc {
					extra = append(extra, "--svc")
				}
				if retransNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if retransWatch {
					extra = append(extra, "-w")
				}
				return flow.RunInKind("retrans", extra...)
			}
			return err
		}
		defer c.Close()

		if !c.HasRetrans() {
			return fmt.Errorf("retransmission tracking not available in this build")
		}

		var log io.Writer = os.Stderr
		if retransNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case retransNoResolve:
			fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case retransResolvePod:
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

		if retransWatch {
			return runWatchRetrans(c, r, sig, log)
		}

		fmt.Fprintf(log, "Collecting retransmissions for %s...\n", retransDuration)
		timer := time.After(retransDuration)
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

		tracker := retrans.New()
		if err := tracker.Read(c, r); err != nil {
			return fmt.Errorf("read retransmissions: %w", err)
		}

		fmt.Print(retrans.FormatRetrans(tracker.Entries(), retransDuration))
		return nil
	},
}

func runWatchRetrans(c *flow.Collector, r resolver.Resolver, sig <-chan os.Signal, log io.Writer) error {
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

	fmt.Fprintln(log, "Watching retransmissions... Press Ctrl+C to stop.")

	for {
		select {
		case <-ticker.C:
			tracker := retrans.New()
			if err := tracker.Read(c, r); err != nil {
				return err
			}
			fmt.Print("\033[2J\033[H" + retrans.FormatRetrans(tracker.Entries(), 2*time.Second))
		case <-sig:
			fmt.Println()
			return nil
		}
	}
}

func init() {
	retransCmd.Flags().DurationVarP(&retransDuration, "duration", "d", 10*time.Second, "Collection duration")
	retransCmd.Flags().BoolVarP(&retransNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	retransCmd.Flags().BoolVarP(&retransResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	retransCmd.Flags().BoolVarP(&retransResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	retransCmd.Flags().BoolVarP(&retransNoHeaders, "no-headers", "", false, "Suppress progress messages")
	retransCmd.Flags().BoolVarP(&retransWatch, "watch", "w", false, "Live updating display (like Linux top)")
	rootCmd.AddCommand(retransCmd)
}
