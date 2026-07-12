package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/dns"
	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/kubernetes"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"

	"github.com/spf13/cobra"
)

var (
	dnsDuration   time.Duration
	dnsNoResolve  bool
	dnsResolvePod bool
	dnsResolveSvc bool
	dnsNoHeaders  bool
	dnsWatch      bool
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Show DNS query latency statistics",
	Long: `Capture UDP/53 DNS traffic and display latency ranking with average, p95, and p99.
Requires eBPF privileges or kind cluster.

Use -w for live updating display (like Linux top).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if dnsDuration > 0 {
					extra = append(extra, "--duration", dnsDuration.String())
				}
				if dnsNoResolve {
					extra = append(extra, "-n")
				}
				if dnsResolvePod {
					extra = append(extra, "--pod")
				}
				if dnsResolveSvc {
					extra = append(extra, "--svc")
				}
				if dnsNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if dnsWatch {
					extra = append(extra, "-w")
				}
				return flow.RunInKind("dns", extra...)
			}
			return err
		}
		defer c.Close()

		if !c.HasDNS() {
			return fmt.Errorf("DNS tracking not available in this build")
		}

		var log io.Writer = os.Stderr
		if dnsNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case dnsNoResolve:
			_, _ = fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case dnsResolvePod:
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

		if dnsWatch {
			return runWatchDNS(c, r, sig, log)
		}

		_, _ = fmt.Fprintf(log, "Collecting DNS queries for %s...\n", dnsDuration)
		timer := time.After(dnsDuration)
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

		tracker := dns.New()
		if err := tracker.Read(c, r); err != nil {
			return fmt.Errorf("read DNS stats: %w", err)
		}

		fmt.Print(dns.FormatDNS(tracker.Entries(), dnsDuration))
		return nil
	},
}

func runWatchDNS(c *flow.Collector, r resolver.Resolver, sig <-chan os.Signal, log io.Writer) error {
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

	_, _ = fmt.Fprintln(log, "Watching DNS... Press Ctrl+C to stop.")

	for {
		select {
		case <-ticker.C:
			tracker := dns.New()
			if err := tracker.Read(c, r); err != nil {
				return err
			}
			fmt.Print("\033[2J\033[H" + dns.FormatDNS(tracker.Entries(), 2*time.Second))
		case <-sig:
			fmt.Println()
			return nil
		}
	}
}

func init() {
	dnsCmd.Flags().DurationVarP(&dnsDuration, "duration", "d", 10*time.Second, "Collection duration")
	dnsCmd.Flags().BoolVarP(&dnsNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	dnsCmd.Flags().BoolVarP(&dnsResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	dnsCmd.Flags().BoolVarP(&dnsResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	dnsCmd.Flags().BoolVarP(&dnsNoHeaders, "no-headers", "", false, "Suppress progress messages")
	dnsCmd.Flags().BoolVarP(&dnsWatch, "watch", "w", false, "Live updating display (like Linux top)")
	rootCmd.AddCommand(dnsCmd)
}
