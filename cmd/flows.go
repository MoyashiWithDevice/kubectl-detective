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

	"github.com/spf13/cobra"
)

var (
	flowsDuration   time.Duration
	flowsNoResolve  bool
	flowsResolvePod bool
	flowsResolveSvc bool
	flowsNoHeaders  bool
	flowsWatch      bool
)

var flowsCmd = &cobra.Command{
	Use:   "flows",
	Short: "Capture and display TCP flows in real-time",
	Long: `Capture TCP connect events in real-time and display source/destination.

Default collects for 10 seconds then exits.
Use -w for continuous display (Ctrl+D or Ctrl+C to stop).
Use --no-headers to suppress progress messages (useful for piping).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if flowsDuration > 0 && !flowsWatch {
					extra = append(extra, "--duration", flowsDuration.String())
				}
				if flowsNoResolve {
					extra = append(extra, "-n")
				}
				if flowsResolvePod {
					extra = append(extra, "--pod")
				}
				if flowsResolveSvc {
					extra = append(extra, "--svc")
				}
				if flowsNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if flowsWatch {
					extra = append(extra, "-w")
				}
				return flow.RunInKind("flows", extra...)
			}
			return err
		}
		defer c.Close()

		var log io.Writer = os.Stderr
		if flowsNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case flowsNoResolve:
			_, _ = fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case flowsResolvePod:
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

		printFlow := func(ev flow.FlowEvent) {
			fmt.Printf("%s:%d → %s:%d [pid=%d] (%s)\n",
				r.Resolve(ev.SrcIP), ev.SrcPort,
				r.Resolve(ev.DstIP), ev.DstPort,
				ev.PID, ev.Comm)
		}

		if flowsWatch {
			if !flowsNoHeaders {
				_, _ = fmt.Fprintln(log, "Capturing TCP flows... Ctrl+D or Ctrl+C to stop.")
			}
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			defer signal.Stop(sig)

			done := make(chan struct{})
			go func() {
				buf := make([]byte, 1)
				_, _ = os.Stdin.Read(buf)
				close(done)
			}()
			for {
				select {
				case <-sig:
					return nil
				case <-done:
					return nil
				default:
				}
				ev, err := c.Read()
				if err != nil {
					return nil
				}
				printFlow(ev)
			}
		}

		if flowsDuration > 0 {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			defer signal.Stop(sig)

			_, _ = fmt.Fprintf(log, "Collecting flows for %s...\n", flowsDuration)
			timer := time.After(flowsDuration)
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
				printFlow(ev)
			}
		}
		return nil
	},
}

func init() {
	flowsCmd.Flags().DurationVarP(&flowsDuration, "duration", "d", 10*time.Second, "Collection duration")
	flowsCmd.Flags().BoolVarP(&flowsNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	flowsCmd.Flags().BoolVarP(&flowsResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	flowsCmd.Flags().BoolVarP(&flowsResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	flowsCmd.Flags().BoolVarP(&flowsNoHeaders, "no-headers", "", false, "Suppress progress messages")
	flowsCmd.Flags().BoolVarP(&flowsWatch, "watch", "w", false, "Continuous display (Ctrl+D or Ctrl+C to stop)")
	rootCmd.AddCommand(flowsCmd)
}
