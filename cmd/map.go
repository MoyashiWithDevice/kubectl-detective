package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"Kubernetes-plugin/internal/flow"
	"Kubernetes-plugin/internal/graph"
	"Kubernetes-plugin/internal/kubernetes"
	"Kubernetes-plugin/internal/resolver"

	"github.com/spf13/cobra"
)

var (
	mapNoResolve  bool
	mapResolvePod bool
	mapResolveSvc bool
	mapDuration   time.Duration
	mapMermaid    bool
	mapNoHeaders  bool
)

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Show service dependency map",
	Long: `Collect TCP flows and display a service dependency map.
Default output is ASCII art. Use --mermaid (-m) for Mermaid format.
Use --no-headers to suppress progress messages (useful for file redirect).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := flow.NewCollector()
		if err != nil {
			if err == flow.ErrNoPrivileges {
				var extra []string
				if mapNoResolve {
					extra = append(extra, "-n")
				}
				if mapResolvePod {
					extra = append(extra, "--pod")
				}
				if mapDuration > 0 {
					extra = append(extra, "--duration", mapDuration.String())
				}
				if mapMermaid {
					extra = append(extra, "-m")
				}
				if mapNoHeaders {
					extra = append(extra, "--no-headers")
				}
				return flow.RunInKind("map", extra...)
			}
			return err
		}
		defer c.Close()

		var log io.Writer = os.Stderr
		if mapNoHeaders {
			log = io.Discard
			resolver.SetLogOutput(io.Discard)
		}

		var r resolver.Resolver
		switch {
		case mapNoResolve:
			fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case mapResolvePod:
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

		g := graph.New()

		if mapDuration > 0 {
			fmt.Fprintf(log, "Collecting flows for %s...\n", mapDuration)
			timer := time.After(mapDuration)
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
				g.AddEdge(
					r.Resolve(ev.SrcIP),
					r.Resolve(ev.DstIP),
				)
			}
		} else {
			fmt.Fprintln(log, "Collecting flows... Press Ctrl+C to stop.")
			go func() {
				<-sig
				c.Close()
			}()
			for {
				ev, err := c.Read()
				if err != nil {
					return err
				}
				g.AddEdge(
					r.Resolve(ev.SrcIP),
					r.Resolve(ev.DstIP),
				)
			}
		}

		if mapMermaid {
			fmt.Print(g.Mermaid())
		} else {
			if !mapNoHeaders {
				fmt.Print("Service Map\n═══════════\n\n")
			}
			fmt.Print(g.ASCII())
		}

		return nil
	},
}

func init() {
	mapCmd.Flags().BoolVarP(&mapMermaid, "mermaid", "m", false, "Output Mermaid format only (for file redirect)")
	mapCmd.Flags().BoolVarP(&mapNoHeaders, "no-headers", "", false, "Suppress progress messages")
	mapCmd.Flags().BoolVarP(&mapNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	mapCmd.Flags().BoolVarP(&mapResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	mapCmd.Flags().BoolVarP(&mapResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	mapCmd.Flags().DurationVarP(&mapDuration, "duration", "d", 10*time.Second, "Collection duration (0 = continuous)")
	rootCmd.AddCommand(mapCmd)
}
