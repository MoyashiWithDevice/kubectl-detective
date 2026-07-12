package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/moyashiwithdevice/kubectl-detective/internal/export"
	"github.com/moyashiwithdevice/kubectl-detective/internal/flow"
	"github.com/moyashiwithdevice/kubectl-detective/internal/graph"
	"github.com/moyashiwithdevice/kubectl-detective/internal/kubernetes"
	"github.com/moyashiwithdevice/kubectl-detective/internal/resolver"

	"github.com/spf13/cobra"
)

var (
	mapNoResolve  bool
	mapResolvePod bool
	mapResolveSvc bool
	mapDuration   time.Duration
	mapNoHeaders  bool
	mapWatch      bool
	mapFormat     string
	mapFile       string
)

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Show service dependency map",
	Long: `Collect TCP flows and display a service dependency map.
Default output is ASCII art.
Use --format to export as csv, json, html, mermaid, or ascii.
Use --file (-F) to write to a file instead of stdout.
Use -w for continuous collection (Ctrl+D to show results, Ctrl+C to quit).
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
				if mapResolveSvc {
					extra = append(extra, "--svc")
				}
				if mapDuration > 0 && !mapWatch {
					extra = append(extra, "--duration", mapDuration.String())
				}
				if mapNoHeaders {
					extra = append(extra, "--no-headers")
				}
				if mapWatch {
					extra = append(extra, "-w")
				}
				if mapFormat != "" {
					extra = append(extra, "--format", mapFormat)
				}
				if mapFile != "" {
					f, err := os.Create(mapFile)
					if err != nil {
						return fmt.Errorf("create output file: %w", err)
					}
					defer func() { _ = f.Close() }()
					return flow.RunInKindTo("map", f, extra...)
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
			_, _ = fmt.Fprintln(log, "resolver: disabled (-n)")
			r = resolver.NewPod(nil, false)
		case mapResolvePod:
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

		g := graph.New()

		if mapWatch {
			interrupted := runMapWatch(c, r, g, log)
			if interrupted {
				return nil
			}
		} else if mapDuration > 0 {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			defer signal.Stop(sig)

			_, _ = fmt.Fprintf(log, "Collecting flows for %s...\n", mapDuration)
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
		}

		format := resolveMapFormat()

		rpt := export.NewReport(g, mapDuration)

		var out io.Writer = os.Stdout
		if mapFile != "" {
			f, err := os.Create(mapFile)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer func() { _ = f.Close() }()
			out = f
			_, _ = fmt.Fprintf(log, "Writing %s to %s\n", format, mapFile)
		}

		switch format {
		case "csv":
			return export.WriteCSV(out, rpt)
		case "json":
			return export.WriteJSON(out, rpt)
		case "html":
			return export.WriteHTML(out, rpt)
		case "mermaid":
			_, err := fmt.Fprint(out, g.Mermaid())
			return err
		default:
			if !mapNoHeaders && mapFile == "" {
				_, _ = fmt.Fprint(out, "Service Map\n═══════════\n\n")
			}
			_, err := fmt.Fprint(out, g.ASCII())
			return err
		}
	},
}

// runMapWatch collects flows continuously. Returns true if interrupted by Ctrl+C.
func runMapWatch(c *flow.Collector, r resolver.Resolver, g *graph.Graph, log io.Writer) bool {
	if !mapNoHeaders {
		_, _ = fmt.Fprintln(log, "Collecting flows... Ctrl+D to show results, Ctrl+C to quit.")
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
			return true
		case <-done:
			return false
		default:
		}
		ev, err := c.Read()
		if err != nil {
			return false
		}
		g.AddEdge(
			r.Resolve(ev.SrcIP),
			r.Resolve(ev.DstIP),
		)
	}
}

func resolveMapFormat() string {
	f := strings.ToLower(mapFormat)
	if f != "" {
		return f
	}
	return "ascii"
}

func init() {
	mapCmd.Flags().StringVarP(&mapFormat, "format", "f", "", "Output format: ascii, mermaid, csv, json, html (default: ascii)")
	mapCmd.Flags().StringVarP(&mapFile, "file", "F", "", "Write output to file instead of stdout")
	mapCmd.Flags().BoolVarP(&mapNoHeaders, "no-headers", "", false, "Suppress progress messages")
	mapCmd.Flags().BoolVarP(&mapNoResolve, "no-resolve", "n", false, "Skip name resolution (show IPs only)")
	mapCmd.Flags().BoolVarP(&mapResolvePod, "pod", "", false, "Resolve IPs to Pod names")
	mapCmd.Flags().BoolVarP(&mapResolveSvc, "svc", "", false, "Resolve IPs to Service names")
	mapCmd.Flags().BoolVarP(&mapWatch, "watch", "w", false, "Continuous collection (Ctrl+D to show, Ctrl+C to quit)")
	mapCmd.Flags().DurationVarP(&mapDuration, "duration", "d", 10*time.Second, "Collection duration")
	rootCmd.AddCommand(mapCmd)
}
