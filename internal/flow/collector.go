package flow

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var ErrNoPrivileges = errors.New("eBPF requires privileges")

//go:embed tcp_connect.bpf.o
var bpfObj []byte

type FlowEvent struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	PID     uint32
	Comm    string
}

// nodeKubeconfig is the path used inside kind nodes for API access.
const nodeKubeconfig = "/tmp/kubectl-detective.kubeconfig"

// RunInKindTo is like RunInKind but writes the container's stdout to the given writer
// instead of os.Stdout. Use this when the output should go to a file on the host.
func RunInKindTo(subcommand string, stdout io.Writer, extraArgs ...string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("eBPF requires privileges but cannot detect binary path: %w", err)
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("eBPF requires privileges: run inside kind node, or use: sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_ipc_lock+eip %s", self)
	}

	nodes, err := listKindNodes()
	if err != nil || len(nodes) == 0 {
		return fmt.Errorf("kind cluster not found: start a kind cluster and try again, or use: sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_ipc_lock+eip %s", self)
	}

	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}

	nodes = preferWorkers(nodes)

	kubeconfig, err := loadKindAPIKubeconfig(nodes)
	if err != nil {
		kubeconfig = nil
	}

	lastErr := errors.New("no reachable kind nodes")
	for _, node := range nodes {
		if err := copyToNode(node, data); err != nil {
			lastErr = err
			continue
		}
		if len(kubeconfig) > 0 {
			if err := writeToNode(node, nodeKubeconfig, kubeconfig); err != nil {
				lastErr = err
				continue
			}
		}

		args := []string{"docker", "exec", "-i"}
		if len(kubeconfig) > 0 {
			args = append(args, "-e", "KUBECONFIG="+nodeKubeconfig)
		}
		args = append(args, node, "/usr/local/bin/kubectl-detective", subcommand)
		args = append(args, extraArgs...)
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return lastErr
}

func RunInKind(subcommand string, extraArgs ...string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("eBPF requires privileges but cannot detect binary path: %w", err)
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("eBPF requires privileges: run inside kind node, or use: sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_ipc_lock+eip %s", self)
	}

	nodes, err := listKindNodes()
	if err != nil || len(nodes) == 0 {
		return fmt.Errorf("kind cluster not found: start a kind cluster and try again, or use: sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_ipc_lock+eip %s", self)
	}

	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}

	// Prefer workers for eBPF (pod traffic); control-plane is still a fallback.
	nodes = preferWorkers(nodes)

	kubeconfig, err := loadKindAPIKubeconfig(nodes)
	if err != nil {
		// Resolution may not be needed (e.g. -n); continue without it.
		kubeconfig = nil
	}

	lastErr := errors.New("no reachable kind nodes")
	for _, node := range nodes {
		if err := copyToNode(node, data); err != nil {
			lastErr = err
			continue
		}
		if len(kubeconfig) > 0 {
			if err := writeToNode(node, nodeKubeconfig, kubeconfig); err != nil {
				lastErr = err
				continue
			}
		}

		args := []string{"docker", "exec", "-i"}
		if len(kubeconfig) > 0 {
			args = append(args, "-e", "KUBECONFIG="+nodeKubeconfig)
		}
		args = append(args, node, "/usr/local/bin/kubectl-detective", subcommand)
		args = append(args, extraArgs...)
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return lastErr
}

// RunAgentInKind deploys both the aggregator and agent inside the same kind node
// so they can communicate via localhost. Used when the local user lacks eBPF
// privileges and the aggregator address is loopback-unreachable from kind containers.
func RunAgentInKind(nodeName string, interval time.Duration, aggregatorAddr string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("eBPF requires privileges but cannot detect binary path: %w", err)
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("eBPF requires privileges: run as root or use: sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_ipc_lock+eip %s", self)
	}

	nodes, err := listKindNodes()
	if err != nil || len(nodes) == 0 {
		return fmt.Errorf("kind cluster not found: start a kind cluster and try again")
	}
	nodes = preferWorkers(nodes)
	node := nodes[0]

	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	if err := copyToNode(node, data); err != nil {
		return fmt.Errorf("copy binary to kind node: %w", err)
	}

	// Stop any previous aggregator/agent inside the node.
	_ = exec.Command("docker", "exec", node, "pkill", "-9", "-f", "kubectl-detective").Run()
	time.Sleep(500 * time.Millisecond)

	// Preserve the user's requested port so the in-kind aggregator matches expectations.
	_, port, _ := net.SplitHostPort(aggregatorAddr)
	if port == "" {
		port = "50051"
	}
	inNodeAgg := "localhost:" + port

	// Start aggregator inside the kind node in the background.
	aggArgs := fmt.Sprintf("nohup /usr/local/bin/kubectl-detective aggregator --listen=%s >/dev/null 2>&1 &", inNodeAgg)
	if err := exec.Command("docker", "exec", "-d", node, "sh", "-c", aggArgs).Run(); err != nil {
		return fmt.Errorf("start aggregator in kind: %w", err)
	}
	time.Sleep(1 * time.Second)

	// Start the agent inside the same node.
	agentArgs := []string{"exec", "-i", node, "/usr/local/bin/kubectl-detective", "agent",
		"--aggregator", inNodeAgg,
		"--interval", interval.String(),
	}
	if nodeName != "" {
		agentArgs = append(agentArgs, "--node", nodeName)
	}

	fmt.Fprintf(os.Stderr, "agent (kind): localhost is unreachable from kind containers; running aggregator + agent inside %s on %s\n", node, inNodeAgg)
	cmd := exec.Command("docker", agentArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyToNode(node string, data []byte) error {
	return writeToNode(node, "/usr/local/bin/kubectl-detective", data)
}

func writeToNode(node, path string, data []byte) error {
	var script string
	if path == "/usr/local/bin/kubectl-detective" {
		script = fmt.Sprintf("rm -f '%s' && cat > '%s' && chmod +x '%s'", path, path, path)
	} else {
		script = fmt.Sprintf("mkdir -p \"$(dirname '%s')\" && cat > '%s' && chmod 600 '%s'", path, path, path)
	}
	cmd := exec.Command("docker", "exec", "-i", node, "sh", "-c", script)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("write %s on %s: %w\n%s", path, node, err, string(out))
	}
	return nil
}

// loadKindAPIKubeconfig returns a kubeconfig usable from inside kind nodes.
// Host kubeconfig points at 127.0.0.1:<mapped-port> and does not work in-node;
// control-plane admin.conf uses the in-cluster API hostname.
func loadKindAPIKubeconfig(nodes []string) ([]byte, error) {
	// Prefer admin.conf from a control-plane container.
	for _, node := range nodes {
		if !isControlPlane(node) {
			continue
		}
		out, err := exec.Command("docker", "exec", node, "cat", "/etc/kubernetes/admin.conf").Output()
		if err == nil && len(out) > 0 {
			return out, nil
		}
	}

	// Discover control-plane even if not in the preferred run list.
	cpNodes, _ := listKindNodesByRole("control-plane")
	for _, node := range cpNodes {
		out, err := exec.Command("docker", "exec", node, "cat", "/etc/kubernetes/admin.conf").Output()
		if err == nil && len(out) > 0 {
			return out, nil
		}
	}

	return nil, fmt.Errorf("kind control-plane admin.conf not found")
}

func isControlPlane(node string) bool {
	out, err := exec.Command("docker", "inspect", "-f",
		`{{index .Config.Labels "io.x-k8s.kind.role"}}`, node).Output()
	if err != nil {
		return strings.Contains(node, "control-plane")
	}
	return strings.TrimSpace(string(out)) == "control-plane"
}

func preferWorkers(nodes []string) []string {
	var workers, others []string
	for _, n := range nodes {
		if isControlPlane(n) {
			others = append(others, n)
		} else {
			workers = append(workers, n)
		}
	}
	return append(workers, others...)
}

func listKindNodes() ([]string, error) {
	return listKindNodesByRole("")
}

func listKindNodesByRole(role string) ([]string, error) {
	args := []string{"ps", "--filter", "label=io.x-k8s.kind.role", "--format", "{{.Names}}"}
	if role != "" {
		args = []string{"ps", "--filter", "label=io.x-k8s.kind.role=" + role, "--format", "{{.Names}}"}
	}
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, err
	}
	nodes := strings.Fields(string(out))
	if len(nodes) == 0 {
		return nil, nil
	}
	return nodes, nil
}

type Collector struct {
	rd        *ringbuf.Reader
	kp        link.Link
	kpTx      link.Link
	kpRx      link.Link
	kpRetrans link.Link
	kpRTT     link.Link
	kpDNSSend link.Link
	kpDNSRecv link.Link
	coll      *ebpf.Collection
}

func NewCollector() (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, ErrNoPrivileges
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObj))
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	prog := coll.Programs["kprobe__tcp_connect"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program not found")
	}

	kp, err := link.Kprobe("tcp_connect", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		_ = kp.Close()
		coll.Close()
		return nil, fmt.Errorf("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		_ = kp.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	c := &Collector{rd: rd, kp: kp, coll: coll}

	if progTx := coll.Programs["kprobe__tcp_sendmsg"]; progTx != nil {
		if kpTx, err := link.Kprobe("tcp_sendmsg", progTx, nil); err == nil {
			c.kpTx = kpTx
		}
	}
	if progRx := coll.Programs["kprobe__tcp_cleanup_rbuf"]; progRx != nil {
		if kpRx, err := link.Kprobe("tcp_cleanup_rbuf", progRx, nil); err == nil {
			c.kpRx = kpRx
		}
	}
	if progRetrans := coll.Programs["kprobe__tcp_retransmit_skb"]; progRetrans != nil {
		if kpRetrans, err := link.Kprobe("tcp_retransmit_skb", progRetrans, nil); err == nil {
			c.kpRetrans = kpRetrans
		}
	}
	if progRTT := coll.Programs["kprobe__tcp_rcv_established"]; progRTT != nil {
		if kpRTT, err := link.Kprobe("tcp_rcv_established", progRTT, nil); err == nil {
			c.kpRTT = kpRTT
		}
	}
	if progDNSSend := coll.Programs["kprobe__udp_sendmsg"]; progDNSSend != nil {
		if kpDNS, err := link.Kprobe("udp_sendmsg", progDNSSend, nil); err == nil {
			c.kpDNSSend = kpDNS
		}
	}
	if progDNSRecv := coll.Programs["kprobe__udp_rcv"]; progDNSRecv != nil {
		if kpDNS, err := link.Kprobe("udp_rcv", progDNSRecv, nil); err == nil {
			c.kpDNSRecv = kpDNS
		}
	}

	return c, nil
}

func (c *Collector) HasThroughput() bool {
	return c.coll.Maps["throughput_map"] != nil
}

type ThroughputKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

type ThroughputVal struct {
	TxBytes uint64
	RxBytes uint64
}

func (c *Collector) ReadThroughput(fn func(ThroughputKey, ThroughputVal) error) error {
	tpMap := c.coll.Maps["throughput_map"]
	if tpMap == nil {
		return fmt.Errorf("throughput_map not available")
	}
	iter := tpMap.Iterate()
	var key ThroughputKey
	var val ThroughputVal
	for iter.Next(&key, &val) {
		if err := fn(key, val); err != nil {
			return err
		}
	}
	return iter.Err()
}

type RetransKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

type RetransVal struct {
	Count uint64
}

func (c *Collector) HasRetrans() bool {
	return c.coll.Maps["retrans_map"] != nil
}

func (c *Collector) ReadRetrans(fn func(RetransKey, RetransVal) error) error {
	rMap := c.coll.Maps["retrans_map"]
	if rMap == nil {
		return fmt.Errorf("retrans_map not available")
	}
	iter := rMap.Iterate()
	var key RetransKey
	var val RetransVal
	for iter.Next(&key, &val) {
		if err := fn(key, val); err != nil {
			return err
		}
	}
	return iter.Err()
}

// RTTHistBuckets must match RTT_HIST_BUCKETS in bpf/tcp_connect.bpf.c.
const RTTHistBuckets = 27

type RTTKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// RTTVal matches struct rtt_val_t in bpf/tcp_connect.bpf.c.
// Trailing pad is required: C aligns the struct to 8 bytes (sizeof = 136).
type RTTVal struct {
	SumUs uint64
	Count uint64
	MinUs uint32
	MaxUs uint32
	Hist  [RTTHistBuckets]uint32
	_     uint32
}

func (c *Collector) HasRTT() bool {
	return c.coll.Maps["rtt_map"] != nil && c.kpRTT != nil
}

func (c *Collector) ReadRTT(fn func(RTTKey, RTTVal) error) error {
	rMap := c.coll.Maps["rtt_map"]
	if rMap == nil {
		return fmt.Errorf("rtt_map not available")
	}
	iter := rMap.Iterate()
	var key RTTKey
	var val RTTVal
	for iter.Next(&key, &val) {
		if err := fn(key, val); err != nil {
			return err
		}
	}
	return iter.Err()
}

// DNS-related types and methods.

func (c *Collector) HasDNS() bool {
	return c.coll.Maps["dns_stats_map"] != nil && c.kpDNSSend != nil && c.kpDNSRecv != nil
}

type DNSStatsKey struct {
	SrcIP [4]byte
	DstIP [4]byte
}

// DNSStatsVal matches struct dns_stats_val_t in bpf/tcp_connect.bpf.c.
// Trailing pad is required: C aligns the struct to 8 bytes (sizeof = 136).
type DNSStatsVal struct {
	Count uint64
	SumUs uint64
	MinUs uint32
	MaxUs uint32
	Hist  [RTTHistBuckets]uint32
	_     uint32
}

func (c *Collector) ReadDNSStats(fn func(DNSStatsKey, DNSStatsVal) error) error {
	dMap := c.coll.Maps["dns_stats_map"]
	if dMap == nil {
		return fmt.Errorf("dns_stats_map not available")
	}
	iter := dMap.Iterate()
	var key DNSStatsKey
	var val DNSStatsVal
	for iter.Next(&key, &val) {
		if err := fn(key, val); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (c *Collector) Read() (FlowEvent, error) {
	record, err := c.rd.Read()
	if err != nil {
		return FlowEvent{}, err
	}

	data := record.RawSample
	if len(data) < 28 {
		return c.Read()
	}

	return FlowEvent{
		SrcIP:   net.IP(data[0:4]),
		DstIP:   net.IP(data[4:8]),
		SrcPort: binary.LittleEndian.Uint16(data[8:10]),
		DstPort: binary.BigEndian.Uint16(data[10:12]),
		PID:     binary.LittleEndian.Uint32(data[12:16]),
		Comm:    string(bytes.TrimRight(data[16:32], "\x00")),
	}, nil
}

func (c *Collector) Close() {
	_ = c.rd.Close()
	_ = c.kp.Close()
	if c.kpTx != nil {
		_ = c.kpTx.Close()
	}
	if c.kpRx != nil {
		_ = c.kpRx.Close()
	}
	if c.kpRetrans != nil {
		_ = c.kpRetrans.Close()
	}
	if c.kpRTT != nil {
		_ = c.kpRTT.Close()
	}
	if c.kpDNSSend != nil {
		_ = c.kpDNSSend.Close()
	}
	if c.kpDNSRecv != nil {
		_ = c.kpDNSRecv.Close()
	}
	c.coll.Close()
}

func Run(out chan<- FlowEvent) error {
	c, err := NewCollector()
	if err != nil {
		return err
	}
	defer c.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		c.Close()
	}()

	for {
		ev, err := c.Read()
		if err != nil {
			return err
		}
		out <- ev
	}
}
