package flow

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"

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

	lastErr := errors.New("no reachable kind nodes")
	for _, node := range nodes {
		if err := copyToNode(node, data); err != nil {
			lastErr = err
			continue
		}
		args := []string{"docker", "exec", "-i", node, "/usr/local/bin/kubectl-detective", subcommand}
		args = append(args, extraArgs...)
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return lastErr
}

func copyToNode(node string, data []byte) error {
	cmd := exec.Command("docker", "exec", "-i", node, "sh", "-c",
		"rm -f /usr/local/bin/kubectl-detective && cat > /usr/local/bin/kubectl-detective && chmod +x /usr/local/bin/kubectl-detective")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy to %s: %w\n%s", node, err, string(out))
	}
	return nil
}

func listKindNodes() ([]string, error) {
	labels := []string{
		"io.x-k8s.kind.role",
	}
	for _, label := range labels {
		out, err := exec.Command("docker", "ps", "--filter", "label="+label, "--format", "{{.Names}}").Output()
		if err != nil {
			continue
		}
		nodes := strings.Fields(string(out))
		if len(nodes) > 0 {
			return nodes, nil
		}
	}
	return nil, nil
}

type Collector struct {
	rd        *ringbuf.Reader
	kp        link.Link
	kpTx      link.Link
	kpRx      link.Link
	kpRetrans link.Link
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
		kp.Close()
		coll.Close()
		return nil, fmt.Errorf("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		kp.Close()
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
	c.rd.Close()
	c.kp.Close()
	if c.kpTx != nil {
		c.kpTx.Close()
	}
	if c.kpRx != nil {
		c.kpRx.Close()
	}
	if c.kpRetrans != nil {
		c.kpRetrans.Close()
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
