package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var logWriter io.Writer = os.Stderr

func SetLogOutput(w io.Writer) {
	logWriter = w
}

type Resolver interface {
	Resolve(ip net.IP) string
	Close()
}

type PodResolver struct {
	mu      sync.RWMutex
	podIPs  map[string]string
	stopCh  chan struct{}
	enabled bool
}

func NewPod(client kubernetes.Interface, enabled bool) *PodResolver {
	r := &PodResolver{
		podIPs:  make(map[string]string),
		stopCh:  make(chan struct{}),
		enabled: enabled,
	}
	if !enabled {
		return r
	}

	pods, err := client.CoreV1().Pods(v1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(pod): List pods failed: %v\n", err)
	} else {
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.PodIP != "" {
				r.podIPs[p.Status.PodIP] = p.Name
			}
		}
		_, _ = fmt.Fprintf(logWriter, "resolver(pod): loaded %d pods (%d with IP)\n", len(pods.Items), len(r.podIPs))
	}

	go r.watchPods(client)
	return r
}

func (r *PodResolver) watchPods(client kubernetes.Interface) {
	wi, err := client.CoreV1().Pods(v1.NamespaceAll).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(pod): Watch pods failed: %v\n", err)
		return
	}
	defer wi.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case ev, ok := <-wi.ResultChan():
			if !ok {
				_, _ = fmt.Fprintf(logWriter, "resolver(pod): Watch channel closed, restarting...\n")
				go r.watchPods(client)
				return
			}
			pod, ok := ev.Object.(*v1.Pod)
			if !ok {
				continue
			}
			switch ev.Type {
			case "ADDED", "MODIFIED":
				if pod.Status.PodIP != "" {
					r.mu.Lock()
					r.podIPs[pod.Status.PodIP] = pod.Name
					r.mu.Unlock()
				}
			case "DELETED":
				if pod.Status.PodIP != "" {
					r.mu.Lock()
					delete(r.podIPs, pod.Status.PodIP)
					r.mu.Unlock()
				}
			}
		}
	}
}

func (r *PodResolver) Resolve(ip net.IP) string {
	if !r.enabled || ip == nil {
		return ip.String()
	}
	r.mu.RLock()
	name, ok := r.podIPs[ip.String()]
	r.mu.RUnlock()
	if ok {
		return name
	}
	return ip.String()
}

func (r *PodResolver) Close() {
	close(r.stopCh)
}
