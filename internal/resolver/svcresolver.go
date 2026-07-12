package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ServiceResolver struct {
	mu      sync.RWMutex
	ipSvc   map[string]string
	ipPod   map[string]string
	stopCh  chan struct{}
	enabled bool
}

func NewService(client kubernetes.Interface, enabled bool) *ServiceResolver {
	r := &ServiceResolver{
		ipSvc:   make(map[string]string),
		ipPod:   make(map[string]string),
		stopCh:  make(chan struct{}),
		enabled: enabled,
	}
	if !enabled {
		return r
	}

	// 1. List Pods (fallback: IP → Pod name)
	pods, err := client.CoreV1().Pods(v1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): List pods failed: %v\n", err)
	} else {
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.PodIP != "" {
				r.ipPod[p.Status.PodIP] = p.Name
			}
		}
	}

	// 2. List Services (ClusterIP, ExternalIP, LoadBalancer IP)
	svcs, err := client.CoreV1().Services(v1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): List Services failed: %v\n", err)
	} else {
		for i := range svcs.Items {
			r.addService(&svcs.Items[i])
		}
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): loaded %d services (%d svc IPs, %d pod IPs)\n",
			len(svcs.Items), len(r.ipSvc), len(r.ipPod))
	}

	// 3. List EndpointSlices (PodIP → Service name)
	eps, err := client.DiscoveryV1().EndpointSlices(v1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): List EndpointSlices failed: %v\n", err)
	} else {
		for i := range eps.Items {
			r.addSlice(&eps.Items[i])
		}
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): loaded %d endpointslices (%d svc IPs, %d pod IPs)\n",
			len(eps.Items), len(r.ipSvc), len(r.ipPod))
	}

	go r.watchPods(client)
	go r.watchServices(client)
	go r.watchSlices(client)
	return r
}

func (r *ServiceResolver) addPod(pod *v1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}
	r.mu.Lock()
	r.ipPod[pod.Status.PodIP] = pod.Name
	r.mu.Unlock()
}

func (r *ServiceResolver) addService(svc *v1.Service) {
	r.mu.Lock()
	svcName := svc.Name

	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		r.ipSvc[svc.Spec.ClusterIP] = svcName
	}
	for _, cip := range svc.Spec.ClusterIPs {
		if cip != "" && cip != "None" {
			r.ipSvc[cip] = svcName
		}
	}
	for _, extIP := range svc.Spec.ExternalIPs {
		if extIP != "" {
			r.ipSvc[extIP] = svcName
		}
	}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			r.ipSvc[ingress.IP] = svcName
		}
	}
	r.mu.Unlock()
}

func (r *ServiceResolver) addSlice(slice *discoveryv1.EndpointSlice) {
	svcName := slice.Labels["kubernetes.io/service-name"]
	if svcName == "" {
		return
	}
	r.mu.Lock()
	for _, ep := range slice.Endpoints {
		for _, addr := range ep.Addresses {
			r.ipSvc[addr] = svcName
		}
	}
	r.mu.Unlock()
}

func (r *ServiceResolver) watchPods(client kubernetes.Interface) {
	wi, err := client.CoreV1().Pods(v1.NamespaceAll).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch pods failed: %v\n", err)
		return
	}
	defer wi.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case ev, ok := <-wi.ResultChan():
			if !ok {
				_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch pods channel closed, restarting...\n")
				go r.watchPods(client)
				return
			}
			pod, ok := ev.Object.(*v1.Pod)
			if !ok {
				continue
			}
			switch ev.Type {
			case "ADDED", "MODIFIED":
				r.addPod(pod)
			case "DELETED":
				if pod.Status.PodIP != "" {
					r.mu.Lock()
					delete(r.ipPod, pod.Status.PodIP)
					r.mu.Unlock()
				}
			}
		}
	}
}

func (r *ServiceResolver) watchServices(client kubernetes.Interface) {
	wi, err := client.CoreV1().Services(v1.NamespaceAll).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch Services failed: %v\n", err)
		return
	}
	defer wi.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case ev, ok := <-wi.ResultChan():
			if !ok {
				_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch Services channel closed, restarting...\n")
				go r.watchServices(client)
				return
			}
			svc, ok := ev.Object.(*v1.Service)
			if !ok {
				continue
			}
			switch ev.Type {
			case "ADDED", "MODIFIED":
				r.addService(svc)
			case "DELETED":
				r.mu.Lock()
				svcName := svc.Name
				for k, v := range r.ipSvc {
					if v == svcName {
						delete(r.ipSvc, k)
					}
				}
				r.mu.Unlock()
			}
		}
	}
}

func (r *ServiceResolver) watchSlices(client kubernetes.Interface) {
	wi, err := client.DiscoveryV1().EndpointSlices(v1.NamespaceAll).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch EndpointSlices failed: %v\n", err)
		return
	}
	defer wi.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case ev, ok := <-wi.ResultChan():
			if !ok {
				_, _ = fmt.Fprintf(logWriter, "resolver(svc): Watch EndpointSlices channel closed, restarting...\n")
				go r.watchSlices(client)
				return
			}
			slice, ok := ev.Object.(*discoveryv1.EndpointSlice)
			if !ok {
				continue
			}
			switch ev.Type {
			case "ADDED", "MODIFIED":
				r.addSlice(slice)
			case "DELETED":
				svcName := slice.Labels["kubernetes.io/service-name"]
				r.mu.Lock()
				for _, ep := range slice.Endpoints {
					for _, addr := range ep.Addresses {
						if r.ipSvc[addr] == svcName {
							delete(r.ipSvc, addr)
						}
					}
				}
				r.mu.Unlock()
			}
		}
	}
}

func (r *ServiceResolver) Resolve(ip net.IP) string {
	if !r.enabled || ip == nil {
		return ip.String()
	}
	ipStr := ip.String()
	r.mu.RLock()
	svc, svcOK := r.ipSvc[ipStr]
	pod, podOK := r.ipPod[ipStr]
	r.mu.RUnlock()
	if svcOK {
		return svc
	}
	if podOK {
		return pod
	}
	return ipStr
}

func (r *ServiceResolver) Close() {
	close(r.stopCh)
}
