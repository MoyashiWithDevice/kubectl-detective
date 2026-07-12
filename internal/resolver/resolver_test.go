package resolver

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolve_Disabled(t *testing.T) {
	r := NewPod(nil, false)
	defer r.Close()

	ip := net.ParseIP("10.0.0.1")
	got := r.Resolve(ip)
	if got != "10.0.0.1" {
		t.Fatalf("expected IP string, got %s", got)
	}
}

func TestResolve_Found(t *testing.T) {
	client := fake.NewSimpleClientset()

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: "10.0.0.1",
		},
	}
	_, _ = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})

	r := NewPod(client, true)
	defer r.Close()

	ip := net.ParseIP("10.0.0.1")
	got := r.Resolve(ip)
	if got != "nginx" {
		t.Fatalf("expected 'nginx', got %s", got)
	}
}

func TestResolve_NotFound(t *testing.T) {
	client := fake.NewSimpleClientset()

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: "10.0.0.1",
		},
	}
	_, _ = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})

	r := NewPod(client, true)
	defer r.Close()

	ip := net.ParseIP("10.0.0.2")
	got := r.Resolve(ip)
	if got != "10.0.0.2" {
		t.Fatalf("expected '10.0.0.2', got %s", got)
	}
}

func TestResolve_MultiplePods(t *testing.T) {
	client := fake.NewSimpleClientset()

	pods := []*v1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "default"}, Status: v1.PodStatus{PodIP: "10.0.0.1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"}, Status: v1.PodStatus{PodIP: "10.0.0.2"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "default"}, Status: v1.PodStatus{PodIP: "10.0.0.3"}},
	}
	for _, pod := range pods {
		_, _ = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	}

	r := NewPod(client, true)
	defer r.Close()

	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "frontend"},
		{"10.0.0.2", "api"},
		{"10.0.0.3", "redis"},
		{"10.0.0.4", "10.0.0.4"},
	}

	for _, tt := range tests {
		got := r.Resolve(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("Resolve(%s) = %s, want %s", tt.ip, got, tt.want)
		}
	}
}

func TestServiceResolver_Disabled(t *testing.T) {
	r := NewService(nil, false)
	defer r.Close()

	ip := net.ParseIP("10.0.0.1")
	got := r.Resolve(ip)
	if got != "10.0.0.1" {
		t.Fatalf("expected IP string, got %s", got)
	}
}

func TestServiceResolver_ClusterIP(t *testing.T) {
	client := fake.NewSimpleClientset()

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "10.96.0.1",
		},
	}
	_, _ = client.CoreV1().Services("default").Create(context.TODO(), svc, metav1.CreateOptions{})

	r := NewService(client, true)
	defer r.Close()

	ip := net.ParseIP("10.96.0.1")
	got := r.Resolve(ip)
	if got != "my-svc" {
		t.Fatalf("expected 'my-svc', got %s", got)
	}
}

func TestServiceResolver_ExternalIP(t *testing.T) {
	client := fake.NewSimpleClientset()

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			ClusterIP:   "10.96.0.1",
			ExternalIPs: []string{"203.0.113.1"},
		},
	}
	_, _ = client.CoreV1().Services("default").Create(context.TODO(), svc, metav1.CreateOptions{})

	r := NewService(client, true)
	defer r.Close()

	tests := []struct {
		ip   string
		want string
	}{
		{"10.96.0.1", "my-svc"},
		{"203.0.113.1", "my-svc"},
		{"10.0.0.9", "10.0.0.9"},
	}
	for _, tt := range tests {
		got := r.Resolve(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("Resolve(%s) = %s, want %s", tt.ip, got, tt.want)
		}
	}
}

func TestServiceResolver_FallbackToPod(t *testing.T) {
	client := fake.NewSimpleClientset()

	// Pod without a Service
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "standalone",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: "10.244.0.5",
		},
	}
	_, _ = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})

	r := NewService(client, true)
	defer r.Close()

	// Pod IP should resolve to pod name (no service maps it)
	got := r.Resolve(net.ParseIP("10.244.0.5"))
	if got != "standalone" {
		t.Fatalf("expected 'standalone' (pod fallback), got %s", got)
	}
}

func TestServiceResolver_ServicePreferred(t *testing.T) {
	client := fake.NewSimpleClientset()

	// Pod belongs to a service
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-abc",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: "10.244.0.5",
		},
	}
	_, _ = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "10.96.0.1",
		},
	}
	_, _ = client.CoreV1().Services("default").Create(context.TODO(), svc, metav1.CreateOptions{})

	// EndpointSlice linking the Pod IP to the Service
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "api"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.244.0.5"}},
		},
	}
	_, _ = client.DiscoveryV1().EndpointSlices("default").Create(context.TODO(), eps, metav1.CreateOptions{})

	r := NewService(client, true)
	defer r.Close()

	// Same IP → Service name preferred over Pod name
	got := r.Resolve(net.ParseIP("10.244.0.5"))
	if got != "api" {
		t.Fatalf("expected 'api' (service preferred), got %s", got)
	}
}
