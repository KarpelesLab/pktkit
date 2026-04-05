package slirp

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func TestNamespaceCreateDelete(t *testing.T) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer p.Close()

	ns, err := p.Create("test1")
	if err != nil {
		t.Fatal(err)
	}
	if ns == nil {
		t.Fatal("Create returned nil")
	}
	if ns.Device() == nil {
		t.Fatal("Device returned nil")
	}

	// Duplicate should fail.
	_, err = p.Create("test1")
	if err == nil {
		t.Fatal("expected error for duplicate namespace")
	}

	// Delete.
	if err := p.Delete("test1"); err != nil {
		t.Fatal(err)
	}

	// Delete again should fail.
	if err := p.Delete("test1"); err == nil {
		t.Fatal("expected error for missing namespace")
	}
}

func TestNamespaceGet(t *testing.T) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer p.Close()

	if ns := p.Get("x"); ns != nil {
		t.Fatal("Get should return nil for missing namespace")
	}

	created, _ := p.Create("x")
	got := p.Get("x")
	if got != created {
		t.Fatal("Get should return the same namespace that was created")
	}
}

func TestNamespaceList(t *testing.T) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer p.Close()

	p.Create("charlie")
	p.Create("alpha")
	p.Create("bravo")

	names := p.List()
	if len(names) != 3 {
		t.Fatalf("List returned %d names, want 3", len(names))
	}
	if names[0] != "alpha" || names[1] != "bravo" || names[2] != "charlie" {
		t.Errorf("List = %v, want [alpha bravo charlie]", names)
	}
}

func TestNamespaceCloseAll(t *testing.T) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})

	p.Create("a")
	p.Create("b")
	p.Create("c")

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	if names := p.List(); len(names) != 0 {
		t.Errorf("List after Close: %v", names)
	}
}

func TestNamespaceConcurrent(t *testing.T) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer p.Close()

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("ns-%d", i)
			ns, err := p.Create(name)
			if err != nil {
				t.Error(err)
				return
			}
			_ = ns.Device()
			_ = p.List()
			_ = p.Get(name)
		}()
	}
	wg.Wait()

	names := p.List()
	if len(names) != 20 {
		t.Errorf("expected 20 namespaces, got %d", len(names))
	}

	// Concurrent delete.
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Delete(fmt.Sprintf("ns-%d", i))
		}()
	}
	wg.Wait()

	if names := p.List(); len(names) != 0 {
		t.Errorf("expected 0 namespaces after delete, got %d", len(names))
	}
}

func BenchmarkNamespaceGet(b *testing.B) {
	p := NewProvider(ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer p.Close()
	p.Create("bench")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Get("bench")
	}
}
