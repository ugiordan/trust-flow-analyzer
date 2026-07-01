package platform

import "testing"

func TestNewKnowledge(t *testing.T) {
	k := NewKnowledge()
	if k == nil {
		t.Fatal("NewKnowledge returned nil")
	}
	if len(k.entries) == 0 {
		t.Fatal("NewKnowledge returned empty knowledge base")
	}
}

func TestLookupKnown(t *testing.T) {
	k := NewKnowledge()

	tests := []struct {
		field          string
		wantKnown      bool
		wantPermissive string
	}{
		{"audiences", true, "PERMISSIVE"},
		{"AllowedGroups", true, "PERMISSIVE"},
		{"EmailDomain", true, "PERMISSIVE"},
		{"InsecureSkipVerify", true, "RESTRICTIVE"},
		{"ServiceAccountName", true, "NEUTRAL"},
		{"UnknownField", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			sem, known := k.Lookup(tt.field)
			if known != tt.wantKnown {
				t.Errorf("Lookup(%q) known = %v, want %v", tt.field, known, tt.wantKnown)
			}
			if known && sem.Permissiveness != tt.wantPermissive {
				t.Errorf("Lookup(%q) permissiveness = %q, want %q", tt.field, sem.Permissiveness, tt.wantPermissive)
			}
		})
	}
}

func TestLookupEmptyMeaning(t *testing.T) {
	k := NewKnowledge()

	sem, ok := k.Lookup("audiences")
	if !ok {
		t.Fatal("audiences not found")
	}
	if sem.EmptyMeaning == "" {
		t.Error("audiences EmptyMeaning is empty")
	}
}
