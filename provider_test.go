package porkbun

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

// fakePorkbun serves the parts of the Porkbun API used by DeleteRecords.
type fakePorkbun struct {
	t *testing.T

	mu         sync.Mutex
	records    []pkbnRecord
	deletedIDs []string
}

func newFakePorkbun(t *testing.T, records []pkbnRecord) *fakePorkbun {
	f := &fakePorkbun{t: t, records: records}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	apiBase = srv.URL
	t.Cleanup(func() { apiBase = ApiBase })

	return f
}

func (f *fakePorkbun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if path, ok := strings.CutPrefix(r.URL.Path, "/dns/retrieveByNameType/example.com/"); ok {
		recordType, subdomain, _ := strings.Cut(path, "/")
		name := "example.com"
		if subdomain != "" {
			name = subdomain + ".example.com"
		}
		matches := []pkbnRecord{}
		for _, rec := range f.records {
			if rec.Type == recordType && rec.Name == name {
				matches = append(matches, rec)
			}
		}
		json.NewEncoder(w).Encode(pkbnRecordsResponse{Status: "SUCCESS", Records: matches})
		return
	}

	if id, ok := strings.CutPrefix(r.URL.Path, "/dns/delete/example.com/"); ok {
		for i, rec := range f.records {
			if rec.ID == id {
				f.records = append(f.records[:i], f.records[i+1:]...)
				f.deletedIDs = append(f.deletedIDs, id)
				fmt.Fprint(w, `{"status":"SUCCESS"}`)
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"status":"ERROR","message":"Could not delete record."}`)
		return
	}

	f.t.Errorf("unexpected request: %s", r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

// Two ACME challenges for the same name (e.g. example.com and *.example.com)
// plus an unrelated TXT record with that name.
func challengeRecords() []pkbnRecord {
	return []pkbnRecord{
		{ID: "1", Name: "_acme-challenge.example.com", Type: "TXT", Content: "other", TTL: "600"},
		{ID: "2", Name: "_acme-challenge.example.com", Type: "TXT", Content: "challenge-a", TTL: "600"},
		{ID: "3", Name: "_acme-challenge.example.com", Type: "TXT", Content: "challenge-b", TTL: "600"},
	}
}

func TestDeleteRecords(t *testing.T) {
	testCases := []struct {
		name  string
		input libdns.Record
		want  []string // deleted IDs
	}{
		{
			name:  "matching value",
			input: libdns.TXT{Name: "_acme-challenge", Text: "challenge-a"},
			want:  []string{"2"},
		},
		{
			name:  "empty value",
			input: libdns.RR{Name: "_acme-challenge", Type: "TXT"},
			want:  []string{"1", "2", "3"},
		},
		{
			name:  "no matching value",
			input: libdns.TXT{Name: "_acme-challenge", Text: "missing"},
			want:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePorkbun(t, challengeRecords())
			provider := Provider{APIKey: "key", APISecretKey: "secret"}

			deleted, err := provider.DeleteRecords(context.Background(), "example.com.", []libdns.Record{tc.input})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fake.deletedIDs, tc.want) {
				t.Errorf("Deleted IDs %v, want %v", fake.deletedIDs, tc.want)
			}
			if len(deleted) != len(tc.want) {
				t.Errorf("Returned %d records, want %d", len(deleted), len(tc.want))
			}
		})
	}
}

// Cleaning up one ACME challenge must not delete another one with the same name.
func TestDeleteRecords_ConcurrentChallenges(t *testing.T) {
	fake := newFakePorkbun(t, challengeRecords())
	provider := Provider{APIKey: "key", APISecretKey: "secret"}

	for _, value := range []string{"challenge-a", "challenge-b"} {
		record := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: value}
		if _, err := provider.DeleteRecords(context.Background(), "example.com.", []libdns.Record{record}); err != nil {
			t.Fatalf("Deleting %s: %v", value, err)
		}
	}

	if want := []string{"2", "3"}; !reflect.DeepEqual(fake.deletedIDs, want) {
		t.Errorf("Deleted IDs %v, want %v", fake.deletedIDs, want)
	}
}
