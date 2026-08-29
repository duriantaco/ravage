package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	flag := env("FORGEOPS_FLAG_ROOT", "flag{forgeops_internal_release_metadata}")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"service":   "forgeops-internal",
			"zone":      "release-control",
			"flag_path": "/flag",
			"hint":      "metadata clients may follow relative internal endpoints",
		})
	})
	mux.HandleFunc("/flag", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"ok":   true,
			"flag": flag,
		})
	})

	log.Fatal(http.ListenAndServe(":9100", mux))
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func env(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
