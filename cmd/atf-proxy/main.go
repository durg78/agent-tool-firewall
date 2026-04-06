package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/durg78/agent-tool-firewall/internal/proxy"
)

func main() {
	port := flag.Int("port", 3123, "Listen port")
	flag.Parse()

	fmt.Printf("🚀 ATF Agent-Tool-Firewall starting on :%d\n", *port)
	fmt.Println("   → Point your LLM agent at http://localhost:" + fmt.Sprintf("%d", *port))

	handler, err := proxy.NewHandler()
	if err != nil {
		log.Fatal(err)
	}

	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), handler); err != nil {
		log.Fatal(err)
	}
}
