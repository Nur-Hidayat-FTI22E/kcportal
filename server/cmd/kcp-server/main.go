// kcp-server (MOD-SERVER, §6) is the fleet backend: enrollment, poll/ack,
// artifact rollout, marketing sync via client_ref, backups (Go net/http +
// MySQL + Redis + nginx, §2.1). It is scoped for M5 and intentionally not
// started here — see docs/ROADMAP.md.
package main

func main() {
	println("kcp-server: not implemented yet (M5) — see docs/ROADMAP.md")
}
