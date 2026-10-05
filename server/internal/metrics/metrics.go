// Package metrics defines the Prometheus metrics exported by the server.
// Metrics carry no usernames or other user-identifying labels.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	Registry = prometheus.NewRegistry()

	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "doommsg_http_requests_total",
		Help: "HTTP requests by route and status code.",
	}, []string{"route", "code"})

	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "doommsg_http_request_duration_seconds",
		Help:    "HTTP request latency by route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})

	WSConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "doommsg_ws_connections",
		Help: "Currently authenticated WebSocket connections.",
	})

	EnvelopesRelayed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "doommsg_envelopes_total",
		Help: "Envelopes accepted by the relay, by kind (stored|ephemeral) and outcome.",
	}, []string{"kind", "outcome"})

	RateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "doommsg_rate_limited_total",
		Help: "Requests rejected by rate limiting, by limiter.",
	}, []string{"limiter"})

	Registrations = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doommsg_registrations_total",
		Help: "Accounts created.",
	})

	PurgedRows = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "doommsg_purged_rows_total",
		Help: "Expired rows removed by the janitor.",
	})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		HTTPRequests, HTTPDuration, WSConnections, EnvelopesRelayed,
		RateLimited, Registrations, PurgedRows,
	)
}
