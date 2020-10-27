package sidecar

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/utilitywarehouse/go-operational/op"
)

const (
	appName        = "vault-kube-cloud-credentials"
	appDescription = "Fetch cloud provider credentials from vault on behalf of a Kubernetes service account and serve them via HTTP."
	promNamespace  = "vkcc"
	promSubsystem  = "sidecar"
)

var (
	promExpiry = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "expiry_timestamp_seconds"),
		Help: "Returns the expiry date for the current credentials, expressed as a Unix Epoch Time",
	})
	promRenewals = prometheus.NewCounter(prometheus.CounterOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "renewals_total"),
		Help: "Total count of renewals",
	})
	promRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "requests_total"),
		Help: "Total count of requests handled, by code and method",
	},
		[]string{"code", "method"},
	)
	promRequestsInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "in_flight_requests"),
		Help: "Number of requests currently in-flight",
	})
	promRequestsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "request_duration_seconds"),
		Help: "A histogram of request latencies",
	},
		[]string{},
	)
	promRequestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "request_size_bytes"),
		Help: "A histogram of request sizes for requests",
	},
		[]string{},
	)
	promResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "response_size_bytes"),
		Help: "A histogram of response sizes for requests",
	},
		[]string{},
	)
	promErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "errors_total"),
		Help: "Total count of errors",
	})
	promVaultRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "vault_requests_total"),
		Help: "Total count of requests to Vault, by code and method",
	},
		[]string{"code", "method"},
	)
	promVaultRequestsInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "vault_in_flight_requests"),
		Help: "Number of requests to Vault currently in-flight",
	})
	promVaultRequestsDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: prometheus.BuildFQName(promNamespace, promSubsystem, "vault_request_duration_seconds"),
		Help: "A histogram of request latencies to Vault",
	},
		[]string{},
	)
	statusHandler = op.NewHandler(
		op.NewStatus(appName, appDescription).
			AddOwner("system", "#infra").
			AddLink("readme", fmt.Sprintf("https://github.com/utilitywarehouse/%s/blob/master/README.md", appName)).
			AddMetrics(
				promExpiry,
				promRenewals,
				promRequests,
				promRequestsDuration,
				promRequestsInFlight,
				promRequestSize,
				promResponseSize,
				promErrors,
				promVaultRequests,
				promVaultRequestsDuration,
				promVaultRequestsInFlight,
			).
			ReadyAlways(),
	)
)
