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
				promErrors,
				promVaultRequests,
				promVaultRequestsDuration,
				promVaultRequestsInFlight,
			).
			ReadyAlways(),
	)
)
