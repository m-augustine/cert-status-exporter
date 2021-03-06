package exporters

import (
	"github.com/m-augustine/cert-status-exporter/src/metrics"
)

// CertExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace string, condition string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes)
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.SecretExpirySeconds.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace, condition).Set(metric.durationUntilExpiry)
		metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.notAfter)
	}

	return nil
}

func (c *SecretExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
}
