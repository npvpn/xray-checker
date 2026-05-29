package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"xray-checker/checker"
	"xray-checker/config"
	"xray-checker/logger"
	"xray-checker/subscription"
	"xray-checker/web"
)

type probeMeta struct {
	Slug     string  `json:"slug"`
	Name     string  `json:"name"`
	Region   string  `json:"region"`
	City     *string `json:"city,omitempty"`
	Operator *string `json:"operator,omitempty"`
}

type summaryPayload struct {
	Total        int   `json:"total"`
	Online       int   `json:"online"`
	Offline      int   `json:"offline"`
	AvgLatencyMs *int  `json:"avg_latency_ms,omitempty"`
}

type proxyPayload struct {
	StableID  string `json:"stable_id"`
	Name      string `json:"name"`
	SubName   string `json:"sub_name,omitempty"`
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
	Online    bool   `json:"online"`
	LatencyMs *int   `json:"latency_ms,omitempty"`
}

type reportPayload struct {
	Probe            probeMeta      `json:"probe"`
	CheckedAt        time.Time      `json:"checked_at"`
	CheckerVersion   string         `json:"checker_version,omitempty"`
	CheckMethod      string         `json:"check_method"`
	SubscriptionName string         `json:"subscription_name,omitempty"`
	PublicIP         string         `json:"public_ip,omitempty"`
	Summary          summaryPayload `json:"summary"`
	Proxies          []proxyPayload `json:"proxies"`
}

func optionalString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func optionalInt64(value int64) *int {
	if value <= 0 {
		return nil
	}
	v := int(value)
	return &v
}

func buildPayload(proxyChecker *checker.ProxyChecker, version string) (reportPayload, error) {
	cfg := config.CLIConfig.Report
	slug := strings.TrimSpace(cfg.Slug)
	if slug == "" {
		return reportPayload{}, fmt.Errorf("PROBE_SLUG is required when REPORT_URL is set")
	}

	proxies := proxyChecker.GetProxies()
	proxyResults := make([]proxyPayload, 0, len(proxies))

	var online, offline int
	var totalLatency int64
	var latencyCount int

	for _, proxy := range proxies {
		status, latency, _ := proxyChecker.GetProxyStatus(proxy.Name)
		if status {
			online++
			if latency > 0 {
				totalLatency += latency.Milliseconds()
				latencyCount++
			}
		} else {
			offline++
		}

		address := fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
		proxyResults = append(proxyResults, proxyPayload{
			StableID:  proxy.StableID,
			Name:      proxy.Name,
			SubName:   proxy.SubName,
			Protocol:  proxy.Protocol,
			Address:   address,
			Online:    status,
			LatencyMs: optionalInt64(latency.Milliseconds()),
		})
	}

	var avgLatency *int
	if latencyCount > 0 {
		avg := int(totalLatency / int64(latencyCount))
		avgLatency = &avg
	}

	publicIP, err := proxyChecker.GetCurrentIP()
	if err != nil {
		logger.Warn("Failed to get public IP for report: %v", err)
	}

	subscriptionName := subscription.GetSubscriptionName()
	if subscriptionName == "" {
		names := web.CollectSubscriptionNames(proxies)
		if len(names) > 0 {
			subscriptionName = names[0]
		}
	}

	probeName := strings.TrimSpace(cfg.Name)
	if probeName == "" {
		probeName = slug
	}

	return reportPayload{
		Probe: probeMeta{
			Slug:     slug,
			Name:     probeName,
			Region:   strings.TrimSpace(cfg.Region),
			City:     optionalString(cfg.City),
			Operator: optionalString(cfg.Operator),
		},
		CheckedAt:        time.Now().UTC(),
		CheckerVersion:   version,
		CheckMethod:      config.CLIConfig.Proxy.CheckMethod,
		SubscriptionName: subscriptionName,
		PublicIP:         publicIP,
		Summary: summaryPayload{
			Total:        len(proxies),
			Online:       online,
			Offline:      offline,
			AvgLatencyMs: avgLatency,
		},
		Proxies: proxyResults,
	}, nil
}

func SendReport(proxyChecker *checker.ProxyChecker, version string) error {
	reportURL := strings.TrimSpace(config.CLIConfig.Report.URL)
	if reportURL == "" {
		return nil
	}

	payload, err := buildPayload(proxyChecker, version)
	if err != nil {
		return err
	}

	if payload.Probe.Region == "" {
		return fmt.Errorf("PROBE_REGION is required when REPORT_URL is set")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	token := strings.TrimSpace(config.CLIConfig.Report.Token)
	if token == "" {
		return fmt.Errorf("REPORT_TOKEN is required when REPORT_URL is set")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, reportURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				logger.Info("Report sent to %s (probe=%s, online=%d/%d)", reportURL, payload.Probe.Slug, payload.Summary.Online, payload.Summary.Total)
				return nil
			}

			lastErr = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
			if resp.StatusCode < 500 {
				return lastErr
			}
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return lastErr
}
