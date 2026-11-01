// Package multisession implements Nexounel's per-class multi-session
// sizing: probe results are clustered into capacity classes, each class
// runs at its own margin-adjusted operating point, and streams are
// striped across the resulting sessions by measured capacity, loss and
// latency.
//
// The package is deliberately dependency-light: it consumes plain probe
// results (adapted by the caller from the tunnel client's connection
// records) and produces clustering/weighting decisions plus the
// file-based node registry. It never opens sockets, never touches the
// wire, and never reads credentials except through the registry loader's
// explicit path argument.
package multisession

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// CapacityMargin is the default safety factor applied to measured
// capacity: a class operates at floor(0.95 x largest repeatedly-intact
// UDP size) per direction, so transient path shrinkage does not turn
// into truncation loss. Configurable via TOML (CAPACITY_MARGIN);
// DefaultCapacityMargin is used when the configured value is absent.
const CapacityMargin = 0.95

// DefaultCapacityMargin is the margin used when no explicit value is
// configured.
const DefaultCapacityMargin = CapacityMargin

// HysteresisDivisor sets the re-clustering hysteresis band: a freshly
// derived download operating point is adopted only when it improves on
// the current one by more than 1/HysteresisDivisor (12.5%), matching the
// single-session hysteresis rule in the tunnel client.
const HysteresisDivisor = 8

// ProbeResult is one resolver's measured capacity. UploadMTU and
// DownloadMTU are the largest repeatedly-intact UDP payload sizes in
// each direction, in bytes. Loss is the measured loss fraction (0..1)
// at the selected edge; RTT is the mean round-trip time. Valid is false
// for resolvers that failed probing; they are never discarded, only
// held as reserves.
type ProbeResult struct {
	Resolver    string
	UploadMTU   int
	DownloadMTU int
	Loss        float64
	// RTT is the mean round-trip time. Zero means unmeasured (neutral).
	RTT   time.Duration
	Valid bool
}

// Class is one capacity class: a set of resolvers that share a similar
// viable (upload, download) range, running at one operating point.
// OperatingUpload/OperatingDownload are margin-adjusted; RawUpload/
// RawDownload are the class floors (minimum measured capacity across
// members) before the margin. Score is the throughput-optimal score
// (U+D) x (#resolvers sustaining >=U/>=D), computed over the class
// members. Reserves holds resolvers that could not be placed in any
// class (invalid or zero capacity); they are never discarded.
type Class struct {
	Members           []ProbeResult
	RawUpload         int
	RawDownload       int
	OperatingUpload   int
	OperatingDownload int
	Score             int
	// AvgLoss and AvgRTTMs are the member means, used for weighting.
	AvgLoss  float64
	AvgRTTMs float64
}

// Clustering is the result of grouping probe results into classes.
type Clustering struct {
	Classes  []Class
	Reserves []ProbeResult
}

// ValidateMargin checks a configured capacity margin. Valid margins are
// in (0, 1]: a margin of 1 means "operate at full measured capacity",
// smaller values leave headroom. Values outside (0, 1] are rejected so
// a misconfiguration can never silently disable the safety buffer or
// invert it.
func ValidateMargin(margin float64) error {
	if margin <= 0 || margin > 1 || math.IsNaN(margin) || math.IsInf(margin, 0) {
		return fmt.Errorf("invalid CAPACITY_MARGIN %v: must be in (0, 1]", margin)
	}
	return nil
}

// OperatingSize applies the margin to a measured capacity: the largest
// operating size that stays margin below the measured value. Zero or
// negative capacity stays zero: a class with no measured capacity
// carries no traffic.
func OperatingSize(measured int, margin float64) int {
	if measured <= 0 {
		return 0
	}
	return int(math.Floor(margin * float64(measured)))
}

// ShouldAdoptOperatingPoint applies the hysteresis rule: adopt a freshly
// derived download operating point only when there is no current point,
// the current point is stranded (curPool == 0), or the new point is
// materially better (>12.5% larger download MTU).
func ShouldAdoptOperatingPoint(curDownload, newDownload, curPool int) bool {
	if curDownload <= 0 {
		return true
	}
	if curPool == 0 {
		return true
	}
	return float64(newDownload-curDownload) > float64(curDownload)/HysteresisDivisor
}

// Cluster groups valid probe results into capacity classes. Results are
// sorted by download MTU (then upload MTU); a new class is cut wherever
// the gap between consecutive values exceeds gapRatio of the larger
// value in either direction, so classes share a similar viable range in
// BOTH directions. A non-positive gapRatio falls back to 0.25. The
// margin is applied per direction to each class floor. Classes are
// returned sorted by score descending (best class first). Invalid or
// zero-capacity results are returned as reserves, never discarded.
func Cluster(results []ProbeResult, gapRatio, margin float64) Clustering {
	if gapRatio <= 0 {
		gapRatio = 0.25
	}
	if err := ValidateMargin(margin); err != nil {
		margin = DefaultCapacityMargin
	}

	var valid []ProbeResult
	var reserves []ProbeResult
	for _, r := range results {
		if r.Valid && r.DownloadMTU > 0 && r.UploadMTU > 0 {
			valid = append(valid, r)
		} else {
			reserves = append(reserves, r)
		}
	}
	if len(valid) == 0 {
		return Clustering{Reserves: reserves}
	}

	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].DownloadMTU != valid[j].DownloadMTU {
			return valid[i].DownloadMTU < valid[j].DownloadMTU
		}
		return valid[i].UploadMTU < valid[j].UploadMTU
	})

	var groups [][]ProbeResult
	current := []ProbeResult{valid[0]}
	for i := 1; i < len(valid); i++ {
		prev, next := valid[i-1], valid[i]
		downGap := next.DownloadMTU - prev.DownloadMTU
		upGap := next.UploadMTU - prev.UploadMTU
		if float64(downGap) > gapRatio*float64(next.DownloadMTU) ||
			float64(upGap) > gapRatio*float64(next.UploadMTU) {
			groups = append(groups, current)
			current = []ProbeResult{next}
			continue
		}
		current = append(current, next)
	}
	groups = append(groups, current)

	classes := make([]Class, 0, len(groups))
	for _, members := range groups {
		classes = append(classes, buildClass(members, margin))
	}
	sort.SliceStable(classes, func(i, j int) bool {
		return classes[i].Score > classes[j].Score
	})
	return Clustering{Classes: classes, Reserves: reserves}
}

func buildClass(members []ProbeResult, margin float64) Class {
	c := Class{Members: members}
	var lossSum float64
	var rttSum float64
	for i, m := range members {
		if i == 0 || m.DownloadMTU < c.RawDownload {
			c.RawDownload = m.DownloadMTU
		}
		if i == 0 || m.UploadMTU < c.RawUpload {
			c.RawUpload = m.UploadMTU
		}
		lossSum += m.Loss
		rttSum += float64(m.RTT.Milliseconds())
	}
	c.OperatingUpload = OperatingSize(c.RawUpload, margin)
	c.OperatingDownload = OperatingSize(c.RawDownload, margin)
	// Every member sustains the class floor by construction (floor is the
	// member minimum), so the sustaining pool is the member count and the
	// score is the throughput-optimal (U+D) x pool over this class.
	c.Score = (c.OperatingUpload + c.OperatingDownload) * len(members)
	c.AvgLoss = lossSum / float64(len(members))
	c.AvgRTTMs = rttSum / float64(len(members))
	return c
}

// Weight computes a class's share of new streams. Capacity dominates:
// the score already encodes (operating size x member count). Loss
// discounts linearly (a class losing 20% of probes carries 20% less
// weight) and latency discounts hyperbolically against a 50ms
// reference: doubling RTT from 50ms to 100ms halves the weight.
// Zero-capacity classes weigh zero and never receive streams.
func Weight(c Class) float64 {
	if c.OperatingUpload <= 0 || c.OperatingDownload <= 0 || len(c.Members) == 0 {
		return 0
	}
	loss := c.AvgLoss
	if loss < 0 {
		loss = 0
	}
	if loss > 1 {
		loss = 1
	}
	latencyFactor := 1 + c.AvgRTTMs/50
	if latencyFactor <= 0 {
		latencyFactor = 1
	}
	return float64(c.Score) * (1 - loss) / latencyFactor
}

// Weights returns one weight per class, in class order.
func Weights(classes []Class) []float64 {
	ws := make([]float64, len(classes))
	for i, c := range classes {
		ws[i] = Weight(c)
	}
	return ws
}

// Choose picks a class index by weighted random selection. r must be in
// [0, totalWeight); it is the caller's randomness (the multiplexer draws
// it), which keeps selection deterministic under test. Classes with zero
// weight are never picked. When all weights are zero, -1 is returned
// (no class can carry traffic).
func Choose(weights []float64, r float64) int {
	total := 0.0
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total <= 0 || r < 0 || r >= total {
		return -1
	}
	acc := 0.0
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		acc += w
		if r < acc {
			return i
		}
	}
	return -1
}

// ErrNoHealthyClass is returned when every class is excluded or
// unhealthy and no stream can be placed.
var ErrNoHealthyClass = errors.New("no healthy session class available")
