package detectors

import (
	"math"

	"github.com/cc1a2b/HHunter/engine"
)

type TimingDetector struct{}

func NewTimingDetector() *TimingDetector {
	return &TimingDetector{}
}

func (d *TimingDetector) Detect(baseline, mutated *engine.ResponseContext) bool {
	delta := math.Abs(float64(mutated.TimingMS - baseline.TimingMS))
	if delta > 1000 {
		return true
	}

	if baseline.TimingMS > 0 {
		ratio := float64(mutated.TimingMS) / float64(baseline.TimingMS)
		if ratio > 2.0 || ratio < 0.5 {
			return true
		}
	}

	return false
}

func (d *TimingDetector) DetectTimingAnomaly(baseline, mutated *engine.ResponseContext) string {
	delta := mutated.TimingMS - baseline.TimingMS

	if delta > 5000 {
		return "significant_delay"
	}
	if delta > 2000 {
		return "moderate_delay"
	}
	if delta < -2000 {
		return "significant_speedup"
	}
	if delta < -1000 {
		return "moderate_speedup"
	}

	return "normal"
}

func (d *TimingDetector) CalculateTimingDelta(baseline, mutated *engine.ResponseContext) int64 {
	return mutated.TimingMS - baseline.TimingMS
}

func (d *TimingDetector) GetEvidence(baseline, mutated *engine.ResponseContext) map[string]string {
	evidence := make(map[string]string)

	delta := d.CalculateTimingDelta(baseline, mutated)
	anomaly := d.DetectTimingAnomaly(baseline, mutated)

	if anomaly != "normal" {
		evidence["timing_anomaly"] = anomaly
		evidence["timing_delta_ms"] = string(rune(delta))
	}

	return evidence
}
