//go:build !windows

// Non-Windows stub: the IP Helper system source does not exist here, so
// the trafficCollector fallback path stays in force.
package main

import "errors"

func readTrafficFromSystem() (TrafficData, error) {
        return TrafficData{}, errors.New("system traffic source is Windows-only (IP Helper)")
}
