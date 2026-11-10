//go:build race

package probes_test

// raceEnabled is true when the tests run under the race detector, which slows
// the million item test down by more than an order of magnitude.
const raceEnabled = true
