package main

import (
	"time"
)

func maxDuration(xs ...time.Duration) time.Duration {
	var max time.Duration
	if len(xs) == 2 {
		if xs[0].Nanoseconds() > xs[1].Nanoseconds() {
			return xs[0]
		}
		return xs[1]
	}
	for _, x := range xs {
		max = maxDuration(max, x)
	}
	return max
}

func maxInt(xs ...int) int {
	var max int
	if len(xs) == 2 {
		if xs[0] > xs[1] {
			return xs[0]
		}
		return xs[1]

	}
	for _, x := range xs {
		max = maxInt(max, x)
	}
	return max
}
