package security

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	rate       float64 // tokens per second
	bucketSize float64 // maximum bucket size
	tokens     float64 // current number of tokens
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate, bucketSize float64) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		bucketSize: bucketSize,
		tokens:     bucketSize,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed under the rate limit
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(r.bucketSize, r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// AllowN checks if n requests are allowed under the rate limit
func (r *RateLimiter) AllowN(n int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(r.bucketSize, r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	if r.tokens >= float64(n) {
		r.tokens -= float64(n)
		return true
	}
	return false
}

// Wait blocks until a request is allowed
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		if r.Allow() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second / time.Duration(r.rate)):
			// Wait for the next token
		}
	}
}

// WaitN blocks until n requests are allowed
func (r *RateLimiter) WaitN(ctx context.Context, n int) error {
	for {
		if r.AllowN(n) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(float64(n)/r.rate) * time.Second):
			// Wait for the next batch of tokens
		}
	}
}

// Reserve returns a reservation for a request
func (r *RateLimiter) Reserve() *Reservation {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens = min(r.bucketSize, r.tokens+elapsed*r.rate)
	r.lastUpdate = now

	if r.tokens >= 1 {
		r.tokens--
		return &Reservation{
			ok:      true,
			timeToAct: now,
		}
	}

	// Calculate when the next token will be available
	timeToAct := now.Add(time.Duration((1-r.tokens)/r.rate) * time.Second)
	return &Reservation{
		ok:      false,
		timeToAct: timeToAct,
	}
}

// Reservation represents a rate limit reservation
type Reservation struct {
	ok        bool
	timeToAct time.Time
}

// OK returns whether the reservation was successful
func (r *Reservation) OK() bool {
	return r.ok
}

// Delay returns the time until the reservation can be used
func (r *Reservation) Delay() time.Duration {
	return time.Until(r.timeToAct)
}

// Cancel cancels the reservation
func (r *Reservation) Cancel() {
	// No-op for now, as we don't need to return tokens
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
} 