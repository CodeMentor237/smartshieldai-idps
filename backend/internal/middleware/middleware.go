package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter implements a token bucket rate limiter per IP
type RateLimiter struct {
	ips    map[string]*rate.Limiter
	mu     *sync.RWMutex
	rate   rate.Limit
	burst  int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		ips:    make(map[string]*rate.Limiter),
		mu:     &sync.RWMutex{},
		rate:   r,
		burst:  b,
	}
}

// GetLimiter returns the rate limiter for the provided IP
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.ips[ip] = limiter
	}

	return limiter
}

// RateLimit middleware implements rate limiting per IP
func (rl *RateLimiter) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := rl.GetLimiter(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, APIResponse{
				Status:  "error",
				Message: "Rate limit exceeded",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// APIResponse standardizes API response format
type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return secure.New(secure.Config{
		STSSeconds:            31536000,
		STSIncludeSubdomains: true,
		FrameDeny:            true,
		ContentTypeNosniff:   true,
		BrowserXssFilter:     true,
		IENoOpen:             true,
		ReferrerPolicy:       "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "default-src 'self'",
	})
}

// ValidateJSON validates JSON payloads
func ValidateJSON() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != "GET" && c.Request.Method != "DELETE" {
			if c.Request.Header.Get("Content-Type") != "application/json" {
				c.JSON(http.StatusUnsupportedMediaType, APIResponse{
					Status:  "error",
					Message: "Content-Type must be application/json",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// RequestTimeout adds timeout to requests
func RequestTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Wrap the request in a timeout
		done := make(chan bool)
		go func() {
			c.Next()
			done <- true
		}()

		select {
		case <-time.After(timeout):
			c.JSON(http.StatusRequestTimeout, APIResponse{
				Status:  "error",
				Message: "Request timeout",
			})
			c.Abort()
		case <-done:
			return
		}
	}
}