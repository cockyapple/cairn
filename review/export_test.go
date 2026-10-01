package review

// SetMaxBlobTotal lowers the bundle size cap for a test and returns a restore func.
func SetMaxBlobTotal(n int64) func() {
	old := maxBlobTotal
	maxBlobTotal = n
	return func() { maxBlobTotal = old }
}
