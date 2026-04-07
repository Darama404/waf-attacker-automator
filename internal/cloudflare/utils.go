package cloudflare

// truncate memotong string panjang untuk logging — mencegah log yang terlalu besar.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}
