package cloudflare

// truncate memotong string panjang untuk logging — mencegah log yang terlalu besar.
// Menggunakan konversi ke []rune untuk mencegah pemotongan karakter UTF-8 di tengah byte.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "...[truncated]"
}
