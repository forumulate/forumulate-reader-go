package reader

// The reader cookies Forumulate sets, by name, and Set-Cookie lines that
// expire them.
//
// Every one is HOST-ONLY (no Domain), at Path=/, on the host the reader reads,
// so these lines only work when sent from that same host (your app on
// example.com serving docs at example.com/docs). On a different host, send the
// reader to SignOutURL instead: our response clears them where they live.
//
//	forumulate_session      the reader's session (httpOnly)
//	fm_signed_in            a non-secret "signed in" hint for the page
//	cflx_vis_org_<orgId>    the org-scoped reader pass (reader.identity_scope: org)
//	cflx_vis_<spaceId>      the per-space reader pass

// ReaderCookieNames lists every reader cookie for an org and its spaces
// (spaces deduplicated, in order).
func ReaderCookieNames(orgID string, spaceIDs ...string) []string {
	names := []string{"forumulate_session", "fm_signed_in", "cflx_vis_org_" + orgID}
	seen := map[string]bool{}
	for _, id := range spaceIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		names = append(names, "cflx_vis_"+id)
	}
	return names
}

// ExpireCookie is a Set-Cookie header value that deletes the host-only cookie name.
func ExpireCookie(name string) string {
	return name + "=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax"
}
