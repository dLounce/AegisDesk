# VPN Connection Troubleshooting

Most VPN failures fall into three categories: expired credentials, an out-of-date client,
or a split-tunnel configuration conflict.

Ask the employee to confirm the error text before changing anything.

1. Confirm the corporate VPN client is version 7.2 or later. Older builds fail against the
   current gateway certificate.
2. Sign out of the client completely, then sign back in. A stale session token is the most
   common cause of a sudden failure that worked yesterday.
3. If the client reports a certificate error, the device certificate has usually expired.
   Device certificates are reissued through the endpoint management console.
4. If connection succeeds but internal sites do not resolve, the split-tunnel profile is
   likely missing. Reapply the standard profile.

VPN access is baseline access. Every active employee already holds it, so a VPN problem is
a connectivity fault to diagnose, not an access request to grant.

Escalate to network operations if the gateway itself is unreachable from multiple networks.
