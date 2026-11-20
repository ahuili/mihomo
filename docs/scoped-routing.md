# Scoped TUN routing

On macOS, start the core with `MIHOMO_SCOPE_FILE` set to an absolute checkpoint path in a dedicated directory with mode 0700, a private Unix controller and process lookup set to `always`. Scope handling starts before the first TUN connection. Leave the environment variable unset for the upstream behavior.

The controller accepts the following operations on its Unix socket. Scope IDs are chosen by the caller. Each ID refers to a fixed set of absolute executable paths and exact normalized hostnames.

1. PUT `/routing-scopes/{id}/seal` with a JSON object containing `paths` and `hosts` arrays. Matching new flows are blocked immediately. A successful response contains a token issued after the old matching handlers have finished. If waiting times out, keep the subject blocked and retry.
2. Verify the expected public IP independently through the chosen relay. PUT `/routing-scopes/{id}/authorize` with `token` and `outbound`. The outbound must be a concrete HTTP proxy. The client is responsible for using a relay that revokes existing streams if the IP verification expires or fails. Matching TCP uses that relay. Matching UDP remains blocked.
3. To remove protection, seal again and DELETE `/routing-scopes/{id}` with that seal's token. Successful removal restores normal routing for future traffic.

A restart reloads saved subjects in the blocked state. It requires fresh authorization. A missing checkpoint in an empty directory means first use. The caller must retain the directory across restarts.

Executable attribution uses macOS socket snapshots. While any path-based scope is active, TUN connections with unknown owners are rejected. Shared helper processes are attributed to the executable that owns the socket. Exact hostname matching requires a hostname visible to the core. Data previously accepted by a remote peer cannot be recalled. This mechanism covers the opted-in TUN data plane.
