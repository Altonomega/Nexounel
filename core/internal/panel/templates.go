package panel

import (
	"bytes"
	"html/template"
	"net/http"
)

const panelCSS = `
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;background:#0b0f14;color:#e6edf3;line-height:1.5;animation:pageIn .35s ease both}
@keyframes pageIn{from{opacity:0}to{opacity:1}}
header{background:linear-gradient(180deg,#10161d,#0d1218);border-bottom:1px solid #1f2a38;padding:16px 24px}
header h1{font-size:19px;margin:0;letter-spacing:.4px}
header h1::after{content:"";display:block;height:2px;width:64px;margin-top:8px;background:linear-gradient(90deg,#38bdf8,#2dd4bf);border-radius:2px}
nav{padding:10px 24px;background:#10161d;border-bottom:1px solid #1f2a38;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
nav a{color:#9fb0c3;text-decoration:none;padding:6px 12px;border-radius:999px;font-size:14px}
nav a:hover{color:#e6edf3;background:#1b2534}
nav form{margin-left:auto}
main{max-width:1080px;margin:0 auto;padding:24px}
h2{font-size:22px;margin:4px 0 16px;color:#f0f6fc}
h3{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#8fa3b8;margin:0 0 12px}
a{color:#7dd3fc}
a:hover{color:#bae6fd}
.card{background:linear-gradient(180deg,#151d29,#121924);border:1px solid #26303f;border-radius:12px;padding:18px 20px;margin:16px 0;box-shadow:0 4px 18px rgba(0,0,0,.35);overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid #232d3d;padding:9px 10px;text-align:left;vertical-align:top}
th{color:#8fa3b8;font-size:12px;text-transform:uppercase;letter-spacing:.06em;background:#18202d}
tr:hover td{background:#1b2534}
tr:last-child td{border-bottom:0}
code{background:#1c2534;padding:2px 6px;border-radius:4px;font-size:13px;color:#a5d8ff}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;max-width:480px;padding:9px 10px;border:1px solid #2a3442;border-radius:8px;background:#0d1319;color:#e6edf3;font-size:14px}
input:focus,textarea:focus,select:focus{outline:none;border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.18)}
label{display:block;margin:14px 0 5px;font-weight:600;color:#c6d2df}
button,.btn{background:#0284c7;color:#fff;border:0;padding:9px 18px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:#0369a1}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge-up{color:#34d399;background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.35)}
.badge-down{color:#f87171;background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.35)}
.badge-warn{color:#fbbf24;background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.35)}
.badge .dot{width:7px;height:7px;border-radius:50%;background:#34d399;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(52,211,153,.45)}50%{box-shadow:0 0 0 5px rgba(52,211,153,0)}}
.error{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.4);color:#fecaca;padding:12px 14px;border-radius:8px}
.ok{background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.4);color:#a7f3d0;padding:12px 14px;border-radius:8px}
.warn{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.4);color:#fde68a;padding:12px 14px;border-radius:8px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
pre{background:#0d1117;color:#dbe4ee;padding:14px;border:1px solid #232d3d;border-radius:8px;overflow:auto;font-size:13px}
footer{padding:18px 24px;color:#6b7a8d;font-size:13px;text-align:center}
.muted{color:#8b98a9;font-size:13px}
form.inline{display:inline}
@media (max-width:640px){main{padding:16px}header,nav{padding-left:14px;padding-right:14px}.card{padding:14px}}
`

const layoutTemplate = `{{define "layout"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="5">{{end}}
<title>{{.Title}} - Nexounel Panel</title>
<style>{{.CSS}}</style>
</head>
<body>
<header><h1>Nexounel Panel</h1></header>
{{if .Authenticated}}<nav>
<a href="{{.WebPath}}/status">Dashboard</a>
<a href="{{.WebPath}}/wizard">Wizard</a>
<a href="{{.WebPath}}/nodes">Nodes</a>
<a href="{{.WebPath}}/logs">Logs</a>
<a href="{{.WebPath}}/jobs">Jobs</a>
<form method="post" action="{{.WebPath}}/logout" style="display:inline"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit" style="padding:5px 12px">Log out ({{.Username}})</button></form>
</nav>{{end}}
<main>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
{{template "content" .}}
</main>
<footer>Local administration panel. Keep the secret path and admin credentials private.</footer>
</body>
</html>{{end}}`

const loginTemplate = `{{define "content"}}<h2>Log in</h2>
<p>Enter the admin credentials set up with the panel first-run setup.</p>
<form method="post" action="{{.WebPath}}/login">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="username">Username</label>
<input type="text" id="username" name="username" autocomplete="username" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required>
<p><button type="submit">Log in</button></p>
</form>{{end}}`

const statusTemplate = `{{define "content"}}<h2>Dashboard</h2>
{{if .Content.RestartNeeded}}<p class="warn">The node registry changed. Restart the server to apply the change. Existing sessions will drop.</p>{{end}}
{{if .Content.RestartResult}}<p class="ok">{{.Content.RestartResult}}</p>{{end}}
{{if .Content.ManualRestart}}<p class="warn">Automatic restart is unavailable here. Run this command on the mother server:<br><code>{{.Content.ManualRestart}}</code></p>{{end}}
{{if .Content.ShownKey}}<div class="card"><h3>New node key (shown once)</h3>
<p>Node: <code>{{.Content.ShownNodeID}}</code> &middot; Key fingerprint: <code class="mono">{{.Content.ShownFingerprint}}</code></p>
<label for="shownkey">Node key (copy now; it will not be shown again)</label>
<input type="text" id="shownkey" readonly value="{{.Content.ShownKey}}">
<p class="muted">Deliver this key to the node before it can connect with it. Keys are never shown again and never logged.</p></div>{{end}}
{{if .Content.ShownToken}}<div class="card"><h3>Join token (shown once)</h3>
<p>Node: <code>{{.Content.ShownTokenNodeID}}</code> &middot; Token fingerprint: <code class="mono">{{.Content.ShownTokenFingerprint}}</code> &middot; Expires: <code>{{.Content.ShownTokenExpires}}</code></p>
<label for="showntoken">Join token (copy now; it will not be shown again)</label>
<input type="text" id="showntoken" readonly value="{{.Content.ShownToken}}">
<p class="muted">Run the node in enroll mode with this token (<code>--enroll</code> with <code>--join-token</code>, <code>--join-token-file</code>, or stdin; prefer the file or stdin so the token stays out of shell history). The token is single-use: it enrolls exactly one node, then burns. A panel restart invalidates outstanding tokens. The token value is never logged.</p></div>{{end}}
<div class="card"><h3>Tunnel / server health</h3>
{{if .Content.Health.Up}}<p>Metrics endpoint: <span class="badge badge-up"><span class="dot"></span>reachable</span></p>{{else}}<p>Metrics/health endpoint unreachable <span class="badge badge-down">unavailable</span>{{if .Content.Health.Error}} <span class="muted">({{.Content.Health.Error}})</span>{{end}}</p>{{end}}
{{with .Content.Health.Details}}<p>Status: {{.Status}} &middot; Uptime: {{.UptimeSeconds}} seconds</p>
{{if .Warnings}}<p>Warnings:</p><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
<p>Transports: UDP {{if .Transports.UDPUp}}up{{else}}down{{end}} &middot; TCP {{if .Transports.TCPUp}}up{{else}}down{{end}} &middot; DoT {{if .Transports.DoTUp}}up{{else}}down{{end}} &middot; DoH {{if .Transports.DoHUp}}up{{else}}down{{end}}</p>
{{if .Monitoring}}<table><tr><th>Metric</th><th>Value</th><th>Unit</th></tr>{{range .Monitoring}}<tr><td>{{.Name}}</td><td>{{.Value}}</td><td>{{.Unit}}</td></tr>{{end}}</table>{{else}}<p>Metrics: unavailable</p>{{end}}
{{else}}<p>Health details: unavailable</p>{{end}}
<p>Prometheus metrics endpoint: {{if .Content.Health.MetricsAvailable}}available ({{.Content.Health.MetricsValueCount}} series){{else}}unavailable{{end}}</p>
<p class="muted">Control socket: {{if .Content.Control.Configured}}{{if .Content.Control.Reachable}}configured and reachable{{else}}configured but unreachable{{end}}{{else}}not configured{{end}} &middot; Server config: {{if .Content.ConfigFiles.ServerPresent}}{{if .Content.ConfigFiles.ServerParseable}}present and parseable{{else}}present but unparseable{{end}}{{else}}missing{{end}} &middot; Node config: {{if .Content.ConfigFiles.NodePresent}}{{if .Content.ConfigFiles.NodeParseable}}present and parseable{{else}}present but unparseable{{end}}{{else}}missing{{end}}</p>
{{if .Content.ConfigFiles.ServerError}}<p class="muted">Server config: {{.Content.ConfigFiles.ServerError}}</p>{{end}}
{{if .Content.ConfigFiles.NodeError}}<p class="muted">Node config: {{.Content.ConfigFiles.NodeError}}</p>{{end}}
</div>
<div class="card"><h3>Live sessions</h3>
{{if .Content.SessionsNote}}<p>{{.Content.SessionsNote}}</p>{{else}}
{{if .Content.Sessions}}<table><tr><th>Session</th><th>Node</th><th>Upload MTU</th><th>Download MTU</th><th>Active streams</th><th>Last activity</th></tr>{{range .Content.Sessions}}<tr><td>{{.SessionID}}</td><td>{{.NodeID}}</td><td>{{.UploadMTU}}</td><td>{{.DownloadMTU}}</td><td>{{.ActiveStreams}}</td><td>{{.LastActivity}}</td></tr>{{end}}</table>{{else}}<p>No live sessions reported by the control socket.</p>{{end}}
{{end}}</div>
<div class="card"><h3>Mesh</h3>
{{if .Content.Mesh.Available}}
<p>Term: <strong>{{.Content.Mesh.Term}}</strong>{{if .Content.Mesh.TermDegraded}} (degraded){{end}} &middot; Table version: {{.Content.Mesh.Version}} &middot; Chief: <strong>{{if .Content.Mesh.ChiefID}}{{.Content.Mesh.ChiefID}}{{else}}none{{end}}</strong> &middot; Snapshot signing: {{if .Content.Mesh.SnapshotSigning}}enabled{{else}}disabled (unsigned tables; degraded derivation unavailable){{end}}</p>
<p class="muted">Snapshot generated at {{.Content.Mesh.GeneratedAt.Format "2006-01-02 15:04:05 MST"}} &middot; Control socket: configured and reachable</p>
{{if .Content.Mesh.Members}}<table><tr><th>Node</th><th>State</th><th>Capacity (B/s)</th><th>Weight</th><th>Loss</th><th>Leg RTT (ms)</th><th>Leg</th><th>Streams</th><th>Forward ports</th><th>Config ver.</th><th>Control stream</th><th>Last heartbeat</th><th>Last ack</th></tr>{{range .Content.Mesh.Members}}<tr><td>{{.ID}}</td><td>{{.State}}</td><td>{{printf "%.0f" .CapacityBps}}</td><td>{{printf "%.3f" .Weight}}</td><td>{{printf "%.3f" .Loss}}</td><td>{{printf "%.1f" .LegRTTMs}}</td><td>{{if .LegOK}}<span class="badge badge-up"><span class="dot"></span>ok</span>{{else}}<span class="badge badge-down">down</span>{{end}}</td><td>{{.ActiveStreams}}</td><td>{{.ForwardPortsBound}}</td><td>{{.ConfigVersion}}</td><td>{{if .StreamConnected}}connected{{else}}not connected{{end}}</td><td>{{if .LastSeen.IsZero}}never{{else}}{{.LastSeen.Format "2006-01-02 15:04:05 MST"}} ({{.LastSeenAgoSeconds}}s ago){{end}}</td><td>{{if .LastAckFor}}{{.LastAckFor}}{{if .LastAckError}}: {{.LastAckError}}{{end}}{{else}}&mdash;{{end}}</td></tr>{{end}}</table>{{else}}<p>No members in the enforced table and no heartbeats recorded.</p>{{end}}
<p class="muted">Weights are capacity shares: zero means the member takes no new streams (reserve, suspect, down, or no capacity reported yet). A member shown SUSPECT or DOWN while its sessions still appear above means heartbeats stopped, not that the node is healthy — the control stream is wedged. An ack error means a config push or rotation order was received but not applied; an absent ack means the order was never acknowledged. Snapshot signing disabled means nodes hold no verified snapshot and cannot derive a degraded chief if the mother link drops.</p>
{{else}}<p>{{.Content.Mesh.Note}}</p>{{end}}</div>
<div class="card"><h3>Join tokens</h3>
<p class="muted">Single-use, 24-hour maximum, bound to one node ID. Issuing pushes the token's bootstrap key to the running server; revoking, consuming, or expiry removes it. Tokens live in panel memory only: a panel restart invalidates outstanding tokens.</p>
{{if .Content.PendingJoins}}<table><tr><th>Node</th><th>Fingerprint</th><th>Expires</th><th>Attempts</th><th>State</th><th>Action</th></tr>{{range .Content.PendingJoins}}<tr><td>{{.NodeID}}</td><td class="mono">{{.Fingerprint}}</td><td>{{.ExpiresAt.Format "2006-01-02 15:04:05 MST"}}</td><td>{{.Attempts}}</td><td>{{if .Used}}used{{else if .Burned}}burned{{else if .Revoked}}revoked{{else}}pending{{end}}</td><td><form method="post" action="{{$.WebPath}}/mesh/revoke" style="display:inline">
<input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
<input type="hidden" name="node_id" value="{{.NodeID}}">
<label style="display:inline"><input type="checkbox" name="confirm" value="yes" required> confirm</label>
<button type="submit">Revoke</button></form></td></tr>{{end}}</table>{{else}}<p>No pending join tokens.</p>{{end}}
<form method="post" action="{{.WebPath}}/mesh/issue">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="mi-node">Node ID (the token enrolls exactly this node)</label>
<input type="text" id="mi-node" name="node_id" required>
<label for="mi-addr">Connect address (tunnel subdomain, issued into the node config)</label>
<input type="text" id="mi-addr" name="connect_address" placeholder="v.example.invalid" required>
<label for="mi-port">Node listen port</label>
<input type="number" id="mi-port" name="listen_port" value="18000" min="1" max="65535">
<label for="mi-range">Forward range (lo-hi)</label>
<input type="text" id="mi-range" name="forward_range" placeholder="20000-20010" required>
<label for="mi-ttl">Token lifetime (hours, 1&ndash;24)</label>
<input type="number" id="mi-ttl" name="ttl_hours" value="24" min="1" max="24">
<p><button type="submit">Issue join token (shown once)</button></p>
</form></div>
<div class="card"><h3>Nodes</h3>
{{if .Content.RegistryError}}<p>Registry: unavailable ({{.Content.RegistryError}})</p>{{else}}
<table><tr><th>Node</th><th>Key fingerprint</th></tr>{{range .Content.Nodes}}<tr><td>{{.ID}}</td><td class="mono">{{.Fingerprint}}</td></tr>{{end}}</table>
{{end}}</div>
<div class="card"><h3>Resolver fleet</h3>
{{if .Content.Resolver.Available}}<p>Source: <code>{{.Content.Resolver.SourceFile}}</code> &middot; {{.Content.Resolver.EntryTotal}} resolvers in {{len .Content.Resolver.Classes}} download-MTU classes</p>
{{if .Content.Resolver.Classes}}<table><tr><th>Download MTU class</th><th>Smallest upload MTU</th><th>Resolvers</th></tr>{{range .Content.Resolver.Classes}}<tr><td>{{.DownloadMTU}}</td><td>{{.UploadMTU}}</td><td>{{.Count}}</td></tr>{{end}}</table>{{end}}
{{if gt .Content.Resolver.EntryTotal (len .Content.Resolver.Entries)}}<p class="muted">Showing the top {{len .Content.Resolver.Entries}} resolvers by download MTU.</p>{{end}}
<table><tr><th>Resolver</th><th>Upload MTU</th><th>Download MTU</th><th>Last seen</th></tr>{{range .Content.Resolver.Entries}}<tr><td>{{.IP}}:{{.Port}}</td><td>{{.UploadMTU}}</td><td>{{.DownloadMTU}}</td><td>{{.LastSeen}}</td></tr>{{end}}</table>
{{else}}<p>Resolver health: unavailable ({{.Content.Resolver.Note}})</p>{{end}}</div>
<div class="card"><h3>Compression</h3>
<p>Dictionary version: <code>{{.Content.Compression.DictionaryVersion}}</code> &middot; Upload dictionary ID: {{.Content.Compression.UploadDictionaryID}} &middot; Download dictionary ID: {{.Content.Compression.DownloadDictionaryID}}</p>
<table><tr><th>Side</th><th>Dictionary</th><th>Level</th><th>Long window</th></tr>
<tr><td>Server</td><td>{{if .Content.Compression.Server.Available}}{{if .Content.Compression.Server.DictEnabled}}enabled{{else}}disabled{{end}}{{else}}unavailable ({{.Content.Compression.Server.Note}}){{end}}</td><td>{{if .Content.Compression.Server.Available}}{{.Content.Compression.Server.Level}}{{else}}&mdash;{{end}}</td><td>{{if .Content.Compression.Server.Available}}{{if .Content.Compression.Server.LongEnabled}}enabled{{else}}disabled{{end}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>Node</td><td>{{if .Content.Compression.Node.Available}}{{if .Content.Compression.Node.DictEnabled}}enabled{{else}}disabled{{end}}{{else}}unavailable ({{.Content.Compression.Node.Note}}){{end}}</td><td>{{if .Content.Compression.Node.Available}}{{.Content.Compression.Node.Level}}{{else}}&mdash;{{end}}</td><td>{{if .Content.Compression.Node.Available}}{{if .Content.Compression.Node.LongEnabled}}enabled{{else}}disabled{{end}}{{else}}&mdash;{{end}}</td></tr></table>
{{if .Content.Compression.Warning}}<p class="warn"><strong>Symmetric-enablement warning:</strong> {{.Content.Compression.Warning}}</p>{{end}}
<p class="muted">Dictionary frames require symmetric enablement: a peer without dictionaries enabled drops dictionary frames. Level 0 keeps the legacy encoder; level 9 is the measured knee. The long window showed no measured gain; keep it off unless a field test proves otherwise.</p>
<form method="post" action="{{.WebPath}}/compression">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label><input type="checkbox" name="dict_enabled" value="yes"{{if .Content.Compression.Server.DictEnabled}} checked{{end}}> Enable dictionary compression (both sides)</label>
<label for="zstd-level">Zstd level (0&ndash;22, both sides)</label>
<input type="number" id="zstd-level" name="zstd_level" value="{{if .Content.Compression.Server.Available}}{{.Content.Compression.Server.Level}}{{else}}0{{end}}" min="0" max="22">
<label><input type="checkbox" name="long_enabled" value="yes"{{if .Content.Compression.Server.LongEnabled}} checked{{end}}> Enable long window (both sides)</label>
<p class="muted">Writes only the three ZSTD_* lines in the server config, and the ZSTD_* lines plus the negotiated compression-type lines in the node config (previous versions kept as .bak). Enabling dictionaries also switches the node compression types to ZSTD; disabling switches them back to LZ4. The setting takes effect only after restarting the server and the node service.</p>
<label><input type="checkbox" name="confirm" value="yes" required> I understand both sides must match and both processes must restart.</label>
<p><button type="submit">Apply compression settings</button></p>
</form></div>
<div class="card"><h3>Registry (live control)</h3>
<p>Control socket: {{if .Content.Control.Configured}}{{if .Content.Control.Reachable}}reachable — changes apply without a restart{{else}}configured but unreachable — changes are written to the registry file; restart the server to apply them{{end}}{{else}}not configured — changes are written to the registry file; restart the server to apply them{{end}}</p>
<form method="post" action="{{.WebPath}}/registry/reload" class="inline">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<button type="submit">Reload registry (live)</button>
</form>
<form method="post" action="{{.WebPath}}/registry/add" class="inline">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="ra-node">Node ID</label>
<input type="text" id="ra-node" name="node_id" required>
<label for="ra-key">Key (leave empty to generate one, shown once)</label>
<input type="text" id="ra-key" name="key" autocomplete="off">
<button type="submit">Add node</button>
</form>
<form method="post" action="{{.WebPath}}/registry/remove" class="inline">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="rr-node">Node ID</label>
<input type="text" id="rr-node" name="node_id" required>
<label><input type="checkbox" name="confirm" value="yes" required> confirm removal</label>
<button type="submit">Remove node</button>
</form>
<form method="post" action="{{.WebPath}}/registry/rotate" class="inline">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="ro-node">Node ID</label>
<input type="text" id="ro-node" name="node_id" required>
<button type="submit">Rotate key (shown once)</button>
</form>
<p class="muted">Rotation only changes the registry. Deliver the new key to the node from <a href="{{.WebPath}}/nodes">Nodes</a> (rotate/deliver) before the node can connect with it.</p></div>
<div class="card"><h3>Apply registry changes</h3>
<p>Restarting the server drops existing sessions. Confirm to proceed.</p>
<form method="post" action="{{.WebPath}}/restart-server">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label><input type="checkbox" name="confirm" value="yes" required> I understand existing sessions will drop.</label>
<p><button type="submit">Apply &amp; restart server</button></p>
</form></div>
<div class="card"><h3>More</h3>
<p><a href="{{.WebPath}}/wizard">Setup wizard</a> &middot; <a href="{{.WebPath}}/nodes">Nodes</a> &middot; <a href="{{.WebPath}}/logs">Logs</a> &middot; <a href="{{.WebPath}}/jobs">Jobs</a></p>
<p class="muted">The JSON agent API lives under the same secret path at /api/* and uses the same session authentication. See docs/PANEL-AGENT-API.md.</p></div>
{{end}}`

const logsTemplate = `{{define "content"}}<h2>Logs</h2>
<p>Last {{.Content.Lines}} lines of each service unit. Lines that may carry secret material are dropped and never rendered.</p>
<div class="card"><h3>nexounel (server)</h3>
{{if .Content.Tails.ServerOK}}<pre>{{range .Content.Tails.ServerLines}}{{.}}
{{end}}</pre>{{else}}<p>unavailable</p>{{end}}</div>
<div class="card"><h3>nexounel-node</h3>
{{if .Content.Tails.NodeOK}}<pre>{{range .Content.Tails.NodeLines}}{{.}}
{{end}}</pre>{{else}}<p>unavailable</p>{{end}}</div>
{{end}}`

const wizardTemplate = `{{define "content"}}<h2>Setup wizard</h2>
<p>Create the DNS records that delegate a tunnel subdomain to this server, then register a node. The node key is shown once: copy it before confirming.</p>
{{if .Content.Errors}}<ul class="error">{{range .Content.Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Content.Results}}<div class="card"><h3>DNS verification</h3>
<table><tr><th>Record</th><th>Name</th><th>Expected</th><th>Resolver</th><th>Result</th></tr>
{{range .Content.Results}}<tr><td>{{.Record}}</td><td>{{.Name}}</td><td>{{.Expected}}</td><td>{{.Resolver}}</td><td>{{if .OK}}verified{{else}}not verified{{if .Error}} ({{.Error}}){{end}}{{end}}</td></tr>{{end}}</table>
{{if .Content.Passed}}<p class="ok">Verification passed.</p>{{else}}<p class="error">Verification did not pass. Check the records and try again.</p>{{end}}</div>{{end}}
{{if .Content.Pending}}<div class="card"><h3>Node deliverables (shown once)</h3>
<p>Connect address: <code>{{.Content.Pending.ConnectAddress}}</code></p>
<p>Node ID: <code>{{.Content.Pending.ID}}</code></p>
<label for="nodekey">Node key (copy now; it will not be shown again)</label>
<input type="text" id="nodekey" readonly value="{{.Content.Pending.Key}}">
<p>Store the key with the node. Confirming writes the node to the registry; the key is not displayed again.</p>
{{if .Content.RevocationGuidance}}<p class="warn">Cloudflare: the authorization used for this run was not stored. Revoke the Global API key or scoped token if it is no longer needed. For future record management, prefer a scoped API token limited to Zone:DNS:Edit on this single zone, entered fresh each time.</p>{{end}}
<form method="post" action="{{.WebPath}}/wizard">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="action" value="confirm">
<p><button type="submit">Confirm and register node</button></p>
</form>
<form method="post" action="{{.WebPath}}/wizard">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="action" value="cancel">
<p><button type="submit">Discard</button></p>
</form></div>
{{else}}
<div class="card"><h3>Manual records</h3>
<p>Create these exact records at your DNS provider (DNS-only, no proxy), then verify.</p>
<form method="post" action="{{.WebPath}}/wizard">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="action" value="verify-manual">
<label for="m-domain">Domain</label>
<input type="text" id="m-domain" name="domain" value="{{.Content.Domain}}" placeholder="example.invalid" required>
<label for="m-subdomain">Tunnel subdomain (default v)</label>
<input type="text" id="m-subdomain" name="subdomain" value="{{.Content.Subdomain}}" placeholder="v">
<label for="m-mother">Mother server IP (IPv4)</label>
<input type="text" id="m-mother" name="mother_ip" value="{{.Content.MotherIP}}" placeholder="203.0.113.10" required>
<label for="m-node">Node ID (optional; generated when empty)</label>
<input type="text" id="m-node" name="node_id" value="{{.Content.NodeID}}">
<label for="m-port">Node listen port</label>
<input type="number" id="m-port" name="listen_port" value="{{.Content.ListenPort}}" min="1" max="65535">
<label for="m-range">Forward range (lo-hi)</label>
<input type="text" id="m-range" name="forward_range" value="{{.Content.ForwardRange}}" placeholder="20000-20010" required>
<p><button type="submit">Verify records</button></p>
</form></div>
<div class="card"><h3>Automatic (Cloudflare)</h3>
<p>Enter a Cloudflare Global API key (with email) or a scoped API token. It is used only for this run and is never stored.</p>
<form method="post" action="{{.WebPath}}/wizard">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="action" value="create-auto">
<label for="a-domain">Domain</label>
<input type="text" id="a-domain" name="domain" value="{{.Content.Domain}}" placeholder="example.invalid" required>
<label for="a-subdomain">Tunnel subdomain (default v)</label>
<input type="text" id="a-subdomain" name="subdomain" value="{{.Content.Subdomain}}" placeholder="v">
<label for="a-mother">Mother server IP (IPv4)</label>
<input type="text" id="a-mother" name="mother_ip" value="{{.Content.MotherIP}}" placeholder="203.0.113.10" required>
<label for="a-node">Node ID (optional; generated when empty)</label>
<input type="text" id="a-node" name="node_id" value="{{.Content.NodeID}}">
<label for="a-port">Node listen port</label>
<input type="number" id="a-port" name="listen_port" value="{{.Content.ListenPort}}" min="1" max="65535">
<label for="a-range">Forward range (lo-hi)</label>
<input type="text" id="a-range" name="forward_range" value="{{.Content.ForwardRange}}" placeholder="20000-20010" required>
<label for="a-email">Cloudflare email (Global API key only; leave empty for a scoped token)</label>
<input type="text" id="a-email" name="cf_email" autocomplete="off">
<label for="a-key">Cloudflare Global API key (only when an email is given)</label>
<input type="password" id="a-key" name="cf_api_key" autocomplete="off">
<label for="a-token">Cloudflare scoped API token (alternative to email + key)</label>
<input type="password" id="a-token" name="cf_api_token" autocomplete="off">
<p><button type="submit">Create records and verify</button></p>
</form></div>
{{end}}{{end}}`

const nodesTemplate = `{{define "content"}}<h2>Nodes</h2>
{{if .Content.RegistryError}}<p>Registry: unavailable ({{.Content.RegistryError}})</p>{{else}}
<table><tr><th>Node</th><th>Key fingerprint</th><th>Actions</th></tr>
{{range .Content.Nodes}}<tr><td>{{.ID}}</td><td class="mono">{{.Fingerprint}}</td><td>
<form method="post" action="{{$.WebPath}}/nodes/remove" style="display:inline">
<input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
<input type="hidden" name="node_id" value="{{.ID}}">
<label style="display:inline"><input type="checkbox" name="remove_remote" value="yes"> also stop/remove remote service</label>
<label style="display:inline"><input type="checkbox" name="confirm" value="yes" required> confirm</label>
<button type="submit">Remove</button></form>
</td></tr>{{end}}</table>{{end}}
<div class="card"><h3>Provision a node</h3>
<p>Deliver the node software and configuration to a Debian/Ubuntu server over SSH. Credentials live only in the job's memory. If the host key is unknown, the job pauses for fingerprint confirmation.</p>
<form method="post" action="{{.WebPath}}/nodes/provision">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="p-node">Node ID (must already be in the registry)</label>
<input type="text" id="p-node" name="node_id" required>
<label for="p-host">Target host (IP or hostname)</label>
<input type="text" id="p-host" name="ssh_host" required>
<label for="p-port">SSH port</label>
<input type="number" id="p-port" name="ssh_port" value="22" min="1" max="65535">
<label for="p-user">SSH username</label>
<input type="text" id="p-user" name="ssh_user" value="root" required>
<label for="p-pass">SSH password (leave empty when using a key below)</label>
<input type="password" id="p-pass" name="ssh_password" autocomplete="off">
<label for="p-key">SSH private key (PEM, alternative to password)</label>
<textarea id="p-key" name="ssh_key" rows="4" autocomplete="off"></textarea>
<label for="p-listen">Node listen port</label>
<input type="number" id="p-listen" name="listen_port" value="18000" min="1" max="65535">
<label for="p-range">Forward range (lo-hi)</label>
<input type="text" id="p-range" name="forward_range" placeholder="20000-20010" required>
<label for="p-addr">Connect address (tunnel subdomain)</label>
<input type="text" id="p-addr" name="connect_addr" placeholder="v.example.invalid" required>
<p><button type="submit">Start provisioning</button></p>
</form></div>
<div class="card"><h3>Rotate a node key</h3>
<p>Generates a new key, updates the registry, delivers the new key file, and restarts only that node. Then restart the server from Status to apply the registry change.</p>
<form method="post" action="{{.WebPath}}/nodes/rotate">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="r-node">Node ID</label>
<input type="text" id="r-node" name="node_id" required>
<label for="r-host">Target host</label>
<input type="text" id="r-host" name="ssh_host" required>
<label for="r-port">SSH port</label>
<input type="number" id="r-port" name="ssh_port" value="22" min="1" max="65535">
<label for="r-user">SSH username</label>
<input type="text" id="r-user" name="ssh_user" value="root" required>
<label for="r-pass">SSH password</label>
<input type="password" id="r-pass" name="ssh_password" autocomplete="off">
<label for="r-key">SSH private key (PEM, alternative to password)</label>
<textarea id="r-key" name="ssh_key" rows="4" autocomplete="off"></textarea>
<p><button type="submit">Rotate key and deliver</button></p>
</form></div>
<div class="card"><h3>Re-deliver the current key</h3>
<p>If a rotation updated the registry but delivery failed, deliver the registry's current key to the node without rotating again.</p>
<form method="post" action="{{.WebPath}}/nodes/deliver">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="d-node">Node ID</label>
<input type="text" id="d-node" name="node_id" required>
<label for="d-host">Target host</label>
<input type="text" id="d-host" name="ssh_host" required>
<label for="d-port">SSH port</label>
<input type="number" id="d-port" name="ssh_port" value="22" min="1" max="65535">
<label for="d-user">SSH username</label>
<input type="text" id="d-user" name="ssh_user" value="root" required>
<label for="d-pass">SSH password</label>
<input type="password" id="d-pass" name="ssh_password" autocomplete="off">
<label for="d-key">SSH private key (PEM, alternative to password)</label>
<textarea id="d-key" name="ssh_key" rows="4" autocomplete="off"></textarea>
<p><button type="submit">Deliver current key</button></p>
</form></div>
{{end}}`

const jobsTemplate = `{{define "content"}}<h2>Jobs</h2>
{{if .Content.Jobs}}<table><tr><th>ID</th><th>Kind</th><th>Node</th><th>Status</th><th>Started</th></tr>
{{range .Content.Jobs}}<tr><td><a href="{{$.WebPath}}/jobs/{{.ID}}">{{.ID}}</a></td><td>{{.Kind}}</td><td>{{.NodeID}}</td><td>{{.Status}}</td><td>{{.CreatedAt}}</td></tr>{{end}}</table>
{{else}}<p>No jobs yet.</p>{{end}}{{end}}`

const jobTemplate = `{{define "content"}}<h2>Job {{.Content.Job.ID}}</h2>
<p>Kind: {{.Content.Job.Kind}} &middot; Node: {{.Content.Job.NodeID}} &middot; Status: <strong>{{.Content.Job.Status}}</strong></p>
{{if .Content.Job.Error}}<p class="error">{{.Content.Job.Error}}</p>{{end}}
{{if .Content.Job.CleanupWarning}}<p class="warn">{{.Content.Job.CleanupWarning}}</p>{{end}}
{{if eq .Content.Job.Status "needs-confirmation"}}<div class="card"><h3>Host key confirmation</h3>
<p>The target presented an unknown SSH host key. Verify this fingerprint out of band before trusting it:</p>
<p class="mono">{{.Content.Job.HostKeyFingerprint}}</p>
<form method="post" action="{{.WebPath}}/jobs/{{.Content.Job.ID}}/confirm-hostkey">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label><input type="checkbox" name="confirm" value="yes" required> I verified this fingerprint and trust this host.</label>
<p><button type="submit">Save fingerprint and trust host</button></p>
</form>
<p>After saving, run the provisioning step again with the same details.</p></div>{{end}}
<h3>Steps</h3>
<table><tr><th>Step</th><th>Status</th><th>Detail</th></tr>
{{range .Content.Job.Steps}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.Detail}}</td></tr>{{end}}</table>
<h3>Log</h3>
<pre>{{range .Content.Job.Log}}{{.}}
{{end}}</pre>
<p><a href="{{.WebPath}}/jobs">All jobs</a></p>{{end}}`

const messageTemplate = `{{define "content"}}<h2>{{.Content.Heading}}</h2>
<p>{{.Content.Body}}</p>
{{if .Content.Link}}<p><a href="{{.Content.Link}}">{{.Content.LinkText}}</a></p>{{end}}{{end}}`

var pageTemplates = map[string]string{
	"login":   loginTemplate,
	"status":  statusTemplate,
	"logs":    logsTemplate,
	"wizard":  wizardTemplate,
	"nodes":   nodesTemplate,
	"jobs":    jobsTemplate,
	"job":     jobTemplate,
	"message": messageTemplate,
}

// PageData is the data passed to every page template.
type PageData struct {
	Title         string
	WebPath       string
	CSS           template.CSS
	CSRFToken     string
	Authenticated bool
	Username      string
	Error         string
	Message       string
	Refresh       bool
	Content       any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data PageData) {
	body, ok := pageTemplates[page]
	if !ok {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	tmpl, err := template.New("panel").Parse(layoutTemplate)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := tmpl.Parse(body); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.CSS = template.CSS(panelCSS)
	if data.Title == "" {
		data.Title = page
	}
	if data.WebPath == "" {
		data.WebPath = s.cfg.WebPath
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, message string, sess *Session) {
	w.WriteHeader(status)
	data := PageData{Title: "Error"}
	if sess != nil && sess.Authenticated {
		data.Authenticated = true
		data.Username = sess.Username
		data.CSRFToken = sess.CSRFToken
	}
	s.render(w, r, "message", dataWithContent(data, messageContent{Heading: "Error", Body: message}))
}

type messageContent struct {
	Heading  string
	Body     string
	Link     string
	LinkText string
}

func dataWithContent(data PageData, content any) PageData {
	data.Content = content
	return data
}
