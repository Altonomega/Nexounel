package panel

import (
	"bytes"
	"html/template"
	"net/http"
	"runtime/debug"
)

const panelCSS = `:root{
--bg:#0b0f14;--bg-soft:#0d1218;--surface:#121924;--surface2:#151d29;
--border:#26303f;--border-soft:#232d3d;--text:#e6edf3;--muted:#8b98a9;
--muted2:#9fb0c3;--accent:#38bdf8;--accent2:#2dd4bf;--blue:#0e49b5;
--blue2:#2f67c2;--blue-deep:#04308f;--green:#34d399;--red:#f87171;
--amber:#fbbf24;--radius:1.5rem;--radius-sm:.5rem
}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.5;animation:pageIn .4s ease both}
@keyframes pageIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
a{color:#7dd3fc;text-decoration:none}
a:hover{color:#bae6fd}
.app{display:flex;min-height:100vh}
.sider{width:236px;flex-shrink:0;background:var(--bg-soft);border-right:1px solid #1f2a38;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;padding:18px 12px;animation:slideIn .45s cubic-bezier(.23,1,.32,1) both}
@keyframes slideIn{from{opacity:0;transform:translateX(-14px)}to{opacity:1;transform:none}}
.brand{display:flex;align-items:center;gap:11px;padding:6px 10px 18px;border-bottom:1px solid #1f2a38;margin-bottom:14px}
.brand-mark{width:38px;height:38px;flex-shrink:0;border-radius:11px;background:linear-gradient(135deg,#38bdf8,#0e49b5 60%,#2dd4bf);display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:0 4px 14px rgba(56,189,248,.35)}
.brand-mark svg{width:22px;height:22px}
.brand-name{font-size:17px;font-weight:700;letter-spacing:.3px;line-height:1.2}
.brand-sub{font-size:11px;color:var(--muted);letter-spacing:.08em;text-transform:uppercase}
.menu{display:flex;flex-direction:column;gap:4px;flex:1}
.menu a{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:var(--radius-sm);color:var(--muted2);font-size:14px;font-weight:500;transition:background .2s ease,color .2s ease,transform .2s ease}
.menu a svg{width:17px;height:17px;flex-shrink:0;opacity:.85}
.menu a:hover{color:var(--text);background:#1b2534;transform:translateX(2px)}
.menu a.active{color:#fff;background-color:var(--blue-deep);background-image:linear-gradient(270deg,rgba(123,199,77,0) 30%,var(--blue2),rgba(123,199,77,0) 100%);background-repeat:no-repeat;animation:menuGlow linear 6.6s infinite;box-shadow:0 4px 14px rgba(14,73,181,.35)}
@keyframes menuGlow{0%{background-position:-500px 0}50%{background-position:1000px 0}100%{background-position:1000px 0}}
.sider-foot{border-top:1px solid #1f2a38;padding-top:14px}
.sider-foot .user-chip{display:flex;align-items:center;gap:9px;padding:8px 10px;color:var(--muted2);font-size:13px}
.user-chip .avatar{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#38bdf8,#2dd4bf);color:#06202b;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.user-chip .avatar svg{width:16px;height:16px}
.sider-foot form{margin:6px 0 0}
.sider-foot button{width:100%;background:transparent;border:1px solid var(--border);color:var(--muted2);box-shadow:none}
.sider-foot button:hover{background:#1b2534;color:var(--text);border-color:#334155;filter:none;transform:none}
.main-col{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:10;background:rgba(11,15,20,.86);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid #1f2a38;padding:15px 26px;display:flex;align-items:center;gap:14px;animation:fadeDown .45s ease both}
@keyframes fadeDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}
.topbar h1{font-size:20px;margin:0;letter-spacing:.3px}
main{max-width:1160px;width:100%;margin:0 auto;padding:26px;flex:1}
h2{font-size:22px;margin:4px 0 16px;color:#f0f6fc}
h3{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:#8fa3b8;margin:0 0 12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:6px 0 20px}
.stat{background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--border);border-radius:1rem;padding:16px 18px;position:relative;overflow:hidden;animation:fadeUp .5s cubic-bezier(.23,1,.32,1) both;transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease}
.stat:nth-child(1){animation-delay:.03s}.stat:nth-child(2){animation-delay:.09s}.stat:nth-child(3){animation-delay:.15s}.stat:nth-child(4){animation-delay:.21s}
.stat:hover{transform:translateY(-2px);box-shadow:0 10px 26px rgba(0,0,0,.4);border-color:#334155}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.stat.ok::before{background:var(--green)}
.stat.bad::before{background:var(--red)}
.stat.warn::before{background:var(--amber)}
.stat-label{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin-bottom:6px}
.stat-value{font-size:24px;font-weight:700;line-height:1.15}
.stat-value .dot{width:9px;height:9px;border-radius:50%;background:var(--green);display:inline-block;margin-right:8px;animation:pulse 2s ease-in-out infinite;vertical-align:2px}
.stat-sub{font-size:12px;color:var(--muted);margin-top:4px}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.card{background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--border);border-radius:var(--radius);padding:20px 22px;margin:18px 0;box-shadow:0 4px 18px rgba(0,0,0,.35);overflow-x:auto;animation:cardIn .5s cubic-bezier(.23,1,.32,1) both;transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease}
.card:hover{transform:translateY(-2px);box-shadow:0 12px 30px rgba(0,0,0,.45);border-color:#334155}
@keyframes cardIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
main>.card:nth-child(1){animation-delay:.02s}main>.card:nth-child(2){animation-delay:.06s}main>.card:nth-child(3){animation-delay:.1s}main>.card:nth-child(4){animation-delay:.14s}main>.card:nth-child(5){animation-delay:.18s}main>.card:nth-child(6){animation-delay:.22s}main>.card:nth-child(7){animation-delay:.26s}main>.card:nth-child(8){animation-delay:.3s}main>.card:nth-child(9){animation-delay:.34s}main>.card:nth-child(10){animation-delay:.38s}main>.card:nth-child(11){animation-delay:.42s}main>.card:nth-child(12){animation-delay:.46s}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--border-soft);padding:11px 10px;text-align:left;vertical-align:top}
th{color:#8fa3b8;font-size:12px;text-transform:uppercase;letter-spacing:.06em;background:#18202d}
tr{transition:background .18s ease}
tr:hover td{background:#1b2534}
tr:last-child td{border-bottom:0}
code{background:#1c2534;padding:2px 6px;border-radius:4px;font-size:13px;color:#a5d8ff}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;max-width:480px;padding:10px 12px;border:1px solid #2a3442;border-radius:10px;background:#0d1319;color:var(--text);font-size:14px;transition:border-color .2s ease,box-shadow .2s ease}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.18)}
label{display:block;margin:14px 0 5px;font-weight:600;color:#c6d2df}
button,.btn{background:linear-gradient(135deg,#0284c7,#0e49b5);color:#fff;border:0;padding:10px 20px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:transform .18s ease,box-shadow .18s ease,filter .18s ease;box-shadow:0 4px 14px rgba(2,132,199,.3)}
button:hover,.btn:hover{filter:brightness(1.12);transform:translateY(-1px);box-shadow:0 8px 20px rgba(2,132,199,.4)}
button:active,.btn:active{transform:scale(.98)}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge-up{color:#34d399;background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.35)}
.badge-down{color:#f87171;background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.35)}
.badge-warn{color:#fbbf24;background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.35)}
.badge .dot{width:7px;height:7px;border-radius:50%;background:#34d399;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(52,211,153,.45)}50%{box-shadow:0 0 0 5px rgba(52,211,153,0)}}
.error{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.4);color:#fecaca;padding:12px 14px;border-radius:10px;animation:fadeUp .35s ease both}
.ok{background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.4);color:#a7f3d0;padding:12px 14px;border-radius:10px;animation:fadeUp .35s ease both}
.warn{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.4);color:#fde68a;padding:12px 14px;border-radius:10px;animation:fadeUp .35s ease both}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
pre{background:#0d1117;color:#dbe4ee;padding:14px;border:1px solid var(--border-soft);border-radius:10px;overflow:auto;font-size:13px}
footer{padding:18px 24px;color:#6b7a8d;font-size:13px;text-align:center}
.muted{color:var(--muted);font-size:13px}
form.inline{display:inline}
.login-wrap{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px;background:radial-gradient(600px 300px at 50% -80px,rgba(56,189,248,.14),transparent 70%),radial-gradient(500px 260px at 85% 110%,rgba(45,212,191,.1),transparent 70%),var(--bg)}
.login-card{width:100%;max-width:420px;background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--border);border-radius:var(--radius);padding:34px 32px 28px;box-shadow:0 24px 60px rgba(0,0,0,.55);animation:popIn .5s cubic-bezier(.23,1,.32,1) both}
@keyframes popIn{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.login-brand{display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:8px}
.login-brand .brand-mark{width:54px;height:54px;border-radius:16px;margin-bottom:14px}
.login-brand .brand-mark svg{width:30px;height:30px}
.login-brand h1{font-size:22px;margin:0 0 4px}
.login-brand p{margin:0;color:var(--muted);font-size:13px}
.login-card h2{text-align:center;margin:18px 0 4px}
.login-card .login-sub{text-align:center;color:var(--muted);font-size:13px;margin:0 0 6px}
.login-card input{max-width:none}
.login-card button{width:100%;padding:12px;margin-top:6px}
.login-foot{margin-top:18px;color:#6b7a8d;font-size:12px;text-align:center;animation:fadeUp .6s ease both}
@media (max-width:860px){
.app{flex-direction:column}
.sider{width:100%;height:auto;position:static;flex-direction:row;align-items:center;padding:10px 12px;gap:10px;border-right:0;border-bottom:1px solid #1f2a38}
.brand{padding:0;border-bottom:0;margin-bottom:0;flex-shrink:0}
.brand-sub{display:none}
.menu{flex-direction:row;overflow-x:auto;gap:4px;flex:1}
.menu a{white-space:nowrap;padding:8px 10px}
.menu a span{display:none}
.sider-foot{border-top:0;padding-top:0;display:flex;align-items:center;gap:8px}
.sider-foot .user-chip{display:none}
.sider-foot button{width:auto;padding:7px 12px}
main{padding:18px 16px}
.topbar{padding:12px 16px}
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media (max-width:520px){.stats{grid-template-columns:1fr}.login-card{padding:26px 20px}}
/* System health banner: one plain-language line answering "is everything OK?" */
.health-banner{display:flex;align-items:flex-start;gap:12px;border-radius:1rem;padding:15px 18px;margin:8px 0 20px;border:1px solid var(--border);background:linear-gradient(180deg,var(--surface2),var(--surface));animation:fadeUp .5s ease both}
.health-banner .hb-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;margin-top:5px;animation:pulse 2s ease-in-out infinite}
.health-banner.healthy{border-color:rgba(52,211,153,.35)}
.health-banner.healthy .hb-dot{background:var(--green)}
.health-banner.degraded{border-color:rgba(251,191,36,.4)}
.health-banner.degraded .hb-dot{background:var(--amber)}
.health-banner.down{border-color:rgba(248,113,113,.45)}
.health-banner.down .hb-dot{background:var(--red)}
.health-banner .hb-title{font-size:15px;font-weight:700;line-height:1.35}
.health-banner .hb-sub{font-size:13px;color:var(--muted);margin-top:2px}
/* 3D topology: mother hub + satellite nodes, pure CSS 3D (no JS).
The scene is a flat "floor" (SVG links) with the mother raised highest
and the nodes raised less, tilted by a gentle sway. Without 3D support
it degrades to the same flat layout — nothing breaks. */
.topo{overflow:hidden}
.topo-scene{position:relative;height:360px;perspective:1100px}
.topo-stage{position:absolute;inset:0;transform-style:preserve-3d;transform:rotateX(10deg);animation:topoSway 26s ease-in-out infinite alternate}
@keyframes topoSway{from{transform:rotateX(10deg) rotateY(-13deg)}to{transform:rotateX(10deg) rotateY(13deg)}}
.topo-svg{position:absolute;inset:0;width:100%;height:100%}
.topo-link{stroke-width:1.4;vector-effect:non-scaling-stroke;opacity:.75;stroke-dasharray:7 7;animation:topoFlow 1.4s linear infinite}
@keyframes topoFlow{to{stroke-dashoffset:-14}}
.topo-link-healthy{stroke:#34d399}
.topo-link-degraded{stroke:#fbbf24}
.topo-link-down{stroke:#f87171}
.topo-mother{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%) translateZ(70px);width:196px;text-align:center;background:linear-gradient(180deg,#182233,#121924);border:1px solid #2f67c2;border-radius:1rem;padding:16px 14px;box-shadow:0 18px 40px rgba(0,0,0,.55),0 0 0 1px rgba(56,189,248,.12),0 0 34px rgba(56,189,248,.16)}
.topo-mother .topo-role{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}
.topo-mother .topo-name{font-size:18px;font-weight:800;margin:2px 0 6px}
.topo-mother .topo-facts{font-size:12px;color:var(--muted2);line-height:1.55}
.topo-node{position:absolute;width:168px;transform:translate(-50%,-50%) translateZ(26px);background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--border);border-radius:1rem;padding:13px 14px;box-shadow:0 12px 28px rgba(0,0,0,.5);transition:transform .25s ease,box-shadow .25s ease}
.topo-node:hover{transform:translate(-50%,-50%) translateZ(44px) scale(1.03);box-shadow:0 18px 36px rgba(0,0,0,.6)}
.topo-node .topo-role{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.topo-node .topo-name{font-size:15px;font-weight:700;margin:2px 0 4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topo-node .topo-facts{font-size:12px;color:var(--muted2);line-height:1.55}
.topo-node.healthy{border-color:rgba(52,211,153,.45)}
.topo-node.degraded{border-color:rgba(251,191,36,.5)}
.topo-node.down{border-color:rgba(248,113,113,.5)}
.topo-status{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:700}
.topo-status .dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s ease-in-out infinite;flex-shrink:0}
.topo-status.healthy{color:#34d399}.topo-status.healthy .dot{background:#34d399}
.topo-status.degraded{color:#fbbf24}.topo-status.degraded .dot{background:#fbbf24}
.topo-status.down{color:#f87171}.topo-status.down .dot{background:#f87171}
.topo-chief{display:inline-block;margin-left:6px;padding:1px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.08em;color:#7dd3fc;background:rgba(56,189,248,.14);border:1px solid rgba(56,189,248,.4);vertical-align:1px}
.topo-pos-0{left:86%;top:50%}
.topo-pos-1{left:72%;top:16%}
.topo-pos-2{left:72%;top:84%}
.topo-pos-3{left:14%;top:50%}
.topo-pos-4{left:28%;top:16%}
.topo-pos-5{left:28%;top:84%}
.topo-legend{display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-top:6px;font-size:12px;color:var(--muted)}
.topo-legend .topo-status{font-weight:600}
.topo-more{margin-top:14px}
.topo-more h4{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:#8fa3b8;margin:0 0 10px}
.topo-note{margin-top:12px}
/* Advanced area: rare/advanced actions in a collapsed, clearly-marked section. */
details.advanced{margin:18px 0}
details.advanced>summary{cursor:pointer;font-size:16px;font-weight:700;padding:14px 6px;list-style:none;display:flex;align-items:baseline;gap:10px;color:#f0f6fc}
details.advanced>summary::-webkit-details-marker{display:none}
details.advanced>summary::before{content:"▸";color:var(--accent);transition:transform .2s ease;flex-shrink:0}
details.advanced[open]>summary::before{transform:rotate(90deg)}
details.advanced .adv-sub{font-size:13px;color:var(--muted);font-weight:400}
details.advanced .card{margin:14px 0}
@media (max-width:860px){
.topo-scene{height:320px}
.topo-node{width:150px}
}
@media (max-width:520px){
.topo-scene{height:300px}
.topo-mother{width:158px;padding:12px 10px}
.topo-node{width:128px;padding:10px 11px}
.topo-pos-0{left:80%;top:50%}
.topo-pos-1{left:68%;top:14%}
.topo-pos-2{left:68%;top:86%}
.topo-pos-3{left:20%;top:50%}
.topo-pos-4{left:32%;top:14%}
.topo-pos-5{left:32%;top:86%}
}
@media (prefers-reduced-motion:reduce){
.topo-stage{animation:none;transform:rotateX(0)}
.topo-link{animation:none}
}
@supports not (transform-style:preserve-3d){
.topo-stage{animation:none;transform:none}
.topo-mother,.topo-node{transform:translate(-50%,-50%)}
}`

const layoutTemplate = `{{define "layout"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="5">{{end}}
<title>{{.Title}} - Nexounel Panel</title>
<link rel="stylesheet" href="{{.WebPath}}/panel.css">
</head>
<body>
{{if .Authenticated}}
<div class="app">
<aside class="sider">
<div class="brand">
<div class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/><path d="M7.5 7.5a6.4 6.4 0 0 0 0 9M16.5 7.5a6.4 6.4 0 0 1 0 9M4.6 4.6a10.5 10.5 0 0 0 0 14.8M19.4 4.6a10.5 10.5 0 0 1 0 14.8"/></svg></div>
<div><div class="brand-name">Nexounel</div><div class="brand-sub">DNS Tunnel Panel</div></div>
</div>
<nav class="menu">
<a href="{{.WebPath}}/status" class="{{if eq .Page "status"}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/></svg><span>Dashboard</span></a>
<a href="{{.WebPath}}/connections" class="{{if eq .Page "connections"}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 7h13l-3.5-3.5M20 17H7l3.5 3.5"/></svg><span>Connections</span></a>
<a href="{{.WebPath}}/wizard" class="{{if eq .Page "wizard"}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9z"/></svg><span>Wizard</span></a>
<a href="{{.WebPath}}/nodes" class="{{if eq .Page "nodes"}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><circle cx="7" cy="7" r="1" fill="currentColor" stroke="none"/><circle cx="7" cy="17" r="1" fill="currentColor" stroke="none"/></svg><span>Nodes</span></a>
<a href="{{.WebPath}}/logs" class="{{if eq .Page "logs"}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></svg><span>Logs</span></a>
<a href="{{.WebPath}}/jobs" class="{{if or (eq .Page "jobs") (eq .Page "job")}}active{{end}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg><span>Jobs</span></a>
</nav>
<div class="sider-foot">
<div class="user-chip"><span class="avatar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"/></svg></span><span>{{.Username}}</span></div>
<form method="post" action="{{.WebPath}}/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Log out</button></form>
</div>
</aside>
<div class="main-col">
<header class="topbar"><h1>{{.Title}}</h1></header>
<main>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
{{template "content" .}}
</main>
<footer>Local administration panel. Keep the secret path and admin credentials private.{{if .BuildVersion}} &middot; Build {{.BuildVersion}}{{end}}</footer>
</div>
</div>
{{else}}
<div class="login-wrap">
<div class="login-card">
<div class="login-brand">
<div class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/><path d="M7.5 7.5a6.4 6.4 0 0 0 0 9M16.5 7.5a6.4 6.4 0 0 1 0 9M4.6 4.6a10.5 10.5 0 0 0 0 14.8M19.4 4.6a10.5 10.5 0 0 1 0 14.8"/></svg></div>
<h1>Nexounel</h1>
<p>DNS Tunnel Panel</p>
</div>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Message}}<p class="ok">{{.Message}}</p>{{end}}
{{template "content" .}}
</div>
<p class="login-foot">Local administration panel. Keep the secret path and admin credentials private.{{if .BuildVersion}} &middot; Build {{.BuildVersion}}{{end}}</p>
</div>
{{end}}
</body>
</html>{{end}}`

const loginTemplate = `{{define "content"}}<h2>Log in</h2>
<p class="login-sub">Enter the admin credentials set up with the panel first-run setup.</p>
<form method="post" action="{{.WebPath}}/login">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<label for="username">Username</label>
<input type="text" id="username" name="username" autocomplete="username" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required>
<p><button type="submit">Log in</button></p>
</form>{{end}}`

const statusTemplate = `{{define "content"}}<h2>Dashboard</h2>
<div class="health-banner {{.Content.Topology.SummaryClass}}">
<span class="hb-dot"></span>
<div><div class="hb-title">{{.Content.Topology.SummaryText}}</div>
<div class="hb-sub">Mother {{if .Content.Topology.MotherUp}}up{{else}}down{{end}} &middot; {{.Content.Topology.NodesUp}} of {{.Content.Topology.NodesTotal}} node(s) healthy &middot; {{.Content.Topology.MotherSessions}} active session(s){{if not .Content.Topology.MeshAvailable}} &middot; node status unavailable{{end}}</div></div>
</div>
<div class="stats">
<div class="stat {{if .Content.Health.Up}}ok{{else}}bad{{end}}">
<div class="stat-label">Tunnel</div>
<div class="stat-value">{{if .Content.Health.Up}}<span class="dot"></span>Reachable{{else}}Unreachable{{end}}</div>
<div class="stat-sub">{{if .Content.Health.Up}}Metrics endpoint responding{{else}}Metrics/health endpoint unreachable{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">Live sessions</div>
<div class="stat-value">{{len .Content.Sessions}}</div>
<div class="stat-sub">active tunnel sessions</div>
</div>
<div class="stat">
<div class="stat-label">Live throughput</div>
<div class="stat-value">{{if .Content.Throughput.OK}}&uarr; {{.Content.Throughput.UpRate}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">{{if .Content.Throughput.OK}}&darr; {{.Content.Throughput.DownRate}} &middot; server-wide{{else}}refresh the page to measure{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">Mesh chief</div>
<div class="stat-value">{{if .Content.Mesh.Available}}{{if .Content.Mesh.ChiefID}}{{.Content.Mesh.ChiefID}}{{else}}none{{end}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">{{if .Content.Mesh.Available}}Term {{.Content.Mesh.Term}} &middot; table v{{.Content.Mesh.Version}}{{else}}Mesh unavailable{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">Resolvers</div>
<div class="stat-value">{{if .Content.Resolver.Available}}{{.Content.Resolver.EntryTotal}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">{{if .Content.Resolver.Available}}in the fleet &middot; {{len .Content.Resolver.Classes}} MTU classes{{else}}Resolver health unavailable{{end}}</div>
</div>
</div>
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
<div class="card topo"><h3>Network topology</h3>
<div class="topo-scene"><div class="topo-stage">
<svg class="topo-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{{range .Content.Topology.Nodes}}{{if .InScene}}<line x1="50" y1="50" x2="{{.X}}" y2="{{.Y}}" class="topo-link topo-link-{{.StatusClass}}"/>{{end}}{{end}}</svg>
<div class="topo-mother">
<div class="topo-role">Mother server</div>
<div class="topo-name">mother</div>
<div class="topo-status {{if .Content.Topology.MotherUp}}healthy{{else}}down{{end}}"><span class="dot"></span>{{if .Content.Topology.MotherUp}}Up{{else}}Down{{end}}</div>
<div class="topo-facts">{{.Content.Topology.MotherSessions}} session(s){{if .Content.Topology.MotherUptime}} &middot; up {{.Content.Topology.MotherUptime}}s{{end}}</div>
</div>
{{range .Content.Topology.Nodes}}{{if .InScene}}<div class="topo-node {{.StatusClass}} {{.PosClass}}">
<div class="topo-role">Node{{if .IsChief}}<span class="topo-chief">Chief</span>{{end}}</div>
<div class="topo-name">{{.ID}}</div>
<div class="topo-status {{.StatusClass}}"><span class="dot"></span>{{.StatusLabel}}</div>
<div class="topo-facts">Loss {{printf "%.1f" .LossPercent}}% &middot; {{.ActiveStreams}} stream(s)<br>{{.ResolverUsable}} resolvers usable &middot; {{printf "%.0f" .CapacityBps}} B/s</div>
</div>{{end}}{{end}}
</div></div>
{{if gt .Content.Topology.BeyondScene 0}}<div class="topo-more"><h4>More nodes</h4>{{range .Content.Topology.Nodes}}{{if not .InScene}}<p><span class="topo-status {{.StatusClass}}"><span class="dot"></span>{{.StatusLabel}}</span> <strong>{{.ID}}</strong>{{if .IsChief}} <span class="topo-chief">Chief</span>{{end}} &mdash; Loss {{printf "%.1f" .LossPercent}}% &middot; {{.ActiveStreams}} stream(s) &middot; {{.ResolverUsable}} resolvers usable &middot; {{printf "%.0f" .CapacityBps}} B/s</p>{{end}}{{end}}</div>{{end}}
<div class="topo-legend"><span class="topo-status healthy"><span class="dot"></span>Healthy</span><span class="topo-status degraded"><span class="dot"></span>Degraded</span><span class="topo-status down"><span class="dot"></span>Down</span><span>The mother is the central hub; lines show live connections to each node.</span></div>
{{if not .Content.Topology.MeshAvailable}}<p class="muted topo-note">Node status unavailable: {{.Content.Topology.MeshNote}}</p>{{else}}{{if eq (len .Content.Topology.Nodes) 0}}<p class="muted topo-note">No nodes connected yet &mdash; <a href="{{.WebPath}}/wizard">add your first node with the Setup wizard</a>.</p>{{end}}{{end}}
</div>
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
{{if .Content.Sessions}}<table><tr><th>Session</th><th>Node</th><th>Upload MTU</th><th>Download MTU</th><th>Active streams</th><th>Age</th><th>Last activity</th></tr>{{range .Content.Sessions}}<tr><td>#{{.SessionID}}</td><td>{{.NodeID}}</td><td>{{.UploadMTU}} B</td><td>{{.DownloadMTU}} B</td><td>{{.ActiveStreams}}</td><td>{{.Age}}</td><td>{{.LastActivityAgo}}</td></tr>{{end}}</table>{{else}}<p>No live sessions reported by the control socket.</p>{{end}}
<p class="muted"><a href="{{.WebPath}}/connections">All connection details &rarr;</a></p>
{{end}}</div>
<div class="card"><h3>Mesh</h3>
{{if .Content.Mesh.Available}}
<p>Term: <strong>{{.Content.Mesh.Term}}</strong>{{if .Content.Mesh.TermDegraded}} (degraded){{end}} &middot; Table version: {{.Content.Mesh.Version}} &middot; Chief: <strong>{{if .Content.Mesh.ChiefID}}{{.Content.Mesh.ChiefID}}{{else}}none{{end}}</strong></p>
<p class="muted">Snapshot signing: {{if .Content.Mesh.SnapshotSigning}}enabled{{else}}disabled &mdash; nodes cannot derive a degraded chief if the mother link drops{{end}} &middot; Generated at {{.Content.Mesh.GeneratedAt.Format "2006-01-02 15:04:05 MST"}}</p>
{{if .Content.Mesh.Members}}<table><tr><th>Node</th><th>State</th><th>Capacity</th><th>Weight</th><th>Loss</th><th>Leg RTT (ms)</th><th>Leg</th><th>Streams</th><th>Forward ports</th><th>Config ver.</th><th>Control stream</th><th>Last heartbeat</th><th>Last ack</th></tr>{{range .Content.Mesh.Members}}<tr><td>{{.ID}}</td><td>{{.State}}</td><td>{{.CapacityRate}}</td><td>{{printf "%.3f" .Weight}}</td><td>{{printf "%.1f%%" .LossPercent}}</td><td>{{printf "%.1f" .LegRTTMs}}</td><td>{{if .LegOK}}<span class="badge badge-up"><span class="dot"></span>ok</span>{{else}}<span class="badge badge-down">down</span>{{end}}</td><td>{{.ActiveStreams}}</td><td>{{.ForwardPortsBound}}</td><td>{{.ConfigVersion}}</td><td>{{if .StreamConnected}}connected{{else}}not connected{{end}}</td><td>{{if .LastSeen.IsZero}}never{{else}}{{.LastSeen.Format "2006-01-02 15:04:05 MST"}} ({{.LastSeenAgoSeconds}}s ago){{end}}</td><td>{{if .LastAckFor}}{{.LastAckFor}}{{if .LastAckError}}: {{.LastAckError}}{{end}}{{else}}&mdash;{{end}}</td></tr>{{end}}</table>{{else}}<p>No members in the enforced table and no heartbeats recorded.</p>{{end}}
<p class="muted">Weights are capacity shares: zero means the member takes no new streams. A member shown SUSPECT or DOWN while its sessions still appear above means heartbeats stopped, not that the node is healthy.</p>
{{else}}<p>{{.Content.Mesh.Note}}</p>{{end}}</div>
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
<details class="advanced"{{if or .Error .Message}} open{{end}}><summary>Advanced <span class="adv-sub">Join tokens &middot; Compression &middot; Registry &middot; Restart</span></summary>
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
</details>
<div class="card"><h3>More</h3>
<p><a href="{{.WebPath}}/connections">Connections</a> &middot; <a href="{{.WebPath}}/wizard">Setup wizard</a> &middot; <a href="{{.WebPath}}/nodes">Nodes</a> &middot; <a href="{{.WebPath}}/logs">Logs</a> &middot; <a href="{{.WebPath}}/jobs">Jobs</a></p>
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
<p>This wizard does three things, in order:</p>
<ol>
<li><strong>DNS records</strong> &mdash; it creates two records at your DNS provider that delegate a tunnel subdomain (for example <code>v.example.com</code>) to this server, so DNS clients can reach the tunnel. Use the automatic Cloudflare path below, or create the records by hand at any provider.</li>
<li><strong>Verification</strong> &mdash; it asks the public resolvers 8.8.8.8 and 1.1.1.1 whether the records are visible, so you know the delegation works before a node is registered.</li>
<li><strong>Node registration</strong> &mdash; it creates a node entry and shows the node key once. Copy it before confirming; the key is never shown again.</li>
</ol>
{{if .Content.Errors}}<ul class="error">{{range .Content.Errors}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Content.Results}}<div class="card"><h3>DNS verification</h3>
<table><tr><th>Record</th><th>Name</th><th>Expected</th><th>Resolver</th><th>Result</th></tr>
{{range .Content.Results}}<tr><td>{{.Record}}</td><td>{{.Name}}</td><td>{{.Expected}}</td><td>{{.Resolver}}</td><td>{{if .OK}}verified{{else}}not verified{{if .Error}} ({{.Error}}){{end}}{{end}}</td></tr>{{end}}</table>
{{if .Content.Passed}}<p class="ok">Verification passed. Both records are visible at the public resolvers &mdash; you can register the node.</p>{{else}}<p class="error">Verification did not pass. Most often this is propagation, not a wrong record: wait a few minutes and try again. If it still fails, check in your DNS provider's dashboard that both records exist with the exact names, values and TTL shown below, and that the A record is DNS-only (grey cloud, not proxied). A record that answers with a different value means another record with the same name already exists.</p>{{end}}</div>{{end}}
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
<p>Create these two records at your DNS provider, with your own domain, subdomain and mother IP substituted. Both are <strong>DNS-only</strong> &mdash; never proxied (Cloudflare orange cloud off): a proxied record would route DNS through the provider's edge and the tunnel would not work. The panel never deletes or changes any existing record &mdash; it only asks you to add these two.</p>
<table><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>What it does</th></tr>
<tr><td>A</td><td>ns1.&lt;domain&gt;</td><td>&lt;mother IP&gt;</td><td>300 (5 min)</td><td>Points the nameserver name at this server. Without it, nothing can resolve the tunnel subdomain.</td></tr>
<tr><td>NS</td><td>&lt;subdomain&gt;.&lt;domain&gt;</td><td>ns1.&lt;domain&gt;</td><td>300 (5 min)</td><td>Delegates the tunnel subdomain to this server.</td></tr></table>
<p>After creating the records, press <strong>Verify records</strong>. Verification queries the public resolvers 8.8.8.8 and 1.1.1.1: the A record must answer with your mother IP, and the NS record must answer with <code>ns1.&lt;domain&gt;</code>. DNS changes can take a few minutes to appear &mdash; if verification fails, wait and try again before changing anything.</p>
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
<p>Cloudflare creates the same two records for you: A <code>ns1.&lt;domain&gt;</code> &rarr; mother IP, TTL 300, DNS-only; NS <code>&lt;subdomain&gt;.&lt;domain&gt;</code> &rarr; <code>ns1.&lt;domain&gt;</code>, TTL 300, DNS-only. The panel never deletes or changes any existing record &mdash; it only adds these two.</p>
<p>Credential: use a <strong>scoped API token limited to Zone:DNS:Edit on this single zone</strong> (preferred), or a Global API key with your account email. The credential is used only for this run and is never stored &mdash; after the run, revoke it if you no longer need it (the panel reminds you on the confirmation screen).</p>
<p>What to expect: after you submit, the panel creates the two records, then verifies them against 8.8.8.8 and 1.1.1.1. If creation succeeds but verification fails, the records are usually still propagating &mdash; wait a few minutes and press Verify again; do not create the records a second time.</p>
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

// connectionsTemplate is the Connections page: live connection
// information for the admin — sessions with ages, nodes with loss
// and bound forward ports, server-wide throughput and cumulative
// counters. It says plainly what the backend cannot provide
// (per-connection live throughput, the nodes' configured port
// ranges) instead of leaving the admin to guess.
const connectionsTemplate = `{{define "content"}}<h2>Connections</h2>
<p>Live connections on this server: tunnel sessions, nodes, forward ports, and server-wide throughput. The tunnel carries anonymous DNS traffic &mdash; there is no per-user client identity; connections are shown per node session.</p>
<div class="stats">
<div class="stat">
<div class="stat-label">Live throughput &uarr;</div>
<div class="stat-value">{{if .Content.Throughput.OK}}{{.Content.Throughput.UpRate}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">{{if .Content.Throughput.OK}}server-wide upload, since the last page load{{else}}refresh the page to measure{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">Live throughput &darr;</div>
<div class="stat-value">{{if .Content.Throughput.OK}}{{.Content.Throughput.DownRate}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">{{if .Content.Throughput.OK}}server-wide download, since the last page load{{else}}refresh the page to measure{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">Active sessions</div>
<div class="stat-value">{{len .Content.Sessions}}</div>
<div class="stat-sub">{{.Content.TotalStreams}} active streams{{if .Content.Uptime}} &middot; server up {{.Content.Uptime}}{{end}}</div>
</div>
<div class="stat">
<div class="stat-label">UDP associations</div>
<div class="stat-value">{{if .Content.Associations.OK}}{{.Content.Associations.Text}}{{else}}&mdash;{{end}}</div>
<div class="stat-sub">active generic-UDP associations{{if .Content.Endpoints.OK}} &middot; {{.Content.Endpoints.Text}} endpoints{{end}}</div>
</div>
</div>
<p class="muted">Per-connection live throughput (up/down per session) is not exposed by the server: the control socket reports session membership only, and the metrics endpoint reports server-wide counters. The live rates above are server-wide, computed from those counters between page loads; per-session traffic is shown as MTU and active streams below. Refresh the page to update the rates.</p>
{{if .Content.SessionsNote}}<p class="warn">{{.Content.SessionsNote}}</p>{{end}}
<div class="card"><h3>Live sessions</h3>
{{if .Content.Sessions}}<table><tr><th>Session</th><th>Node</th><th>Upload MTU</th><th>Download MTU</th><th>Active streams</th><th>Age</th><th>Last activity</th></tr>{{range .Content.Sessions}}<tr><td>#{{.SessionID}}</td><td>{{.NodeID}}</td><td>{{.UploadMTU}} B</td><td>{{.DownloadMTU}} B</td><td>{{.ActiveStreams}}</td><td>{{.Age}}</td><td>{{.LastActivityAgo}}</td></tr>{{end}}</table>{{else}}<p>No live sessions reported by the control socket.</p>{{end}}</div>
<div class="card"><h3>Nodes</h3>
{{if .Content.Mesh.Available}}{{if .Content.Mesh.Members}}<table><tr><th>Node</th><th>State</th><th>Loss</th><th>Capacity</th><th>Resolvers usable</th><th>Resolvers rejected</th><th>Forward ports bound</th><th>Control stream</th><th>Last heartbeat</th></tr>{{range .Content.Mesh.Members}}<tr><td>{{.ID}}{{if eq .ID $.Content.Mesh.ChiefID}} (chief){{end}}</td><td>{{.State}}</td><td>{{printf "%.1f%%" .LossPercent}}</td><td>{{.CapacityRate}}</td><td>{{.ResolverUsable}}</td><td>{{.ResolverRejected}}</td><td>{{.ForwardPortsBound}}</td><td>{{if .StreamConnected}}connected{{else}}not connected{{end}}</td><td>{{if .LastSeen.IsZero}}never{{else}}{{.LastSeen.Format "2006-01-02 15:04:05 MST"}} ({{.LastSeenAgoSeconds}}s ago){{end}}</td></tr>{{end}}</table>{{else}}<p>No nodes connected yet &mdash; <a href="{{.WebPath}}/wizard">add your first node with the Setup wizard</a>.</p>{{end}}{{else}}<p>Node status unavailable: {{.Content.Mesh.Note}}</p>{{end}}</div>
<div class="card"><h3>Forward ports</h3>
{{if .Content.Mesh.Available}}{{if .Content.Mesh.Members}}<table><tr><th>Node</th><th>Forward ports bound</th></tr>{{range .Content.Mesh.Members}}<tr><td>{{.ID}}</td><td>{{.ForwardPortsBound}}</td></tr>{{end}}</table>{{else}}<p>No nodes connected, so no forward ports are in use.</p>{{end}}{{else}}<p>Forward-port use is unavailable: {{.Content.Mesh.Note}}</p>{{end}}
<p class="muted">Each node forwards a configured port range (FORWARD_RANGE in the node config) through the tunnel. The mother has no node config file, so the range itself is not shown here &mdash; the bound count per node above is what the server can observe.</p></div>
<div class="card"><h3>Totals since server start</h3>
{{if .Content.Health.Up}}<table><tr><th>Counter</th><th>Total</th></tr>
<tr><td>Data sent (upstream)</td><td>{{if .Content.UpBytes.OK}}{{.Content.UpBytes.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>Data received (downstream)</td><td>{{if .Content.DownBytes.OK}}{{.Content.DownBytes.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>Datagrams sent</td><td>{{if .Content.UpDatagrams.OK}}{{.Content.UpDatagrams.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>Datagrams received</td><td>{{if .Content.DownDatagrams.OK}}{{.Content.DownDatagrams.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>Dropped packets</td><td>{{if .Content.DroppedPackets.OK}}{{.Content.DroppedPackets.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>DNS upstream queries</td><td>{{if .Content.UpstreamQueries.OK}}{{.Content.UpstreamQueries.Text}}{{else}}&mdash;{{end}}</td></tr>
<tr><td>DNS upstream failures</td><td>{{if .Content.UpstreamFailures.OK}}{{.Content.UpstreamFailures.Text}}{{else}}&mdash;{{end}}</td></tr></table>
<p class="muted">Cumulative counters since the server started &mdash; not live rates. The live rates at the top of this page are computed from the byte counters between page loads.</p>{{else}}<p>Server totals unavailable: the metrics endpoint is unreachable{{if .Content.Health.Error}} ({{.Content.Health.Error}}){{end}}.</p>{{end}}</div>
{{end}}`

var pageTemplates = map[string]string{
	"login":       loginTemplate,
	"status":      statusTemplate,
	"connections": connectionsTemplate,
	"logs":        logsTemplate,
	"wizard":      wizardTemplate,
	"nodes":       nodesTemplate,
	"jobs":        jobsTemplate,
	"job":         jobTemplate,
	"message":     messageTemplate,
}

// PageData is the data passed to every page template.
type PageData struct {
	Title         string
	Page          string
	WebPath       string
	CSRFToken     string
	Authenticated bool
	Username      string
	Error         string
	Message       string
	Refresh       bool
	Content       any
	// BuildVersion identifies the running panel binary (short VCS
	// revision, e.g. "53ddf08"; "dev" when no revision is stamped).
	// Rendered in the footer so the operator can prove which build
	// is serving the page.
	BuildVersion string
}

// buildVersion returns a short identifier for the running panel binary,
// from the VCS revision stamped into the binary at build time (Go 1.18+
// stamps vcs.revision when building from a git checkout). It returns
// "dev" when no revision is available (e.g. built outside a checkout).
// The footer renders it so the operator can prove which build is serving
// the page — the answer to "am I looking at the new panel or a cached
// old one?".
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 9 {
			return s.Value[:9]
		}
	}
	return "dev"
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
	data.Page = page
	if data.Title == "" {
		data.Title = page
	}
	if data.WebPath == "" {
		data.WebPath = s.cfg.WebPath
	}
	if data.BuildVersion == "" {
		data.BuildVersion = buildVersion()
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
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
