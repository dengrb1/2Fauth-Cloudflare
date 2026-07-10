export const APP_STYLES = String.raw`
:root {
  color-scheme: light;
  --bg: #f4f7f8;
  --surface: #ffffff;
  --surface-subtle: #f8fafb;
  --surface-strong: #edf5f4;
  --text: #172b2d;
  --text-muted: #657779;
  --line: #dce5e6;
  --line-strong: #c7d5d6;
  --brand: #087f79;
  --brand-strong: #05645f;
  --brand-soft: #e3f3f1;
  --danger: #b42318;
  --danger-soft: #fff0ee;
  --warning: #a15c08;
  --focus: #2f9d97;
  --sidebar: #102d30;
  --sidebar-muted: #a7bdbe;
  --radius-sm: 9px;
  --radius-md: 14px;
  --radius-lg: 20px;
  --shadow-sm: 0 1px 2px rgba(16, 45, 48, .05);
  --shadow-md: 0 14px 36px rgba(16, 45, 48, .09);
  --sidebar-width: 248px;
  --topbar-height: 76px;
}

* { box-sizing: border-box; }
html { min-width: 320px; background: var(--bg); }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  background: var(--bg);
  font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
button, input, select, textarea { font: inherit; }
button, input, select, textarea, summary { outline: none; }
button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible,
summary:focus-visible, [tabindex]:focus-visible { box-shadow: 0 0 0 3px rgba(47, 157, 151, .24); }
button { cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .52; }
.hidden, [hidden] { display: none !important; }
.visible { display: block !important; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.muted { color: var(--text-muted); font-size: 13px; }
.error { color: var(--danger); font-size: 13px; }
.stack { display: grid; gap: 16px; }
.row { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; }
.spacer { flex: 1; }

.auth-shell {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 32px 18px;
  background:
    radial-gradient(circle at 14% 10%, rgba(8, 127, 121, .16), transparent 34%),
    radial-gradient(circle at 88% 88%, rgba(73, 138, 173, .12), transparent 30%),
    linear-gradient(145deg, #f7faf9, #edf4f4);
}
.auth-card {
  width: min(100%, 440px);
  padding: 34px;
  border: 1px solid rgba(199, 213, 214, .82);
  border-radius: 24px;
  background: rgba(255,255,255,.96);
  box-shadow: 0 24px 70px rgba(16,45,48,.13);
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark {
  display: grid; place-items: center; flex: 0 0 auto;
  width: 42px; height: 42px; border-radius: 13px;
  color: white; background: linear-gradient(145deg, #0a928a, #086a67);
  box-shadow: 0 8px 18px rgba(8,127,121,.25);
}
.brand-mark svg { width: 23px; height: 23px; }
.brand-copy strong { display: block; font-size: 18px; letter-spacing: -.02em; }
.brand-copy span { color: var(--text-muted); font-size: 12px; }
.auth-heading { margin: 30px 0 22px; }
.auth-heading h1, .auth-heading h2 { margin: 0 0 6px; font-size: 27px; letter-spacing: -.035em; }
.auth-heading p { margin: 0; color: var(--text-muted); }
.auth-form { display: grid; gap: 16px; }
.auth-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 24px; padding-top: 18px; border-top: 1px solid var(--line); }

.field { display: grid; gap: 7px; min-width: 0; }
.field > span, .field-label { color: #344d4f; font-weight: 600; font-size: 13px; }
.field-hint { color: var(--text-muted); font-size: 12px; font-weight: 400; }
input, select, textarea {
  width: 100%; min-height: 44px; padding: 10px 12px;
  color: var(--text); background: #fff;
  border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
  transition: border-color .15s ease, box-shadow .15s ease;
}
input:hover, select:hover, textarea:hover { border-color: #aebfc0; }
input:focus, select:focus, textarea:focus { border-color: var(--focus); box-shadow: 0 0 0 3px rgba(47,157,151,.14); }
textarea { resize: vertical; min-height: 126px; }
input[type="color"] { padding: 5px; min-width: 48px; }
input[type="file"] { padding: 8px; }

.btn {
  min-height: 42px; display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  padding: 9px 15px; border: 1px solid transparent; border-radius: 10px;
  color: #fff; background: var(--brand); font-weight: 650;
  transition: transform .15s ease, background .15s ease, border-color .15s ease;
}
.btn:hover:not(:disabled) { background: var(--brand-strong); }
.btn[aria-busy="true"]::after { content: ""; width: 14px; height: 14px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin .65s linear infinite; }
.btn:active:not(:disabled) { transform: translateY(1px); }
.btn svg { width: 17px; height: 17px; }
.btn-secondary { color: var(--text); background: #fff; border-color: var(--line-strong); }
.btn-secondary:hover:not(:disabled) { background: var(--surface-subtle); border-color: #aebfc0; }
.btn-quiet { color: var(--text-muted); background: transparent; border-color: transparent; }
.btn-quiet:hover:not(:disabled) { color: var(--text); background: var(--surface-strong); }
.btn-danger { color: #fff; background: var(--danger); }
.btn-danger:hover:not(:disabled) { background: #8f1b13; }
.btn-block { width: 100%; }
.icon-btn { width: 42px; height: 42px; padding: 0; border-radius: 10px; }

.app-shell { min-height: 100vh; padding-left: var(--sidebar-width); }
.sidebar {
  position: fixed; inset: 0 auto 0 0; z-index: 40; width: var(--sidebar-width);
  display: flex; flex-direction: column; padding: 22px 16px;
  color: #fff; background: linear-gradient(180deg, #102f32, #0d282b 72%, #0b2426);
}
.sidebar .brand { padding: 0 8px 24px; }
.sidebar .brand-mark { width: 38px; height: 38px; box-shadow: none; }
.sidebar .brand-copy span { color: var(--sidebar-muted); }
.nav-label { padding: 12px 12px 7px; color: #779597; font-size: 11px; font-weight: 750; text-transform: uppercase; letter-spacing: .1em; }
.nav { display: grid; gap: 5px; }
.nav-item {
  width: 100%; min-height: 46px; display: flex; align-items: center; gap: 12px;
  padding: 10px 12px; color: var(--sidebar-muted); background: transparent;
  border: 0; border-radius: 11px; text-align: left; font-weight: 600;
}
.nav-item svg { width: 19px; height: 19px; }
.nav-item:hover { color: #fff; background: rgba(255,255,255,.07); }
.nav-item.active { color: #fff; background: rgba(49,176,166,.18); box-shadow: inset 3px 0 0 #47bdb4; }
.sidebar-bottom { margin-top: auto; padding-top: 18px; border-top: 1px solid rgba(255,255,255,.08); }
.sidebar-user { display: flex; align-items: center; gap: 10px; padding: 8px; }
.avatar { width: 36px; height: 36px; display: grid; place-items: center; border-radius: 50%; color: #0d3938; background: #bde6e2; font-weight: 800; }
.sidebar-user-copy { min-width: 0; }
.sidebar-user-copy strong { display: block; overflow: hidden; text-overflow: ellipsis; }
.sidebar-user-copy span { color: var(--sidebar-muted); font-size: 12px; }
.sidebar .btn-quiet { width: 100%; justify-content: flex-start; color: var(--sidebar-muted); }
.sidebar .btn-quiet:hover { color: #fff; background: rgba(255,255,255,.07); }

.topbar {
  position: sticky; top: 0; z-index: 30; min-height: var(--topbar-height);
  display: flex; align-items: center; gap: 18px; padding: 15px 28px;
  border-bottom: 1px solid var(--line); background: rgba(255,255,255,.92); backdrop-filter: blur(14px);
}
.mobile-menu { display: none; }
.page-title { min-width: 150px; }
.page-title h1 { margin: 0; font-size: 21px; letter-spacing: -.025em; }
.page-title p { margin: 1px 0 0; color: var(--text-muted); font-size: 12px; }
.topbar-search { position: relative; flex: 1; max-width: 480px; }
.topbar-search svg { position: absolute; left: 12px; top: 12px; width: 18px; color: var(--text-muted); }
.topbar-search input { padding-left: 39px; background: var(--surface-subtle); }
.main { width: min(100%, 1480px); margin: 0 auto; padding: 28px; }
.workspace { display: none; }
.workspace.active { display: block; }
.workspace-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 20px; }
.workspace-header h2 { margin: 0 0 4px; font-size: 20px; letter-spacing: -.025em; }
.workspace-header p { margin: 0; color: var(--text-muted); }

.panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius-md); box-shadow: var(--shadow-sm); }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 18px 20px; border-bottom: 1px solid var(--line); }
.panel-head h3 { margin: 0; font-size: 16px; }
.panel-body { padding: 20px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }
.toolbar .field-inline { width: auto; min-width: 170px; flex: 0 1 220px; }
.toolbar select { min-height: 42px; }
.entries-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(286px, 1fr)); gap: 16px; }
.entry-card {
  position: relative; min-width: 0; padding: 18px;
  border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--surface);
  box-shadow: var(--shadow-sm); transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
}
.entry-card:hover { transform: translateY(-2px); border-color: #c5d7d7; box-shadow: 0 12px 30px rgba(16,45,48,.08); }
.entry-card.disabled { opacity: .63; }
.entry-card-head { display: flex; align-items: flex-start; gap: 10px; }
.entry-ident { min-width: 0; flex: 1; }
.entry-ident h3 { margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 16px; }
.entry-ident p { margin: 2px 0 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-muted); font-size: 12px; }
.entry-menu-wrap { position: relative; }
.entry-menu {
  position: absolute; top: 44px; right: 0; z-index: 15; width: 205px; padding: 7px;
  border: 1px solid var(--line); border-radius: 11px; background: #fff; box-shadow: var(--shadow-md);
}
.entry-menu button, .entry-menu label { width: 100%; min-height: 38px; display: flex; align-items: center; gap: 9px; padding: 8px 10px; border: 0; border-radius: 8px; color: var(--text); background: transparent; text-align: left; }
.entry-menu button:hover { background: var(--surface-strong); }
.entry-menu button.danger { color: var(--danger); }
.entry-menu select { min-height: 38px; margin: 5px 0; }
.badges { min-height: 26px; display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin-top: 14px; }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; border-radius: 999px; color: #476062; background: var(--surface-strong); font-size: 11px; font-weight: 700; }
.swatch { width: 8px; height: 8px; flex: 0 0 auto; border-radius: 50%; background: var(--brand); }
.code-button { width: 100%; display: block; margin: 18px 0 4px; padding: 0; border: 0; color: var(--text); background: transparent; text-align: left; }
.code { font-size: clamp(28px, 3vw, 34px); line-height: 1.2; letter-spacing: .12em; font-weight: 760; font-variant-numeric: tabular-nums; }
.code-caption { display: flex; justify-content: space-between; margin-bottom: 10px; color: var(--text-muted); font-size: 12px; }
.progress { height: 6px; overflow: hidden; border-radius: 999px; background: #e9efef; }
.progress > i { display: block; height: 100%; width: 0; border-radius: inherit; background: linear-gradient(90deg, #37a69e, #087f79); transition: width .3s linear; }
.entry-footer { display: flex; align-items: center; gap: 8px; margin-top: 15px; }
.entry-footer .btn { flex: 1; }

.empty-state { grid-column: 1 / -1; display: grid; justify-items: center; gap: 10px; padding: 64px 22px; border: 1px dashed var(--line-strong); border-radius: var(--radius-md); color: var(--text-muted); text-align: center; background: rgba(255,255,255,.54); }
.empty-state svg { width: 44px; height: 44px; color: #88aaa8; }
.empty-state h3 { margin: 4px 0 0; color: var(--text); }
.empty-state p { margin: 0; max-width: 390px; }
.skeleton { min-height: 230px; overflow: hidden; background: #fff; }
.skeleton::after { content: ""; display: block; width: 75%; height: 14px; margin: 22px; border-radius: 8px; background: linear-gradient(90deg,#edf2f2 25%,#f8fafa 50%,#edf2f2 75%); background-size: 200% 100%; animation: shimmer 1.3s infinite; box-shadow: 0 38px #edf2f2, 0 89px #edf2f2, 0 126px #edf2f2; }

.two-col { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, .66fr); gap: 18px; align-items: start; }
.group-list { display: grid; gap: 10px; }
.group-item { display: flex; align-items: center; gap: 12px; padding: 14px; border: 1px solid var(--line); border-radius: 11px; }
.group-color { width: 34px; height: 34px; border-radius: 10px; background: var(--brand); }
.group-copy { min-width: 0; flex: 1; }
.group-copy strong { display: block; }
.group-copy span { color: var(--text-muted); font-size: 12px; }
.callout { padding: 14px 16px; border-radius: 11px; color: #295b57; background: var(--brand-soft); }
.callout strong { display: block; margin-bottom: 2px; }
.transfer-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 18px; }
.action-card { padding: 20px; }
.action-card h3 { margin: 0 0 5px; }
.action-card p { min-height: 42px; margin: 0 0 16px; color: var(--text-muted); }
.recommended { border-color: #9dcfca; box-shadow: inset 0 3px 0 var(--brand); }
.settings-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 18px; }
.setting-row { display: grid; grid-template-columns: 1fr minmax(180px, 240px); align-items: center; gap: 20px; padding: 18px 0; border-bottom: 1px solid var(--line); }
.setting-row:last-child { border-bottom: 0; }
.setting-row h3 { margin: 0 0 3px; font-size: 14px; }
.setting-row p { margin: 0; color: var(--text-muted); font-size: 12px; }

.table-wrap { width: 100%; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 13px 12px; border-bottom: 1px solid var(--line); text-align: left; white-space: nowrap; }
th { color: var(--text-muted); background: var(--surface-subtle); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
td.actions { display: flex; flex-wrap: wrap; gap: 7px; }

.dialog { width: min(calc(100% - 28px), 560px); max-height: min(86vh, 780px); padding: 0; overflow: hidden; border: 1px solid var(--line); border-radius: 18px; color: var(--text); background: #fff; box-shadow: 0 28px 80px rgba(9,34,36,.24); }
.dialog.wide { width: min(calc(100% - 28px), 720px); }
.dialog::backdrop { background: rgba(7,29,31,.48); backdrop-filter: blur(3px); }
.dialog-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; padding: 20px 22px 16px; border-bottom: 1px solid var(--line); }
.dialog-head h2 { margin: 0; font-size: 19px; }
.dialog-head p { margin: 3px 0 0; color: var(--text-muted); font-size: 12px; }
.dialog-body { max-height: calc(86vh - 145px); overflow-y: auto; padding: 20px 22px; }
.dialog-footer { display: flex; justify-content: flex-end; gap: 10px; padding: 15px 22px; border-top: 1px solid var(--line); background: var(--surface-subtle); }
.form-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 15px; }
.span-2 { grid-column: 1 / -1; }
.advanced { border: 1px solid var(--line); border-radius: 11px; }
.advanced summary { cursor: pointer; padding: 12px 14px; font-weight: 650; }
.advanced .advanced-body { padding: 2px 14px 14px; }
.scan-preview { width: 100%; max-height: 300px; border-radius: 11px; background: #102d30; }

.toast-region { position: fixed; right: 20px; bottom: 20px; z-index: 100; display: grid; gap: 10px; width: min(360px, calc(100% - 40px)); }
.toast { display: flex; align-items: flex-start; gap: 10px; padding: 13px 15px; border: 1px solid #acd6d2; border-radius: 11px; color: #174c48; background: #edfaf8; box-shadow: var(--shadow-md); animation: toast-in .18s ease-out; }
.toast.error { color: #7a211b; border-color: #efb8b3; background: #fff1ef; }
.toast strong { display: block; }
.toast button { margin-left: auto; padding: 0; border: 0; color: inherit; background: transparent; }
.sidebar-scrim { display: none; }

@keyframes shimmer { to { background-position: -200% 0; } }
@keyframes toast-in { from { opacity: 0; transform: translateY(8px); } }
@keyframes spin { to { transform: rotate(360deg); } }

@media (max-width: 1024px) {
  :root { --sidebar-width: 218px; }
  .main { padding: 24px; }
  .topbar { padding-inline: 24px; }
  .two-col { grid-template-columns: 1fr; }
}

@media (max-width: 768px) {
  .app-shell { padding-left: 0; }
  .sidebar { transform: translateX(-102%); width: min(86vw, 292px); transition: transform .2s ease; box-shadow: var(--shadow-md); }
  body.sidebar-open .sidebar { transform: translateX(0); }
  .sidebar-scrim { position: fixed; inset: 0; z-index: 35; display: block; visibility: hidden; opacity: 0; background: rgba(8,31,33,.46); transition: opacity .2s ease; }
  body.sidebar-open .sidebar-scrim { visibility: visible; opacity: 1; }
  .mobile-menu { display: inline-flex; }
  .topbar { min-height: 68px; padding: 11px 14px; gap: 10px; }
  .page-title { min-width: 0; flex: 1; }
  .page-title p, .topbar-search { display: none; }
  .topbar .btn-primary span { display: none; }
  .topbar .btn-primary { width: 42px; padding: 0; }
  .main { padding: 18px 14px 28px; }
  .workspace-header { align-items: center; }
  .entries-grid { grid-template-columns: 1fr; }
  .transfer-grid, .settings-grid { grid-template-columns: 1fr; }
  .setting-row { grid-template-columns: 1fr; gap: 10px; }
  .dialog-footer { position: sticky; bottom: 0; }
}

@media (max-width: 480px) {
  .auth-shell { padding: 0; align-items: stretch; }
  .auth-card { width: 100%; min-height: 100vh; padding: 28px 20px; border: 0; border-radius: 0; }
  .workspace-header h2 { font-size: 18px; }
  .toolbar > * { flex: 1 1 100%; }
  .entry-card { padding: 16px; }
  .code { font-size: 30px; }
  .form-grid { grid-template-columns: 1fr; }
  .span-2 { grid-column: auto; }
  .dialog { width: 100%; max-width: none; max-height: 94vh; margin: auto 0 0; border-radius: 18px 18px 0 0; }
  .dialog-body { max-height: calc(94vh - 145px); }
  .dialog-footer .btn { flex: 1; }
  .panel-body { padding: 16px; }
  td.actions { min-width: 240px; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
}
`;
