package report

import (
	"fmt"
	"html/template"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EasyRecon/wappaGo/structure"
)

// technoView is one detected technology as shown in a card chip.
type technoView struct {
	Name    string
	Version string
	Tooltip string // confidence / cpe, surfaced on hover
}

// cardView holds the per-host values rendered into a card. Every string here
// may originate from the scanned target (page title, hostname, cert SANs,
// technology names), so the card is rendered through html/template, which
// contextually escapes each value and closes the stored-XSS vector.
type cardView struct {
	StatusCode    int
	StatusClass   string
	Host          string
	Scheme        string
	Url           string
	Title         string
	ScreenshotSrc string
	HasShot       bool
	IP            string
	CDN           string
	ContentType   string
	Size          string
	RespTime      string
	Ports         string
	Location      string
	Cname         []string
	CertVhost     []string
	Technos       []technoView
	SearchKey     string
}

var cardTmpl = template.Must(template.New("card").Parse(`
  <article class="card s-{{.StatusClass}}" data-search="{{.SearchKey}}">
    <header class="chead">
      <span class="stamp">{{.StatusCode}}</span>
      <span class="addr">
        <span class="host">{{.Host}}</span>
        <span class="sub">{{.Scheme}}{{if .Ports}} · {{.Ports}}{{end}}</span>
      </span>
      <a class="open" href="{{.Url}}" target="_blank" rel="noopener" title="Open {{.Url}}">↗</a>
    </header>
    {{if .HasShot}}
    <button type="button" class="shot" data-full="{{.ScreenshotSrc}}" aria-label="Enlarge screenshot of {{.Host}}">
      <img src="{{.ScreenshotSrc}}" alt="Screenshot of {{.Host}}" loading="lazy">
    </button>
    {{else}}
    <div class="shot noshot" aria-hidden="true"><span>no capture</span></div>
    {{end}}
    {{if .Title}}<h2 class="ctitle" title="{{.Title}}">{{.Title}}</h2>{{end}}
    <dl class="meta">
      {{if .IP}}<div><dt>ip</dt><dd class="mono">{{.IP}}</dd></div>{{end}}
      {{if .CDN}}<div><dt>cdn</dt><dd>{{.CDN}}</dd></div>{{end}}
      {{if .ContentType}}<div><dt>type</dt><dd class="mono">{{.ContentType}}</dd></div>{{end}}
      {{if .Size}}<div><dt>size</dt><dd class="mono">{{.Size}}</dd></div>{{end}}
      {{if .RespTime}}<div><dt>time</dt><dd class="mono">{{.RespTime}}</dd></div>{{end}}
      {{if .Location}}<div class="wide"><dt>→</dt><dd class="mono trunc" title="{{.Location}}">{{.Location}}</dd></div>{{end}}
    </dl>
    {{if .Technos}}
    <ul class="techs">
      {{range .Technos}}<li class="chip"{{if .Tooltip}} title="{{.Tooltip}}"{{end}}>{{.Name}}{{if .Version}}<span class="ver">{{.Version}}</span>{{end}}</li>{{end}}
    </ul>
    {{end}}
    {{if or .CertVhost .Cname}}
    <div class="extra">
      {{if .CertVhost}}<details><summary>cert SANs<span class="n">{{len .CertVhost}}</span></summary><ul class="list mono">{{range .CertVhost}}<li>{{.}}</li>{{end}}</ul></details>{{end}}
      {{if .Cname}}<details><summary>cname<span class="n">{{len .Cname}}</span></summary><ul class="list mono">{{range .Cname}}<li>{{.}}</li>{{end}}</ul></details>{{end}}
    </div>
    {{end}}
  </article>`))

// card renders a single host card. It is the escaping boundary for all
// attacker-controlled data; everything outside it (layout, summary counts) is
// trusted, tool-generated text.
func card(data structure.Data, screenPath string) string {
	host := data.Infos.Data
	if host == "" {
		host = data.Url
	}

	var technos []technoView
	for _, t := range data.Infos.Technologies {
		var hint []string
		if t.Confidence != "" {
			hint = append(hint, "confidence "+t.Confidence)
		}
		if t.Cpe != "" {
			hint = append(hint, t.Cpe)
		}
		technos = append(technos, technoView{Name: t.Name, Version: t.Version, Tooltip: strings.Join(hint, " · ")})
	}

	keyParts := []string{data.Url, data.Infos.Title, host, data.Infos.IP, data.Infos.CDN}
	for _, t := range data.Infos.Technologies {
		keyParts = append(keyParts, t.Name)
	}

	view := cardView{
		StatusCode:    data.Infos.Status_code,
		StatusClass:   statusClass(data.Infos.Status_code),
		Host:          host,
		Scheme:        data.Infos.Scheme,
		Url:           data.Url,
		Title:         data.Infos.Title,
		ScreenshotSrc: screenPath + "/" + data.Infos.Screenshot,
		HasShot:       data.Infos.Screenshot != "",
		IP:            data.Infos.IP,
		CDN:           data.Infos.CDN,
		ContentType:   data.Infos.Content_type,
		Size:          humanizeBytes(data.Infos.Content_length),
		RespTime:      formatDuration(data.Infos.Response_time),
		Ports:         strings.Join(data.Infos.Ports, ", "),
		Location:      data.Infos.Location,
		Cname:         data.Infos.Cname,
		CertVhost:     data.Infos.CertVhost,
		Technos:       technos,
		SearchKey:     strings.ToLower(strings.Join(keyParts, " ")),
	}

	var sb strings.Builder
	if err := cardTmpl.Execute(&sb, view); err != nil {
		return ""
	}
	return sb.String()
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "ok"
	case code >= 300 && code < 400:
		return "redir"
	case code >= 400 && code < 500:
		return "client"
	case code >= 500:
		return "server"
	default:
		return "unknown"
	}
}

func humanizeBytes(n int) string {
	if n <= 0 {
		return ""
	}
	const unit = 1024
	if n < unit {
		return strconv.Itoa(n) + " B"
	}
	// The exponent must stay inside units. Content_length is attacker-supplied
	// (it is parsed straight from the Content-Length header in cmd.Do), and a
	// host advertising >= 1024^5 bytes used to push exp past the end of the old
	// 4-character "KMGT" string — an index-out-of-range panic in the report
	// writer, which destroyed the whole run's output.
	const units = "KMGTPE"
	div, exp := int64(unit), 0
	for x := int64(n) / unit; x >= unit && exp < len(units)-1; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), units[exp])
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if ms := d.Milliseconds(); ms < 1 {
		return "<1 ms"
	} else if ms < 1000 {
		return strconv.FormatInt(ms, 10) + " ms"
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

// statusBand is one segment of the distribution bar in the summary strip.
type statusBand struct {
	class string
	label string
}

var statusBands = []statusBand{
	{"ok", "2xx"},
	{"redir", "3xx"},
	{"client", "4xx"},
	{"server", "5xx"},
	{"unknown", "other"},
}

func Report_main(datas []structure.Data, screenPath string) {
	counts := map[string]int{}
	techs := map[string]bool{}
	for _, d := range datas {
		counts[statusClass(d.Infos.Status_code)]++
		for _, t := range d.Infos.Technologies {
			techs[t.Name] = true
		}
	}

	var b strings.Builder
	b.WriteString(pageHead)
	b.WriteString(renderSummary(len(datas), len(techs), counts))
	b.WriteString(`<main class="grid" id="grid">`)
	for _, d := range datas {
		b.WriteString(card(d, screenPath))
	}
	b.WriteString(pageFoot)

	_ = os.WriteFile("wappaGo_report.html", []byte(b.String()), 0644)
}

// renderSummary builds the header strip. It only ever interpolates integers and
// fixed band labels, so plain string assembly is safe (no user data).
func renderSummary(hosts, techCount int, counts map[string]int) string {
	var bar, legend strings.Builder
	for _, band := range statusBands {
		c := counts[band.class]
		if c == 0 {
			continue
		}
		n := strconv.Itoa(c)
		bar.WriteString(`<span class="seg s-` + band.class + `" style="flex-grow:` + n + `" title="` + band.label + `: ` + n + `"></span>`)
		legend.WriteString(`<li class="s-` + band.class + `"><i></i>` + band.label + `<b>` + n + `</b></li>`)
	}

	generated := time.Now().Format("2006-01-02 15:04 MST")
	return `<section class="summary">
      <div class="stat"><span class="num">` + strconv.Itoa(hosts) + `</span><span class="lbl">hosts</span></div>
      <div class="dist">
        <div class="bar" role="img" aria-label="HTTP status distribution">` + bar.String() + `</div>
        <ul class="legend">` + legend.String() + `</ul>
      </div>
      <div class="stat"><span class="num">` + strconv.Itoa(techCount) + `</span><span class="lbl">technologies</span></div>
      <div class="gen"><span class="count" id="count"></span><span class="ts">` + generated + `</span></div>
    </section>`
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wappaGo · attack surface report</title>
<style>
:root{
  --bg:#0a0e13; --panel:#121a24; --panel2:#0d141d; --line:#1f2b39;
  --ink:#d8e1ec; --muted:#7e8b9c; --faint:#556271; --accent:#36d1c4;
  --ok:#3fb950; --redir:#58a6ff; --client:#d8a017; --server:#f85149; --unknown:#6e7b8a;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.45;
  background-image:radial-gradient(1200px 500px at 80% -10%,rgba(54,209,196,.06),transparent 60%);}
a{color:inherit}

/* ---- top bar ---- */
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:24px;
  padding:14px 24px;background:rgba(10,14,19,.86);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--line)}
.brand{display:flex;flex-direction:column;line-height:1.1}
.logo{font-family:var(--mono);font-size:18px;font-weight:600;letter-spacing:.5px}
.logo .cur{color:var(--accent);animation:blink 1.1s steps(1) infinite}
.eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.32em;text-transform:uppercase;color:var(--muted)}
.filter{margin-left:auto;width:min(360px,42vw);font-family:var(--mono);font-size:13px;
  color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:8px;
  padding:9px 12px;outline:none;transition:border-color .15s,box-shadow .15s}
.filter::placeholder{color:var(--faint)}
.filter:focus-visible{border-color:var(--accent);box-shadow:0 0 0 3px rgba(54,209,196,.16)}

/* ---- summary ---- */
.summary{display:flex;align-items:center;gap:28px;flex-wrap:wrap;
  padding:18px 24px;border-bottom:1px solid var(--line);background:var(--panel2)}
.stat{display:flex;flex-direction:column;line-height:1}
.stat .num{font-family:var(--mono);font-size:26px;font-weight:600}
.stat .lbl{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-top:4px}
.dist{flex:1;min-width:220px;display:flex;flex-direction:column;gap:8px}
.bar{display:flex;height:9px;border-radius:99px;overflow:hidden;background:var(--panel);border:1px solid var(--line)}
.seg{min-width:3px}
.seg.s-ok{background:var(--ok)} .seg.s-redir{background:var(--redir)}
.seg.s-client{background:var(--client)} .seg.s-server{background:var(--server)} .seg.s-unknown{background:var(--unknown)}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin:0;padding:0;list-style:none;font-size:12px;color:var(--muted)}
.legend li{display:flex;align-items:center;gap:6px}
.legend i{width:8px;height:8px;border-radius:2px;display:inline-block}
.legend b{color:var(--ink);font-family:var(--mono)}
.legend .s-ok i{background:var(--ok)} .legend .s-redir i{background:var(--redir)}
.legend .s-client i{background:var(--client)} .legend .s-server i{background:var(--server)} .legend .s-unknown i{background:var(--unknown)}
.gen{display:flex;flex-direction:column;align-items:flex-end;gap:3px;font-family:var(--mono);font-size:11px;color:var(--muted)}
.gen .count{color:var(--accent)}

/* ---- grid ---- */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:16px;padding:22px 24px 64px}

/* ---- card ---- */
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;
  display:flex;flex-direction:column;transition:transform .14s ease,border-color .14s ease,box-shadow .14s ease}
.card:hover{transform:translateY(-3px);border-color:#2c3c4e;box-shadow:0 14px 32px -18px rgba(0,0,0,.8)}
.card.hidden{display:none}

.chead{display:flex;align-items:center;gap:11px;padding:11px 13px;border-bottom:1px solid var(--line);position:relative}
.chead::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
.s-ok .chead::before{background:var(--ok)} .s-redir .chead::before{background:var(--redir)}
.s-client .chead::before{background:var(--client)} .s-server .chead::before{background:var(--server)} .s-unknown .chead::before{background:var(--unknown)}
.stamp{font-family:var(--mono);font-size:13px;font-weight:700;padding:2px 7px;border-radius:6px;letter-spacing:.5px}
.s-ok .stamp{color:var(--ok);background:rgba(63,185,80,.12)} .s-redir .stamp{color:var(--redir);background:rgba(88,166,255,.12)}
.s-client .stamp{color:var(--client);background:rgba(216,160,23,.14)} .s-server .stamp{color:var(--server);background:rgba(248,81,73,.13)}
.s-unknown .stamp{color:var(--unknown);background:rgba(110,123,138,.14)}
.addr{display:flex;flex-direction:column;min-width:0;flex:1}
.addr .host{font-family:var(--mono);font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.addr .sub{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.open{flex-shrink:0;width:28px;height:28px;display:grid;place-items:center;border-radius:7px;
  color:var(--muted);text-decoration:none;transition:background .14s,color .14s}
.open:hover{background:var(--panel2);color:var(--accent)}

.shot{display:block;width:100%;aspect-ratio:16/10;background:var(--panel2);border:0;padding:0;cursor:zoom-in;overflow:hidden;position:relative}
.shot img{width:100%;height:100%;object-fit:cover;object-position:top center;display:block;transition:transform .3s ease}
.shot:hover img{transform:scale(1.03)}
.shot.noshot{cursor:default;display:grid;place-items:center}
.shot.noshot span{font-family:var(--mono);font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--faint)}
.shot.noshot img{display:none}

.ctitle{margin:0;padding:11px 13px 4px;font-size:13.5px;font-weight:600;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

.meta{margin:0;padding:6px 13px 10px;display:grid;grid-template-columns:1fr 1fr;gap:3px 16px}
.meta div{display:flex;gap:8px;min-width:0}
.meta div.wide{grid-column:1/-1}
.meta dt{flex-shrink:0;width:34px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.meta dd{margin:0;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mono{font-family:var(--mono);font-size:12px}
.trunc{overflow:hidden;text-overflow:ellipsis}

.techs{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:2px 13px 13px;list-style:none}
.chip{font-size:11.5px;padding:3px 8px;border:1px solid var(--line);border-radius:99px;
  background:var(--panel2);color:#c3cedb;display:inline-flex;align-items:center;gap:5px;max-width:100%}
.chip .ver{font-family:var(--mono);font-size:10.5px;color:var(--accent)}

.extra{padding:0 13px 12px;display:flex;flex-direction:column;gap:6px}
details summary{cursor:pointer;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);
  list-style:none;display:flex;align-items:center;gap:7px;user-select:none}
details summary::-webkit-details-marker{display:none}
details summary::before{content:"▸";color:var(--accent);transition:transform .15s}
details[open] summary::before{transform:rotate(90deg)}
details summary .n{margin-left:auto;font-family:var(--mono);background:var(--panel2);border:1px solid var(--line);
  border-radius:99px;padding:0 7px;color:var(--ink)}
.list{margin:7px 0 2px;padding:0 0 0 16px;display:flex;flex-direction:column;gap:2px;
  font-size:11.5px;color:#aeb9c7;max-height:140px;overflow:auto}
.list li{word-break:break-all}

/* ---- lightbox ---- */
.lightbox{position:fixed;inset:0;z-index:60;display:none;place-items:center;padding:32px;
  background:rgba(4,7,10,.86);backdrop-filter:blur(3px);cursor:zoom-out}
.lightbox.open{display:grid}
.lightbox img{max-width:100%;max-height:100%;border-radius:10px;border:1px solid var(--line);
  box-shadow:0 30px 80px -30px #000}
.lb-close{position:absolute;top:18px;right:22px;width:40px;height:40px;display:grid;place-items:center;
  border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:10px;
  font-size:22px;line-height:1;cursor:pointer}
.lb-close:hover{color:var(--accent);border-color:var(--accent)}

@keyframes blink{50%{opacity:0}}
@media (max-width:640px){
  .grid{grid-template-columns:1fr;padding:16px}
  .topbar{flex-wrap:wrap;gap:12px}
  .filter{width:100%;margin-left:0}
}
@media (prefers-reduced-motion:reduce){
  *{animation:none!important;transition:none!important;scroll-behavior:auto}
}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="logo">wappaGo<span class="cur">▌</span></span>
    <span class="eyebrow">attack surface report</span>
  </div>
  <input id="filter" class="filter" type="search" placeholder="filter by host, ip, tech…" aria-label="Filter results" autocomplete="off">
</header>`

const pageFoot = `</main>
<div id="lightbox" class="lightbox" aria-hidden="true">
  <button type="button" class="lb-close" aria-label="Close">&times;</button>
  <img alt="Enlarged screenshot">
</div>
<script>
(function(){
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card'));
  var filter = document.getElementById('filter');
  var count = document.getElementById('count');
  var total = cards.length;
  function update(){
    var q = (filter.value || '').trim().toLowerCase();
    var shown = 0;
    for(var i=0;i<cards.length;i++){
      var hit = !q || cards[i].dataset.search.indexOf(q) !== -1;
      cards[i].classList.toggle('hidden', !hit);
      if(hit) shown++;
    }
    if(count) count.textContent = q ? (shown + ' / ' + total) : (total + ' shown');
  }
  filter.addEventListener('input', update);
  update();

  // Broken screenshots fall back to the placeholder.
  var imgs = document.querySelectorAll('.shot img');
  for(var j=0;j<imgs.length;j++){
    imgs[j].addEventListener('error', function(e){
      var s = e.target.closest('.shot');
      s.classList.add('noshot');
      if(!s.querySelector('span')){ var t=document.createElement('span'); t.textContent='no capture'; s.appendChild(t); }
    });
  }

  // Lightbox via event delegation: one document-level handler so every
  // screenshot is clickable and clicking anywhere else (or the close button)
  // dismisses it.
  var box = document.getElementById('lightbox');
  var boxImg = box.querySelector('img');
  function closeBox(){ box.classList.remove('open'); boxImg.removeAttribute('src'); }
  document.addEventListener('click', function(e){
    var shot = e.target.closest('.shot[data-full]');
    if(shot){ boxImg.src = shot.dataset.full; box.classList.add('open'); return; }
    if(box.classList.contains('open')) closeBox();
  });
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape' && box.classList.contains('open')) closeBox();
  });
})();
</script>
</body>
</html>`
