/**
 * The CAPTCHA page suspicious visitors of a website's login page are sent
 * to (captcha.xpguard.org/v). Server-rendered, no framework, mobile first.
 */

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);

/** The page's looks, chosen in the portal (Overview » CAPTCHA Page). */
export const CAPTCHA_DESIGNS = ['classic', 'minimal', 'midnight'] as const;
export type CaptchaDesign = (typeof CAPTCHA_DESIGNS)[number];

export interface PageData {
  /** Website the visitor wanted (shown and returned to). */
  host: string;
  /** Address the visitor is seen with here. */
  visitorIp: string;
  /** Request parameters, sent back with the solved check. */
  params: { s: string; ip: string; h: string; u: string; preview?: boolean } | null;
  /** Cloudflare Turnstile site key ('' = not set up). */
  siteKey: string;
  /** The check: Turnstile, ALTCHA, or Turnstile with ALTCHA when it cannot load. */
  provider?: 'turnstile' | 'altcha' | 'auto';
  /** Error shown instead of the check. */
  error?: string;
  /** Look of the page (classic when not set). */
  design?: CaptchaDesign;
  /** Seconds counted down before the visitor is sent back (0: at once). */
  countdown?: number;
}

/**
 * The animated badge: the xPGuard shield in a turning ring with orbiting
 * dots while the check runs; the ring turns green with a tick once verified.
 */
const badge = `<div class="badge" id="badge" aria-hidden="true">
<svg class="ring" viewBox="0 0 120 120"><defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="var(--a1)"/><stop offset="1" stop-color="var(--a2)"/></linearGradient></defs>
<circle cx="60" cy="60" r="54" fill="none" stroke="var(--track)" stroke-width="6"/>
<circle class="arc" cx="60" cy="60" r="54" fill="none" stroke="url(#rg)" stroke-width="6" stroke-linecap="round" stroke-dasharray="110 230"/></svg>
<div class="orbit"><i></i><i></i><i></i></div>
<img class="shield" src="/xpguard-shield.png" alt="">
<svg class="tick" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24"/><path d="M15 27l7 7 15-16"/></svg>
</div>`;

const css = `
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
  font-family:Poppins,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#0f2a55;
  background:#f4f7fb;background-image:radial-gradient(circle at 10% 0%,#e7eefb 0,transparent 45%),radial-gradient(circle at 100% 100%,#fdeee2 0,transparent 40%);padding:24px 16px}
.card{width:100%;max-width:520px;background:#fff;border:1px solid #e3e9f2;border-radius:22px;box-shadow:0 18px 50px -20px rgba(15,42,85,.25);
  padding:34px 28px 26px;text-align:center}
.shield{width:112px;height:112px;margin:0 auto 10px;display:block}
:root{--a1:#1d4f96;--a2:#f06a1d;--track:#e8eef7;--ok:#16a34a}
.badge{position:relative;width:132px;height:132px;margin:0 auto 12px}
.badge .ring{position:absolute;inset:0;width:100%;height:100%;animation:s 1.6s linear infinite}
.badge .shield{position:absolute;inset:22px;width:88px;height:88px;margin:0;animation:pulse 2.4s ease-in-out infinite}
.badge .orbit{position:absolute;inset:0;animation:s 3.2s linear infinite reverse}
.badge .orbit i{position:absolute;left:50%;top:-1px;width:10px;height:10px;margin-left:-5px;border-radius:50%;background:var(--a2);box-shadow:0 0 10px var(--a2)}
.badge .orbit i:nth-child(2){transform:rotate(120deg);transform-origin:5px 67px;background:var(--a1);box-shadow:0 0 10px var(--a1)}
.badge .orbit i:nth-child(3){transform:rotate(240deg);transform-origin:5px 67px;background:#22c3a6;box-shadow:0 0 10px #22c3a6}
.badge .tick{position:absolute;right:2px;bottom:6px;width:38px;height:38px;opacity:0;transform:scale(.4);transition:all .45s cubic-bezier(.2,1.6,.4,1)}
.badge .tick circle{fill:var(--ok)}.badge .tick path{fill:none;stroke:#fff;stroke-width:5;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:40;stroke-dashoffset:40;transition:stroke-dashoffset .5s .25s}
.badge.done .ring{animation:none}.badge.done .arc{stroke:var(--ok);stroke-dasharray:340 0;transition:stroke-dasharray .6s}
.badge.done .orbit{display:none}.badge.done .shield{animation:none}
.badge.done .tick{opacity:1;transform:scale(1)}.badge.done .tick path{stroke-dashoffset:0}
.badge.err .ring{animation-duration:4s}.badge.err .arc{stroke:#dc2626}
.badge.idle .ring,.badge.idle .shield{animation:none}.badge.idle .orbit{display:none}.badge.idle .arc{stroke-dasharray:340 0}
@keyframes pulse{50%{transform:scale(.94)}}
@media (prefers-reduced-motion:reduce){.badge .ring,.badge .orbit,.badge .shield{animation:none}}
.count{margin:14px auto 0;max-width:340px}
.count p{margin:0 0 8px;font-size:16px;font-weight:600}
.count .nw{white-space:nowrap}.count .n{display:inline-block;min-width:1.1em;font-size:22px;font-weight:800;color:var(--a2);text-align:center}
.bar{height:6px;border-radius:9px;background:var(--track);overflow:hidden}
.bar span{display:block;height:100%;width:100%;background:linear-gradient(90deg,var(--a1),var(--a2));transition:width 1s linear}
.count a{display:inline-block;margin-top:10px;font-size:14px;color:var(--a1);font-weight:600}
.elapsed{font-size:12px;color:#7b8aa3;margin-top:6px}
/* Minimal: no card, the badge beside the text on wide screens. */
body.d-minimal{background:#fbfcfe;background-image:none}
.d-minimal .card{max-width:760px;background:transparent;border:0;box-shadow:none;display:grid;grid-template-columns:170px 1fr;gap:6px 34px;text-align:left;align-items:start}
.d-minimal .badge{grid-row:span 9;margin:6px 0 0;width:150px;height:150px}.d-minimal .badge .shield{inset:26px;width:98px;height:98px}
.d-minimal .site{text-transform:none;font-size:clamp(20px,4.6vw,28px);letter-spacing:0}
.d-minimal .widget{justify-content:flex-start}.d-minimal .count{margin-left:0}.d-minimal .foot{justify-content:flex-start;grid-column:1/-1}
.d-minimal summary{text-align:left}
.d-minimal details,.d-minimal .label,.d-minimal .status,.d-minimal .ip,.d-minimal .by,.d-minimal .preview{grid-column:2}
@media (max-width:600px){.d-minimal .card{grid-template-columns:1fr;text-align:center}.d-minimal .badge{grid-row:auto;margin:0 auto 10px}.d-minimal .card>*{grid-column:1!important}.d-minimal .widget{justify-content:center}.d-minimal .count{margin:14px auto 0}.d-minimal .foot{justify-content:center}}
/* Midnight: dark, glassy card. */
body.d-midnight{color:#e6edf8;background:#0b1424;background-image:radial-gradient(circle at 15% 10%,#1b3a6b 0,transparent 45%),radial-gradient(circle at 90% 90%,#4a2a14 0,transparent 40%)}
.d-midnight{--a1:#5b9bff;--a2:#ff8a3d;--track:#22324d;--ok:#22c55e}
.d-midnight .card{background:rgba(17,28,48,.78);border-color:#25395c;box-shadow:0 24px 60px -20px rgba(0,0,0,.6);backdrop-filter:blur(8px)}
.d-midnight .site{color:#f1f5ff}.d-midnight .by{color:#a9c3ee}.d-midnight .ip{background:#13223b;border-color:#25395c;color:#b9c8e2}.d-midnight .ip b{color:#fff}
.d-midnight .label,.d-midnight details{color:#9fb0cc}.d-midnight summary,.d-midnight .status{color:#a9c3ee}
.d-midnight .foot{border-color:#22324d;color:#8798b6}.d-midnight .box{background:#2a1714;border-color:#5c2a20;color:#ffb4a3}
.d-midnight .status.ok{color:#4ade80}.d-midnight .status.err{color:#f87171}
.d-midnight .again{background:#13223b;border-color:#2c446c;color:#cfe0ff}.d-midnight .elapsed{color:#7f90ae}
.d-midnight .foot img{filter:brightness(0) invert(1);opacity:.85}
.site{font-size:clamp(22px,6vw,34px);font-weight:800;letter-spacing:.5px;text-transform:uppercase;margin:6px 0 4px;word-break:break-word;color:#123a78}
.by{font-size:17px;font-weight:600;margin:0 0 14px;color:#1d4f96}
.by b{color:#f06a1d}
.ip{display:inline-block;font-size:15px;background:#f1f5fb;border:1px solid #e1e8f3;border-radius:999px;padding:7px 16px;margin:4px 0 22px;color:#334a6b}
.ip b{color:#0f2a55;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.label{font-size:12px;font-weight:700;letter-spacing:1.4px;color:#5a6b85;margin:0 0 10px;text-transform:uppercase}
.widget{min-height:70px;display:flex;justify-content:center;align-items:center}
.status{min-height:24px;margin:16px 0 0;font-size:15px;font-weight:600;color:#1d4f96}
.status.err{color:#c0392b}.status.ok{color:#15803d}
.again{margin-top:12px;border:1px solid #c9d6ea;background:#fff;color:#1d4f96;font:600 14px inherit;font-family:inherit;border-radius:10px;padding:9px 18px;cursor:pointer}
.again:hover{background:#f1f5fb}
.preview{background:#fff7e6;border:1px solid #f6d9a8;color:#8a5a00;border-radius:12px;padding:10px 14px;font-size:14px;margin:0 0 16px}
.widget altcha-widget{width:100%;max-width:300px;--altcha-max-width:300px}
.spin{display:inline-block;width:16px;height:16px;border:2px solid #cfd9ea;border-top-color:#1d4f96;border-radius:50%;animation:s 1s linear infinite;vertical-align:-3px;margin-right:8px}
@keyframes s{to{transform:rotate(360deg)}}
.box{background:#fff5f2;border:1px solid #f6d3c8;border-radius:14px;padding:14px 16px;color:#8a2d14;font-size:15px;line-height:1.5}
.foot{margin-top:24px;padding-top:16px;border-top:1px solid #edf1f7;display:flex;flex-wrap:wrap;gap:10px 18px;justify-content:center;align-items:center;font-size:13px;color:#7b8aa3}
.foot img{height:18px;vertical-align:middle;margin-left:4px}
details{margin-top:14px;text-align:left;font-size:14px;line-height:1.55;color:#4b5b74}
summary{cursor:pointer;text-align:center;color:#1d4f96;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
details p{margin:10px 0 0}
@media (max-width:480px){.card{padding:26px 18px 20px;border-radius:18px}.shield{width:92px;height:92px}}
`;

export function renderPage(d: PageData): string {
  const host = esc(d.host || 'this website');
  const body = d.error
    ? `<div class="box">${esc(d.error)}</div>`
    : `<p class="label">Human verification</p>
<div class="widget"><div id="ts"></div></div>
<p class="status" id="status" role="status" aria-live="polite"><span class="spin"></span>Loading the check…</p>
<p class="elapsed" id="elapsed"></p>
<div class="count" id="count" hidden></div>
<button type="button" class="again" id="again" hidden>Try again</button>`;
  const wait = Math.max(0, Math.min(15, d.countdown ?? 5));
  const provider = d.provider ?? 'turnstile';
  const script =
    d.error || !d.params
      ? ''
      : `<script>
var P=${JSON.stringify(d.params).replace(/</g, '\\u003c')},WAIT=${wait},HOST=${JSON.stringify(host)},bd=document.getElementById('badge'),el=document.getElementById('elapsed'),cn=document.getElementById('count'),t0=Date.now(),tick=setInterval(function(){var n=Math.floor((Date.now()-t0)/1000);el.textContent=n>0?'Checking for '+n+' second'+(n===1?'':'s'):''},1000),MODE=${JSON.stringify(provider)},KEY=${JSON.stringify(d.siteKey)},st=document.getElementById('status'),ag=document.getElementById('again'),box=document.getElementById('ts'),altcha=null,usingAltcha=false;
function show(t,c){st.className='status'+(c?' '+c:'');st.innerHTML=t}
// After an error the check is not restarted by itself (it would solve again
// and repeat the same error): the visitor chooses to try again.
function fail(t){show(t,'err');ag.hidden=false;bd.className='badge err'}
function stopClock(){clearInterval(tick);el.textContent=''}
// Verified: the badge turns green and the seconds count down to the return.
function back(url){
  stopClock();bd.className='badge done';
  if(WAIT<=0){show('Verified. Taking you back to '+HOST+'…','ok');location.replace(url);return}
  show('Verified: you are human.','ok');
  var left=WAIT;cn.hidden=false;
  cn.innerHTML='<p>You will be taken back to <b>'+HOST+'</b> in <span class="nw"><span class="n" id="n">'+left+'</span> second'+(left===1?'':'s')+'</span></p><div class="bar"><span id="bar"></span></div><a href="#" id="go">Go now</a>';
  var nEl=document.getElementById('n'),bar=document.getElementById('bar');
  document.getElementById('go').onclick=function(e){e.preventDefault();location.replace(url)};
  requestAnimationFrame(function(){bar.style.width=((left-1)/WAIT*100)+'%'});
  var iv=setInterval(function(){left--;nEl.textContent=Math.max(left,0);bar.style.width=(Math.max(left-1,0)/WAIT*100)+'%';
    if(left<=0){clearInterval(iv);location.replace(url)}},1000);
}
ag.onclick=function(){ag.hidden=true;bd.className='badge';if(usingAltcha){startAltcha()}else{show('Please confirm you are not a robot.');if(window.turnstile)turnstile.reset()}};
function done(sol){
  show('<span class="spin"></span>Checking…');
  fetch('/v/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({},sol,P))})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(x){
    if(!x.ok){fail(x.j.error||'The check failed. Please try again.');return}
    if(x.j.preview){stopClock();bd.className='badge done';show('Preview: the check works. A real visitor would now count down and go back to the website.','ok');
      if(WAIT>0){cn.hidden=false;cn.innerHTML='<p>You will be taken back to <b>'+HOST+'</b> in <span class="nw"><span class="n">'+WAIT+'</span> seconds</span></p><div class="bar"><span></span></div>'}return}
    back(x.j.redirect);
  }).catch(function(){fail('Network error. Please try again.')});
}
// ALTCHA: the browser solves a small puzzle by itself (no third party).
function startAltcha(){
  usingAltcha=true;ag.hidden=true;
  show('<span class="spin"></span>Checking your browser…');
  var go=function(){
    box.innerHTML='';
    altcha=document.createElement('altcha-widget');
    altcha.setAttribute('challenge','/v/altcha/challenge');
    altcha.setAttribute('auto','onload');
    altcha.setAttribute('configuration',JSON.stringify({hideFooter:true,hideLogo:true,minDuration:600}));
    altcha.addEventListener('verified',function(e){done({altcha:e.detail.payload})});
    altcha.addEventListener('statechange',function(e){if(e.detail&&e.detail.state==='error')fail('The check could not finish. Please try again.')});
    box.appendChild(altcha);
  };
  if(customElements.get('altcha-widget')){go();return}
  var s=document.createElement('script');s.type='module';s.src='/v/altcha.js';
  s.onload=go;s.onerror=function(){fail('The check could not load. Please reload the page.')};
  document.head.appendChild(s);
}
// Turnstile; in auto mode ALTCHA takes over when it cannot load or run.
function startTurnstile(){
  var started=false;
  window.onTs=function(){
    started=true;
    show('Please confirm you are not a robot.');stopClock();
    turnstile.render('#ts',{sitekey:KEY,callback:function(t){done({token:t})},
      'error-callback':function(){if(MODE==='auto'&&!usingAltcha){startAltcha();return true}show('The check could not load. Please reload the page.','err')},
      'expired-callback':function(){show('The check expired. Please try again.','err')}});
  };
  var s=document.createElement('script');s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTs&render=explicit';s.async=true;
  s.onerror=function(){if(MODE==='auto')startAltcha();else show('The check could not load. Please reload the page.','err')};
  document.head.appendChild(s);
  if(MODE==='auto')setTimeout(function(){if(!started&&!usingAltcha)startAltcha()},8000);
}
if(MODE==='altcha')startAltcha();else startTurnstile();
</script>`;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer">
<title>Human verification · ${host}</title>
<link rel="icon" type="image/png" href="/favicon-32.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>${css}</style>
</head><body class="d-${d.design ?? 'classic'}">
<main class="card">
${d.error ? badge.replace('class="badge"', 'class="badge idle"') : badge}
${d.params?.preview ? '<p class="preview">Preview of the page visitors see. Solving it here only tests the check; no website is changed.</p>' : ''}
<h1 class="site">${host}</h1>
<p class="by">is protected by <b>xPGuard</b></p>
<p class="ip">Your IP address is <b>${esc(d.visitorIp)}</b></p>
${body}
<noscript><div class="box">Please enable JavaScript to continue.</div></noscript>
<details><summary>Why am I seeing this?</summary>
<p>${host} uses xPGuard to keep attackers away. Your address was recently seen sending suspicious requests, or it is on a list of addresses used for attacks, or this page is only open to people, so we ask you to confirm that you are a person.</p>
<p>After the check you go straight back to the page you asked for, and this address is not asked again for a while. ${provider === 'altcha' ? 'Your browser solves a small puzzle by itself' : 'The check is run by Cloudflare Turnstile'}; no account or personal details are needed.</p>
</details>
<div class="foot"><span>Powered by <img src="/xpguard-wordmark.png" alt="xPGuard"></span></div>
</main>
${script}
</body></html>`;
}

/** Plain page for the CAPTCHA host's front page. */
export function renderInfo(): string {
  return renderPage({ host: 'xPGuard', visitorIp: '', params: null, siteKey: '', error: 'This is the xPGuard verification service. You are sent here by a website when a check is needed.' }).replace(
    /<p class="ip">[\s\S]*?<\/p>/,
    '',
  );
}
