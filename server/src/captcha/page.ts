/**
 * The CAPTCHA page suspicious visitors of a website's login page are sent
 * to (captcha.xpguard.org/v). Server-rendered, no framework, mobile first.
 */

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);

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
}

const css = `
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
  font-family:Poppins,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#0f2a55;
  background:#f4f7fb;background-image:radial-gradient(circle at 10% 0%,#e7eefb 0,transparent 45%),radial-gradient(circle at 100% 100%,#fdeee2 0,transparent 40%);padding:24px 16px}
.card{width:100%;max-width:520px;background:#fff;border:1px solid #e3e9f2;border-radius:22px;box-shadow:0 18px 50px -20px rgba(15,42,85,.25);
  padding:34px 28px 26px;text-align:center}
.shield{width:112px;height:112px;margin:0 auto 10px;display:block}
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
<button type="button" class="again" id="again" hidden>Try again</button>`;
  const provider = d.provider ?? 'turnstile';
  const script =
    d.error || !d.params
      ? ''
      : `<script>
var P=${JSON.stringify(d.params).replace(/</g, '\\u003c')},MODE=${JSON.stringify(provider)},KEY=${JSON.stringify(d.siteKey)},st=document.getElementById('status'),ag=document.getElementById('again'),box=document.getElementById('ts'),altcha=null,usingAltcha=false;
function show(t,c){st.className='status'+(c?' '+c:'');st.innerHTML=t}
// After an error the check is not restarted by itself (it would solve again
// and repeat the same error): the visitor chooses to try again.
function fail(t){show(t,'err');ag.hidden=false}
ag.onclick=function(){ag.hidden=true;if(usingAltcha){startAltcha()}else{show('Please confirm you are not a robot.');if(window.turnstile)turnstile.reset()}};
function done(sol){
  show('<span class="spin"></span>Checking…');
  fetch('/v/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({},sol,P))})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(x){
    if(!x.ok){fail(x.j.error||'The check failed. Please try again.');return}
    if(x.j.preview){show('Preview: the check works. A real visitor would now go back to the website.','ok');return}
    show('Verified. Taking you back to ${host}…','ok');
    setTimeout(function(){location.replace(x.j.redirect)},${1200});
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
    show('Please confirm you are not a robot.');
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
</head><body>
<main class="card">
<img class="shield" src="/xpguard-shield.png" alt="">
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
