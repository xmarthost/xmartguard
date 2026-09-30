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
  params: { s: string; ip: string; h: string; u: string } | null;
  /** Cloudflare Turnstile site key ('' = not set up). */
  siteKey: string;
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
<p class="status" id="status" role="status" aria-live="polite"><span class="spin"></span>Loading the check…</p>`;
  const script =
    d.error || !d.params
      ? ''
      : `<script>
var P=${JSON.stringify(d.params).replace(/</g, '\\u003c')},st=document.getElementById('status');
function show(t,c){st.className='status'+(c?' '+c:'');st.innerHTML=t}
function done(token){
  show('<span class="spin"></span>Checking…');
  fetch('/v/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({token:token},P))})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(x){
    if(!x.ok){show(x.j.error||'The check failed. Please try again.','err');if(window.turnstile)turnstile.reset();return}
    show('Verified. Taking you back to ${host}…','ok');
    setTimeout(function(){location.replace(x.j.redirect)},${1200});
  }).catch(function(){show('Network error. Please try again.','err');if(window.turnstile)turnstile.reset()});
}
window.onTs=function(){
  show('Please confirm you are not a robot.');
  turnstile.render('#ts',{sitekey:${JSON.stringify(d.siteKey)},callback:done,'error-callback':function(){show('The check could not load. Please reload the page.','err')},'expired-callback':function(){show('The check expired. Please try again.','err')}});
};
</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTs&render=explicit" async defer></script>`;
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
<h1 class="site">${host}</h1>
<p class="by">is protected by <b>xPGuard</b></p>
<p class="ip">Your IP address is <b>${esc(d.visitorIp)}</b></p>
${body}
<noscript><div class="box">Please enable JavaScript to continue.</div></noscript>
<details><summary>Why am I seeing this?</summary>
<p>${host} uses xPGuard to keep attackers away from its login page. Your address was recently seen sending suspicious requests, or it is on a list of addresses used for attacks, so we ask you to confirm that you are a person.</p>
<p>After the check you go straight back to the page you asked for, and this address is not asked again for a while. The check is run by Cloudflare Turnstile; no account or personal details are needed.</p>
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
