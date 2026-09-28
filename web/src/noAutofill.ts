// Browsers fill saved logins into any page that has a password field: the
// field before it gets the saved email and the password field the saved
// password. The portal's settings hold API keys and bot tokens in password
// fields, so every input that does not ask for autofill itself (the login
// page does) is marked as "not a login" for the browser and for password
// managers.
export function markNoAutofill(el: HTMLInputElement | HTMLTextAreaElement): void {
  if (el.hasAttribute('autocomplete')) return;
  const type = el instanceof HTMLInputElement ? el.type : 'textarea';
  if (['checkbox', 'radio', 'button', 'submit', 'range', 'color', 'file', 'hidden'].includes(type)) return;
  el.setAttribute('autocomplete', type === 'password' ? 'new-password' : 'off');
  el.setAttribute('data-1p-ignore', '');
  el.setAttribute('data-lpignore', 'true');
  el.setAttribute('data-bwignore', 'true');
  el.setAttribute('data-form-type', 'other');
}

export function installNoAutofill(root: ParentNode = document): void {
  const scan = (n: ParentNode) => n.querySelectorAll?.('input, textarea').forEach((el) => markNoAutofill(el as HTMLInputElement));
  scan(root);
  new MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((node) => {
        if (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement) markNoAutofill(node);
        else if (node instanceof Element) scan(node);
      });
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
}
