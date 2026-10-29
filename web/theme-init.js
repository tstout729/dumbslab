// Runs before first paint (classic script, not a module) so the page never flashes the wrong theme.
(function () {
  var mq = window.matchMedia('(prefers-color-scheme: dark)');
  function pref() {
    try {
      return localStorage.getItem('ds-theme') || 'system';
    } catch (e) {
      return 'system';
    }
  }
  function apply() {
    var p = pref();
    var dark = p === 'dark' || (p === 'system' && mq.matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.dataset.themePref = p;
  }
  apply();
  if (mq.addEventListener) mq.addEventListener('change', apply);
  else if (mq.addListener) mq.addListener(apply);
  window.__dsApplyTheme = apply;
})();
