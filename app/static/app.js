(function () {
  // Tabs: if JavaScript is off, all sections are simply shown one under another.
  var root = document.querySelector("[data-tabs]");
  if (root) {
    root.classList.add("js-tabs");
    var buttons = root.querySelectorAll("[data-tab]");
    var panels = root.querySelectorAll("[data-panel]");
    var show = function (name) {
      buttons.forEach(function (b) { b.setAttribute("aria-selected", b.dataset.tab === name ? "true" : "false"); });
      panels.forEach(function (p) { p.classList.toggle("active", p.dataset.panel === name); });
    };
    buttons.forEach(function (b) { b.addEventListener("click", function () { show(b.dataset.tab); }); });
    show(buttons[0].dataset.tab);
  }

  // Extra confirmation before deleting history.
  var clearForm = document.querySelector("[data-confirm-form]");
  if (clearForm) {
    clearForm.addEventListener("submit", function (e) {
      if (!window.confirm("Delete all local investigation history? This cannot be undone.")) { e.preventDefault(); }
    });
  }

  // Show progress while the investigation runs (it can take up to a minute).
  var form = document.querySelector("[data-investigate-form]");
  if (form) {
    var btn = form.querySelector("button[type=submit]");
    form.addEventListener("submit", function () { btn.disabled = true; btn.textContent = "Investigating..."; });
    window.addEventListener("pageshow", function () { btn.disabled = false; btn.textContent = "Investigate"; });
  }
})();