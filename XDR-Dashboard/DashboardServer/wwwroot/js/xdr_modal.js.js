// wwwroot/js/xdr-modal.js
window.xdrModal = {
  show: function (id) {
    const el = document.getElementById(id);
    if (!el) return;

    // Bootstrap 5
    const m = bootstrap.Modal.getOrCreateInstance(el, { backdrop: true, keyboard: true, focus: true });
    m.show();
  },
  hide: function (id) {
    const el = document.getElementById(id);
    if (!el) return;

    const m = bootstrap.Modal.getOrCreateInstance(el);
    m.hide();
  }
};
