/* Execute the shipped editor against a bounded DOM test double. No target code runs. */
const fs = require('fs');
const vm = require('vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const workspace = input.workspace;
const events = {};
const downloads = [];
const blobs = new Map();
const escape = value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
class Field {
  constructor(name, value) {
    this.name = name; this.value = value; this.textContent = value; this.attrs = {value}; this.error = '';
    if (name === 'decision') this.options = ['', 'justified', 'disabled', 'note', 'needs_runtime_validation', 'needs_human_review'].map(value => ({
      value, selected: value === this.value,
      setAttribute(key) { if (key === 'selected') this.selected = true; },
      removeAttribute(key) { if (key === 'selected') this.selected = false; }
    }));
  }
  setCustomValidity(value) { this.error = value; }
  reportValidity() { return !this.error; }
  focus() { this.focused = true; }
  setAttribute(key, value) { this.attrs[key] = value; }
  render() {
    if (this.name === 'decision') return '<select data-field="decision">' + this.options.map(option => '<option value="' + option.value + '"' + (option.selected ? ' selected="selected"' : '') + '>' + option.value + '</option>').join('') + '</select>';
    if (this.name === 'reason') return '<textarea data-field="reason">' + escape(this.textContent) + '</textarea>';
    return '<input data-field="' + this.name + '" value="' + escape(this.attrs.value) + '">';
  }
}
class Editor {
  constructor(item) {
    this.dataset = {reviewId: item.id}; this.fields = {};
    for (const key of ['decision', 'reason', 'reviewer', 'reviewed_at', 'evidence_ref']) this.fields[key] = new Field(key, item[key]);
    this.badge = {textContent: item.decision || 'unreviewed'};
    this.details = {open: false, tagName: 'DETAILS', parentElement: null, querySelector: () => this.badge};
    this.parentElement = this.details;
  }
  querySelector(selector) { return this.fields[selector.match(/data-field="([a-z_]+)"/)[1]]; }
  closest() { return this.details; }
  addEventListener(name, callback) { this[name] = callback; }
  render() { return '<details><summary><span class="pill">' + escape(this.badge.textContent) + '</span></summary><fieldset data-review-id="' + escape(this.dataset.reviewId) + '">' + Object.values(this.fields).map(field => field.render()).join('') + '</fieldset></details>'; }
}
const editors = workspace.items.map(item => new Editor(item));
const capsule = {textContent: JSON.stringify(workspace)};
const progress = {textContent: ''};
const status = {textContent: ''};
function cloneDocument() {
  const cloneEditors = workspace.items.map(item => new Editor(item));
  const cloneCapsule = {textContent: capsule.textContent};
  const cloneStatus = {textContent: status.textContent};
  return {
    querySelector(selector) { return selector === '#invarune-review' ? cloneCapsule : cloneStatus; },
    querySelectorAll() { return cloneEditors; },
    get outerHTML() { return '<html><body><p id="original-counts">Original scan snapshot</p>' + cloneEditors.map(editor => editor.render()).join('') + '<p id="review-save-status">' + escape(cloneStatus.textContent) + '</p><script type="application/json" id="invarune-review">' + cloneCapsule.textContent + '</script></body></html>'; }
  };
}
const document = {
  getElementById(id) {
    if (id === 'invarune-review') return capsule;
    if (id === 'review-progress') return progress;
    if (id === 'review-save-status') return status;
    return {addEventListener(name, callback) { events[id + ':' + name] = callback; }};
  },
  querySelectorAll() { return editors; },
  documentElement: {cloneNode: cloneDocument},
  createElement(tag) {
    if (tag !== 'a') throw new Error('Unexpected element creation');
    return {href: '', download: '', remove() {}, click() { const blob = blobs.get(this.href); downloads.push({filename: this.download, content: blob.content, mime: blob.type}); }};
  },
  body: {appendChild() {}}
};
const sandbox = {
  document, Blob: class { constructor(parts, options) { this.content = parts.join(''); this.type = options.type; this.size = Buffer.byteLength(this.content, 'utf8'); } },
  URL: {createObjectURL(blob) { const key = 'blob:review-fixture-' + blobs.size; blobs.set(key, blob); return key; }, revokeObjectURL(key) { blobs.delete(key); }},
  window: {setTimeout(callback) { callback(); }},
  fetch() { throw new Error('Network access forbidden'); },
  XMLHttpRequest() { throw new Error('Network access forbidden'); }
};
vm.runInNewContext(input.script, sandbox, {timeout: 2000});
for (const edit of input.edits || []) {
  const editor = editors.find(item => item.dataset.reviewId === edit.id);
  for (const [field, value] of Object.entries(edit.values)) editor.fields[field].value = value;
  if (editor.input) editor.input();
}
events[(input.format === 'json' ? 'download-review-json' : 'download-reviewed-html') + ':click']();
process.stdout.write(JSON.stringify({downloads, status: status.textContent, progress: progress.textContent,
  validity_errors: editors.flatMap(editor => Object.values(editor.fields).map(field => field.error)).filter(Boolean)}));
