/* ============================================================================
 * FileSync 在线编辑器前端
 *  - 代码高亮（CodeMirror，无自动补全）、等宽字体
 *  - 保存 / 暂存 / 提交 commit / 删除到回收站
 *  - 移动端横屏可用（文件列表可折叠）
 * ========================================================================== */

(() => {
  'use strict';

  const CSRF = window.LG_CSRF || '';
  const $ = (id) => document.getElementById(id);

  const state = {
    files: [],
    current: null,       // 当前文件路径
    dirty: false,
    cm: null,            // CodeMirror 实例
  };

  /* ------------------------------ 通用 ------------------------------ */

  async function api(action, opts = {}) {
    const { method = 'GET', params = {}, body = null } = opts;
    const qs = new URLSearchParams({ api: action, ...params });
    const init = { method, headers: { 'X-CSRF': CSRF } };
    if (body !== null) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch('?' + qs.toString(), init);
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error('服务端返回了非 JSON 内容（HTTP ' + res.status + '）');
    }
    if (!data.ok) {
      throw new Error(data.error || ('请求失败（HTTP ' + res.status + '）'));
    }
    return data;
  }

  let toastTimer = null;
  function toast(message, isError = false) {
    const el = $('toast');
    el.textContent = message;
    el.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = 'toast'; }, 3200);
  }

  function setStatus(text) {
    $('status-text').textContent = text;
  }

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  }

  function setDirty(value) {
    state.dirty = value;
    $('dirty-dot').classList.toggle('on', value);
  }

  /* --------------------------- 编辑器初始化 --------------------------- */

  const CM_MODES = {
    html: 'htmlmixed', htm: 'htmlmixed', php: 'application/x-httpd-php',
    js: 'javascript', mjs: 'javascript', css: 'css', json: 'application/json',
    xml: 'xml', svg: 'xml', md: 'markdown', py: 'python',
    c: 'text/x-csrc', h: 'text/x-csrc', cpp: 'text/x-c++src', hpp: 'text/x-c++src',
    java: 'text/x-java', ts: 'text/typescript',
  };

  function modeFor(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    return CM_MODES[ext] || null;
  }

  function initEditor() {
    const textarea = $('editor');
    if (window.CodeMirror) {
      state.cm = CodeMirror.fromTextArea(textarea, {
        lineNumbers: true,
        lineWrapping: false,
        indentUnit: 4,
        tabSize: 4,
        mode: null,
        styleActiveLine: true,
      });
      state.cm.setOption('extraKeys', {
        'Ctrl-S': () => saveFile(),
        'Cmd-S': () => saveFile(),
      });
      state.cm.on('change', () => setDirty(true));
      state.cm.on('cursorActivity', () => {
        const pos = state.cm.getDoc().getCursor();
        $('cursor-pos').textContent = '行 ' + (pos.line + 1) + '，列 ' + (pos.ch + 1);
      });
    } else {
      textarea.addEventListener('input', () => setDirty(true));
      textarea.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
          e.preventDefault();
          saveFile();
        }
      });
    }
  }

  function getValue() {
    return state.cm ? state.cm.getValue() : $('editor').value;
  }

  function setValue(text, mime) {
    if (state.cm) {
      state.cm.setOption('mode', mime);
      state.cm.setValue(text);
      state.cm.clearHistory();
      setTimeout(() => state.cm.refresh(), 30);
    } else {
      $('editor').value = text;
    }
  }

  /* ----------------------------- 文件列表 ----------------------------- */

  async function loadFiles() {
    try {
      const data = await api('list');
      state.files = data.files || [];
      renderFiles();
      setStatus('共 ' + state.files.length + ' 个文件');
    } catch (e) {
      toast(e.message, true);
    }
  }

  function renderFiles() {
    const keyword = ($('filter').value || '').trim().toLowerCase();
    const list = $('file-list');
    list.innerHTML = '';
    let shown = 0;
    for (const file of state.files) {
      if (keyword && !file.path.toLowerCase().includes(keyword)) continue;
      const li = document.createElement('li');
      li.textContent = file.path;
      li.title = file.path;
      li.dataset.path = file.path;
      if (file.path === state.current) li.classList.add('active');
      li.addEventListener('click', () => openFile(file.path));
      list.appendChild(li);
      shown++;
      if (shown >= 800) break;          // 超大站点避免卡顿
    }
  }

  async function openFile(path) {
    if (state.dirty && !confirm('当前文件有未保存的修改，确定切换吗？')) {
      return;
    }
    try {
      const data = await api('read', { params: { path } });
      state.current = path;
      setValue(data.content, modeFor(path));
      setDirty(false);
      $('current-file').textContent = path;
      $('current-file').title = path;
      $('file-size').textContent = fmtSize(data.size);
      $('placeholder').classList.add('hidden');
      renderFiles();
      setStatus('已打开 ' + path);
      closeSidebarOnMobile();
    } catch (e) {
      toast(e.message, true);
    }
  }

  /* ------------------------------- 保存 ------------------------------- */

  async function saveFile() {
    if (!state.current) {
      toast('请先选择一个文件', true);
      return;
    }
    try {
      const data = await api('save', {
        method: 'POST',
        body: { path: state.current, content: getValue() },
      });
      setDirty(false);
      $('file-size').textContent = fmtSize(data.size);
      setStatus('已保存 ' + new Date().toLocaleTimeString());
      toast('已保存 ' + data.path);
      const index = state.files.find((f) => f.path === data.path);
      if (index) index.size = data.size;
    } catch (e) {
      toast(e.message, true);
    }
  }

  /* ------------------------- 暂存 / 提交 / 删除 ------------------------- */

  async function stageCurrent() {
    const body = state.current
      ? { paths: [state.current] }
      : { all: true };
    try {
      const data = await api('stage', { method: 'POST', body });
      toast('已暂存 ' + data.staged + ' 个文件');
      setStatus('暂存区：' + Object.keys(data.index || {}).length + ' 个文件');
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function commitChanges() {
    const message = prompt('提交信息（commit message）：');
    if (message === null) return;
    if (!message.trim()) {
      toast('提交信息不能为空', true);
      return;
    }
    try {
      const data = await api('commit', { method: 'POST', body: { message: message.trim() } });
      const c = data.commit || {};
      const lines = (c.changes || []).map(
        (ch) => ch.path + '  +' + ch.added + ' -' + ch.removed
      );
      toast('提交成功 ' + (c.id || data.head));
      setStatus('提交 ' + (c.id || data.head) + '：' + lines.length + ' 个文件');
      if (lines.length) {
        console.log('提交内容：\n' + lines.join('\n'));
      }
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function deleteCurrent() {
    if (!state.current) {
      toast('请先选择一个文件', true);
      return;
    }
    if (!confirm('把 ' + state.current + ' 移入回收站？\n（可在「回收站」里复原）')) {
      return;
    }
    try {
      const data = await api('delete', { method: 'POST', body: { path: state.current } });
      toast('已移入回收站：' + data.path);
      state.current = null;
      $('current-file').textContent = '未选择文件';
      $('file-size').textContent = '';
      setValue('', null);
      setDirty(false);
      $('placeholder').classList.remove('hidden');
      await loadFiles();
    } catch (e) {
      toast(e.message, true);
    }
  }

  /* ------------------------------ 回收站 ------------------------------ */

  async function openTrash() {
    try {
      const data = await api('trash');
      const list = $('trash-list');
      list.innerHTML = '';
      if (!data.items.length) {
        list.innerHTML = '<li class="muted">回收站是空的</li>';
      }
      for (const item of data.items) {
        const li = document.createElement('li');
        const span = document.createElement('span');
        span.textContent = item.path;
        span.title = item.path;
        const btn = document.createElement('button');
        btn.textContent = '复原';
        btn.addEventListener('click', () => restoreFile(item.path));
        li.appendChild(span);
        li.appendChild(btn);
        list.appendChild(li);
      }
      $('trash-panel').classList.remove('hidden');
    } catch (e) {
      toast(e.message, true);
    }
  }

  async function restoreFile(path) {
    try {
      await api('restore', { method: 'POST', body: { path } });
      toast('已复原 ' + path);
      await openTrash();
      await loadFiles();
    } catch (e) {
      toast(e.message, true);
    }
  }

  /* ------------------------------ 移动端 ------------------------------ */

  function closeSidebarOnMobile() {
    if (window.matchMedia('(max-width: 860px)').matches) {
      $('sidebar').classList.remove('open');
    }
  }

  /* ------------------------------- 绑定 ------------------------------- */

  function bind() {
    $('btn-refresh').addEventListener('click', () => {
      loadFiles();
      toast('文件列表已刷新');
    });
    $('filter').addEventListener('input', renderFiles);
    $('btn-save').addEventListener('click', saveFile);
    $('btn-stage').addEventListener('click', stageCurrent);
    $('btn-commit').addEventListener('click', commitChanges);
    $('btn-delete').addEventListener('click', deleteCurrent);
    $('btn-trash').addEventListener('click', openTrash);
    $('btn-close-trash').addEventListener('click', () => $('trash-panel').classList.add('hidden'));
    $('btn-menu').addEventListener('click', () => $('sidebar').classList.toggle('open'));
    $('btn-logout').addEventListener('click', async () => {
      try {
        await api('logout', { method: 'POST' });
      } catch (e) { /* 忽略 */ }
      location.reload();
    });

    window.addEventListener('beforeunload', (e) => {
      if (state.dirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initEditor();
    bind();
    loadFiles();
  });
})();
