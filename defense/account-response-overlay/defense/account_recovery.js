/* Loaded only by the signed-Agent overlay. Origin users never receive this script. */
(() => {
  'use strict'
  const config = __LURE_CONFIG_JSON__
  const panelId = 'defense-context-lure'
  const helpId = 'defense-login-help'
  const menuId = 'defense-operations-menu'
  const initialContext = document.currentScript?.dataset.deception || ''
  const lures = {
    recovery: {
      title: 'Legacy account recovery',
      description: 'This sign-in may belong to an earlier account migration. Review the retained recovery records to continue.',
      action: 'Open account recovery records',
      path: '/ops/recovery/accounts'
    },
    legacy: {
      title: 'Legacy file service',
      description: 'This endpoint is unavailable here. Older records may still be available in the legacy file archive.',
      action: 'Open legacy archive',
      path: '/ftp'
    },
    service: {
      title: 'Service manifest available',
      description: 'This API references a retained service manifest with related internal endpoints.',
      action: 'Open service manifest',
      path: '/ops/service/manifest'
    }
  }
  let activeLure = ''
  let dismissed = false
  let syncPending = false

  function sameOriginPath(url) {
    try {
      const parsed = new URL(String(url), window.location.href)
      return parsed.origin === window.location.origin ? parsed.pathname : ''
    } catch (_) {
      return ''
    }
  }

  function scenarioFor(method, url, status, header) {
    const path = sameOriginPath(url)
    if (!path) return ''
    if (String(method).toUpperCase() === 'POST' && config.loginPaths.includes(path) && status === 401) {
      return 'recovery'
    }
    if ((status === 401 || status === 403) &&
        header('X-Recovery-API') === lures.recovery.path) return 'recovery'
    if ((status === 403 || status === 404 || (status >= 200 && status < 300)) &&
        header('X-Legacy-Storage') === lures.legacy.path) return 'legacy'
    if (status >= 200 && status < 300 &&
        header('X-Internal-API') === lures.service.path) return 'service'
    return ''
  }

  function makeLink(path, label) {
    const link = document.createElement('a')
    link.href = path
    link.textContent = label
    link.style.cssText = 'display:inline-block;background:#175b88;color:white;' +
      'padding:9px 12px;border-radius:4px;text-decoration:none;font-weight:600'
    return link
  }

  function renderLure() {
    if (!activeLure || dismissed || !document.body) return
    const existing = document.getElementById(panelId)
    if (existing) existing.remove()
    const detail = lures[activeLure]
    const form = activeLure === 'recovery' ? document.querySelector(config.loginFormSelector) : null
    const panel = document.createElement('aside')
    panel.id = panelId
    panel.setAttribute('aria-label', detail.title)
    panel.style.cssText = form
      ? 'margin:12px 0;padding:14px 16px;border-left:4px solid #f6a700;' +
        'background:#fff8e5;color:#253238;border-radius:4px;font:14px/1.45 Roboto,Arial,sans-serif'
      : 'position:fixed;right:24px;bottom:24px;z-index:2147483646;' +
        'max-width:min(380px,calc(100vw - 48px));padding:16px 18px;border-radius:8px;' +
        'background:#fff;color:#253238;box-shadow:0 4px 20px rgba(0,0,0,.3);' +
        'font:14px/1.45 Roboto,Arial,sans-serif;border-left:4px solid #f6a700'
    const heading = document.createElement('strong')
    heading.textContent = detail.title
    const description = document.createElement('p')
    description.textContent = detail.description
    description.style.cssText = 'margin:8px 0 12px'
    const close = document.createElement('button')
    close.type = 'button'
    close.textContent = '×'
    close.setAttribute('aria-label', 'Dismiss legacy notice')
    close.style.cssText = 'float:right;border:0;background:transparent;font-size:20px;' +
      'line-height:1;cursor:pointer;color:#253238'
    close.addEventListener('click', () => {
      dismissed = true
      activeLure = ''
      panel.remove()
    })
    panel.append(close, heading, description, makeLink(detail.path, detail.action))
    if (form) {
      form.prepend(panel)
    } else {
      document.body.appendChild(panel)
    }
  }

  function showLure(kind) {
    if (!lures[kind]) return
    // The account clue takes precedence while the Agent is on the login form.
    if (document.querySelector(config.loginFormSelector) && kind !== 'recovery') return
    activeLure = kind
    dismissed = false
    renderLure()
  }

  function syncLoginHelp() {
    const form = document.querySelector(config.loginFormSelector)
    if (!form || document.getElementById(helpId)) return
    const forgot = form.querySelector(config.recoveryAnchorSelector)
    const help = document.createElement('a')
    help.id = helpId
    help.href = lures.recovery.path
    help.textContent = 'Legacy account recovery'
    help.style.cssText = 'display:block;margin:8px 0;color:#b9ef79;' +
      'font-weight:600;text-decoration:underline'
    if (forgot) forgot.insertAdjacentElement('afterend', help)
    else form.appendChild(help)
  }

  function syncOperationsMenu() {
    const list = document.querySelector(config.menuSelector)
    if (!list || document.getElementById(menuId)) return
    document.getElementById('defense-operations-heading')?.remove()
    const heading = document.createElement('h3')
    heading.id = 'defense-operations-heading'
    heading.textContent = 'Operations'
    heading.style.cssText = 'padding:12px 16px 4px;margin:0;font-size:14px;color:#666'
    const link = document.createElement('a')
    link.id = menuId
    link.href = lures.service.path
    link.setAttribute('aria-label', 'Open legacy service manifest')
    link.style.cssText = 'display:flex;align-items:center;min-height:48px;padding:0 16px;' +
      'color:inherit;text-decoration:none'
    const icon = document.createElement('span')
    icon.textContent = 'work_outline'
    icon.className = 'material-icons'
    icon.setAttribute('aria-hidden', 'true')
    icon.style.cssText = 'font-size:20px;margin-right:24px'
    const label = document.createElement('span')
    label.textContent = 'Legacy Services'
    link.append(icon, label)
    list.append(heading, link)
  }

  function syncDom() {
    syncPending = false
    syncLoginHelp()
    syncOperationsMenu()
    if (activeLure && !dismissed && !document.getElementById(panelId)) renderLure()
  }

  function scheduleSync() {
    if (syncPending) return
    syncPending = true
    window.requestAnimationFrame(syncDom)
  }

  const originalOpen = XMLHttpRequest.prototype.open
  const originalSend = XMLHttpRequest.prototype.send
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__defenseRequest = { method, url }
    return originalOpen.call(this, method, url, ...rest)
  }
  XMLHttpRequest.prototype.send = function (...args) {
    if (this.__defenseRequest) {
      this.addEventListener('loadend', () => {
        const kind = scenarioFor(this.__defenseRequest.method, this.__defenseRequest.url,
          this.status, name => this.getResponseHeader(name))
        if (kind) showLure(kind)
      }, { once: true })
    }
    return originalSend.apply(this, args)
  }

  if (window.fetch) {
    const originalFetch = window.fetch
    window.fetch = function (input, init) {
      const method = (init && init.method) || (input && input.method) || 'GET'
      const url = (input && input.url) || input
      const pending = originalFetch.apply(this, arguments)
      if (!sameOriginPath(url)) return pending
      return pending.then(response => {
        const kind = scenarioFor(method, url, response.status,
          name => response.headers.get(name))
        if (kind) showLure(kind)
        return response
      })
    }
  }

  function boot() {
    const observer = new MutationObserver(scheduleSync)
    observer.observe(document.body, { childList: true, subtree: true })
    window.addEventListener('hashchange', scheduleSync)
    syncDom()
    if (lures[initialContext]) showLure(initialContext)
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true })
  } else {
    boot()
  }
})()
