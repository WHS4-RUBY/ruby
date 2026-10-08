const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const path = require('node:path')
const { test } = require('node:test')
const vm = require('node:vm')

const template = readFileSync(path.join(__dirname, '../defense/account_recovery.js'), 'utf8')
const defaultConfig = {
  loginPaths: ['/rest/user/login'], loginFormSelector: '#login-form',
  recoveryAnchorSelector: 'a[href="#/forgot-password"]',
  menuSelector: 'mat-sidenav mat-nav-list'
}

class Element {
  constructor(tag) {
    this.tagName = tag
    this.children = []
    this.style = {}
    this.attributes = {}
    this.parentElement = null
    this.id = ''
    this.href = ''
    this.textContent = ''
  }
  setAttribute(name, value) {
    this.attributes[name] = value
    if (name === 'id') this.id = value
  }
  addEventListener(name, callback) {
    this['on' + name] = callback
  }
  append(...children) {
    for (const child of children) {
      child.parentElement = this
      this.children.push(child)
    }
  }
  appendChild(child) {
    this.append(child)
  }
  prepend(child) {
    child.parentElement = this
    this.children.unshift(child)
  }
  remove() {
    if (this.parentElement) {
      const items = this.parentElement.children
      items.splice(items.indexOf(this), 1)
      this.parentElement = null
    }
  }
  insertAdjacentElement(_, child) {
    const items = this.parentElement.children
    items.splice(items.indexOf(this) + 1, 0, child)
    child.parentElement = this.parentElement
  }
  querySelector(selector) {
    const matches = item =>
      (selector.startsWith('#') && item.id === selector.slice(1)) ||
      (selector.startsWith('a[href=') && item.tagName === 'a' &&
        item.href === selector.slice(8, -2)) ||
      (selector === 'a' && item.tagName === 'a')
    const visit = item => {
      for (const child of item.children) {
        if (matches(child)) return child
        const nested = visit(child)
        if (nested) return nested
      }
      return null
    }
    return visit(this)
  }
}

function createContext({ login = false, recoveryAnchor = true, initialContext = '', config = defaultConfig } = {}) {
  const body = new Element('body')
  const nav = new Element('mat-nav-list')
  body.append(nav)
  let form
  if (login) {
    form = new Element('form')
    form.id = 'login-form'
    if (recoveryAnchor) {
      const forgot = new Element('a')
      forgot.href = config.recoveryAnchorSelector.slice(8, -2)
      form.append(forgot)
    }
    body.append(form)
  }
  const document = {
    body,
    currentScript: { dataset: { deception: initialContext } },
    readyState: 'complete',
    createElement: tag => new Element(tag),
    getElementById: id => {
      if (body.id === id) return body
      const visit = item => {
        for (const child of item.children) {
          if (child.id === id) return child
          const nested = visit(child)
          if (nested) return nested
        }
        return null
      }
      return visit(body)
    },
    querySelector: selector => selector === config.menuSelector ? nav :
      selector === config.loginFormSelector ? form || null : null
  }
  const responses = []
  class FakeXHR {
    constructor() {
      this.reply = responses.shift() || { status: 200, headers: {} }
      this.handlers = {}
    }
    open() {}
    addEventListener(name, callback) { this.handlers[name] = callback }
    getResponseHeader(name) { return this.reply.headers[name] || null }
    send() {
      this.status = this.reply.status
      this.handlers.loadend?.()
    }
  }
  const fetchResponses = []
  const window = {
    location: { href: 'http://lab.local/#/login', origin: 'http://lab.local' },
    fetch: async () => {
      const reply = fetchResponses.shift() || { status: 200, headers: {} }
      return {
        status: reply.status,
        headers: { get: name => reply.headers[name] || null }
      }
    },
    requestAnimationFrame: callback => callback(),
    addEventListener() {}
  }
  const context = { document, window, URL, XMLHttpRequest: FakeXHR,
    MutationObserver: class { observe() {} } }
  vm.runInNewContext(template.replace('__LURE_CONFIG_JSON__', JSON.stringify(config)), context)
  return { context, document, body, form, nav, responses, fetchResponses }
}

test('login page offers recovery before and after a failed attempt', () => {
  const state = createContext({ login: true })
  assert.equal(state.document.getElementById('defense-login-help').href,
    '/ops/recovery/accounts')
  assert.equal(state.document.getElementById('defense-operations-menu').href,
    '/ops/service/manifest')
  assert.equal(state.document.getElementById('defense-context-lure'), null)
  state.responses.push({ status: 401,
    headers: { 'X-Recovery-API': '/ops/recovery/accounts' } })
  const request = new state.context.XMLHttpRequest()
  request.open('POST', '/rest/user/login')
  request.send()
  const card = state.document.getElementById('defense-context-lure')
  assert.equal(card.parentElement, state.form)
  assert.equal(state.form.children[0], card)
  assert.equal(card.querySelector('a').href, '/ops/recovery/accounts')
})

test('recon and API response headers select one visible contextual card', async () => {
  const state = createContext()
  state.fetchResponses.push({ status: 200,
    headers: { 'X-Internal-API': '/ops/service/manifest' } })
  await state.context.window.fetch('/api/metadata')
  assert.equal(state.document.getElementById('defense-context-lure').querySelector('a').href,
    '/ops/service/manifest')
  state.responses.push({ status: 404,
    headers: { 'X-Legacy-Storage': '/ftp' } })
  const request = new state.context.XMLHttpRequest()
  request.open('GET', '/admin')
  request.send()
  assert.equal(state.document.getElementById('defense-context-lure').querySelector('a').href,
    '/ftp')
  assert.equal(state.body.children.filter(item => item.id === 'defense-context-lure').length, 1)
})

test('ordinary responses expose only the menu fallback', async () => {
  const state = createContext()
  state.fetchResponses.push({ status: 200, headers: {} })
  await state.context.window.fetch('/api/Products')
  assert.equal(state.document.getElementById('defense-context-lure'), null)
  assert.equal(state.document.getElementById('defense-operations-menu').href,
    '/ops/service/manifest')
})

test('direct HTML errors can carry an initial scenario', () => {
  const state = createContext({ initialContext: 'legacy' })
  assert.equal(state.document.getElementById('defense-context-lure').querySelector('a').href,
    '/ftp')
})

test('a different site profile changes login path and DOM selectors without changing script', () => {
  const config = { loginPaths: ['/api/auth/login'], loginFormSelector: 'form[data-login]',
    recoveryAnchorSelector: 'a[href="/forgot-password"]', menuSelector: 'nav.main' }
  const state = createContext({ login: true, config })
  assert.equal(state.document.getElementById('defense-login-help').href, '/ops/recovery/accounts')
  state.responses.push({ status: 401, headers: {} })
  const request = new state.context.XMLHttpRequest()
  request.open('POST', '/api/auth/login')
  request.send()
  assert.equal(state.document.getElementById('defense-context-lure').parentElement, state.form)
})

test('RUBY login form without a recovery anchor still offers the signed-Agent lure', () => {
  const config = { loginPaths: ['/api/auth/login'],
    loginFormSelector: '.masthead .session form.inline',
    recoveryAnchorSelector: "a[href='#/account']", menuSelector: 'nav.primary' }
  const state = createContext({ login: true, recoveryAnchor: false, config })
  const help = state.document.getElementById('defense-login-help')
  assert.equal(help.href, '/ops/recovery/accounts')
  assert.equal(help.parentElement, state.form)
  state.responses.push({ status: 401, headers: {} })
  const request = new state.context.XMLHttpRequest()
  request.open('POST', '/api/auth/login')
  request.send()
  assert.equal(state.document.getElementById('defense-context-lure').parentElement, state.form)
})
