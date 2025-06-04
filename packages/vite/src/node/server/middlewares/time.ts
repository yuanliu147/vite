import { performance } from 'node:perf_hooks'
import type { Connect } from 'dep-types/connect'
import { createDebugger, prettifyUrl, timeFrom } from '../../utils'

const logTime = createDebugger('vite:time')

export function timeMiddleware(root: string): Connect.NextHandleFunction {
  // Keep the named function. The name is visible in debug logs via `DEBUG=connect:dispatcher ...`
  // 保留已命名的函数。通过“DEBUG=connect:dispatcher ”,可以在调试日志中看到该名称...`
  return function viteTimeMiddleware(req, res, next) {
    const start = performance.now()
    const end = res.end
    res.end = (...args: readonly [any, any?, any?]) => {
      logTime?.(`${timeFrom(start)} ${prettifyUrl(req.url!, root)}`)
      return end.call(res, ...args)
    }
    next()
  }
}
