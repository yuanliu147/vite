import path from 'node:path'
import { execSync } from 'node:child_process'
import type * as net from 'node:net'
import { get as httpGet } from 'node:http'
import { get as httpsGet } from 'node:https'
import type * as http from 'node:http'
import { performance } from 'node:perf_hooks'
import type { Http2SecureServer } from 'node:http2'
import connect from 'connect'
import corsMiddleware from 'cors'
import colors from 'picocolors'
import chokidar from 'chokidar'
import type { FSWatcher, WatchOptions } from 'dep-types/chokidar'
import type { Connect } from 'dep-types/connect'
import launchEditorMiddleware from 'launch-editor-middleware'
import type { SourceMap } from 'rollup'
import type { ModuleRunner } from 'vite/module-runner'
import type { CommonServerOptions } from '../http'
import {
  httpServerStart,
  resolveHttpServer,
  resolveHttpsConfig,
  setClientErrorHandler,
} from '../http'
import type { InlineConfig, ResolvedConfig } from '../config'
import { isResolvedConfig, resolveConfig } from '../config'
import {
  diffDnsOrderChange,
  getServerUrlByHost,
  isInNodeModules,
  isObject,
  isParentDirectory,
  mergeConfig,
  mergeWithDefaults,
  normalizePath,
  resolveHostname,
  resolveServerUrls,
  setupSIGTERMListener,
  teardownSIGTERMListener,
} from '../utils'
import { ssrLoadModule } from '../ssr/ssrModuleLoader'
import { ssrFixStacktrace, ssrRewriteStacktrace } from '../ssr/ssrStacktrace'
import { ssrTransform } from '../ssr/ssrTransform'
import { reloadOnTsconfigChange } from '../plugins/esbuild'
import { bindCLIShortcuts } from '../shortcuts'
import type { BindCLIShortcutsOptions } from '../shortcuts'
import { ERR_OUTDATED_OPTIMIZED_DEP } from '../../shared/constants'
import {
  CLIENT_DIR,
  DEFAULT_DEV_PORT,
  defaultAllowedOrigins,
} from '../constants'
import type { Logger } from '../logger'
import { printServerUrls } from '../logger'
import { warnFutureDeprecation } from '../deprecations'
import {
  createNoopWatcher,
  getResolvedOutDirs,
  resolveChokidarOptions,
  resolveEmptyOutDir,
} from '../watch'
import { initPublicFiles } from '../publicDir'
import { getEnvFilesForMode } from '../env'
import type { RequiredExceptFor } from '../typeUtils'
import type { MinimalPluginContextWithoutEnvironment } from '../plugin'
import type { PluginContainer } from './pluginContainer'
import {
  BasicMinimalPluginContext,
  ERR_CLOSED_SERVER,
  basePluginContextMeta,
  createPluginContainer,
} from './pluginContainer'
import type { WebSocketServer } from './ws'
import { createWebSocketServer } from './ws'
import { baseMiddleware } from './middlewares/base'
import { proxyMiddleware } from './middlewares/proxy'
import { htmlFallbackMiddleware } from './middlewares/htmlFallback'
import {
  cachedTransformMiddleware,
  transformMiddleware,
} from './middlewares/transform'
import {
  createDevHtmlTransformFn,
  indexHtmlMiddleware,
} from './middlewares/indexHtml'
import {
  servePublicMiddleware,
  serveRawFsMiddleware,
  serveStaticMiddleware,
} from './middlewares/static'
import { timeMiddleware } from './middlewares/time'
import { ModuleGraph } from './mixedModuleGraph'
import type { ModuleNode } from './mixedModuleGraph'
import { notFoundMiddleware } from './middlewares/notFound'
import { buildErrorMessage, errorMiddleware } from './middlewares/error'
import type { HmrOptions, NormalizedHotChannel } from './hmr'
import { handleHMRUpdate, updateModules } from './hmr'
import { openBrowser as _openBrowser } from './openBrowser'
import type { TransformOptions, TransformResult } from './transformRequest'
import { transformRequest } from './transformRequest'
import { searchForPackageRoot, searchForWorkspaceRoot } from './searchRoot'
import type { DevEnvironment } from './environment'
import { hostValidationMiddleware } from './middlewares/hostCheck'
import { rejectInvalidRequestMiddleware } from './middlewares/rejectInvalidRequest'

const usedConfigs = new WeakSet<ResolvedConfig>()

export interface ServerOptions extends CommonServerOptions {
  /**
   * Configure HMR-specific options (port, host, path & protocol)
   */
  hmr?: HmrOptions | boolean
  /**
   * Do not start the websocket connection.
   * @experimental
   */
  ws?: false
  /**
   * Warm-up files to transform and cache the results in advance. This improves the
   * initial page load during server starts and prevents transform waterfalls.
   */
  warmup?: {
    /**
     * The files to be transformed and used on the client-side. Supports glob patterns.
     */
    clientFiles?: string[]
    /**
     * The files to be transformed and used in SSR. Supports glob patterns.
     */
    ssrFiles?: string[]
  }
  /**
   * chokidar watch options or null to disable FS watching
   * https://github.com/paulmillr/chokidar/tree/3.6.0#api
   */
  watch?: WatchOptions | null
  /**
   * Create Vite dev server to be used as a middleware in an existing server
   * @default false
   */
  middlewareMode?:
    | boolean
    | {
        /**
         * Parent server instance to attach to
         *
         * This is needed to proxy WebSocket connections to the parent server.
         */
        server: HttpServer
      }
  /**
   * Options for files served via '/\@fs/'.
   */
  fs?: FileSystemServeOptions
  /**
   * Origin for the generated asset URLs.
   *
   * @example `http://127.0.0.1:8080`
   */
  origin?: string
  /**
   * Pre-transform known direct imports
   * @default true
   */
  preTransformRequests?: boolean
  /**
   * Whether or not to ignore-list source files in the dev server sourcemap, used to populate
   * the [`x_google_ignoreList` source map extension](https://developer.chrome.com/blog/devtools-better-angular-debugging/#the-x_google_ignorelist-source-map-extension).
   *
   * By default, it excludes all paths containing `node_modules`. You can pass `false` to
   * disable this behavior, or, for full control, a function that takes the source path and
   * sourcemap path and returns whether to ignore the source path.
   */
  sourcemapIgnoreList?:
    | false
    | ((sourcePath: string, sourcemapPath: string) => boolean)
  /**
   * Backward compatibility. The buildStart and buildEnd hooks were called only once for all
   * environments. This option enables per-environment buildStart and buildEnd hooks.
   * @default false
   * @experimental
   */
  perEnvironmentStartEndDuringDev?: boolean
  /**
   * Run HMR tasks, by default the HMR propagation is done in parallel for all environments
   * @experimental
   */
  hotUpdateEnvironments?: (
    server: ViteDevServer,
    hmr: (environment: DevEnvironment) => Promise<void>,
  ) => Promise<void>
}

export interface ResolvedServerOptions
  extends Omit<
    RequiredExceptFor<
      ServerOptions,
      | 'host'
      | 'https'
      | 'proxy'
      | 'hmr'
      | 'ws'
      | 'watch'
      | 'origin'
      | 'hotUpdateEnvironments'
    >,
    'fs' | 'middlewareMode' | 'sourcemapIgnoreList'
  > {
  fs: Required<FileSystemServeOptions>
  middlewareMode: NonNullable<ServerOptions['middlewareMode']>
  sourcemapIgnoreList: Exclude<
    ServerOptions['sourcemapIgnoreList'],
    false | undefined
  >
}

export interface FileSystemServeOptions {
  /**
   * Strictly restrict file accessing outside of allowing paths.
   *
   * Set to `false` to disable the warning
   *
   * @default true
   */
  strict?: boolean

  /**
   * Restrict accessing files outside the allowed directories.
   *
   * Accepts absolute path or a path relative to project root.
   * Will try to search up for workspace root by default.
   */
  allow?: string[]

  /**
   * Restrict accessing files that matches the patterns.
   *
   * This will have higher priority than `allow`.
   * picomatch patterns are supported.
   *
   * @default ['.env', '.env.*', '*.{crt,pem}', '**\/.git/**']
   */
  deny?: string[]
}

export type ServerHook = (
  this: MinimalPluginContextWithoutEnvironment,
  server: ViteDevServer,
) => (() => void) | void | Promise<(() => void) | void>

export type HttpServer = http.Server | Http2SecureServer

export interface ViteDevServer {
  /**
   * The resolved vite config object
   */
  config: ResolvedConfig
  /**
   * A connect app instance.
   * - Can be used to attach custom middlewares to the dev server.
   * - Can also be used as the handler function of a custom http server
   *   or as a middleware in any connect-style Node.js frameworks
   *
   * https://github.com/senchalabs/connect#use-middleware
   */
  middlewares: Connect.Server
  /**
   * native Node http server instance
   * will be null in middleware mode
   */
  httpServer: HttpServer | null
  /**
   * Chokidar watcher instance. If `config.server.watch` is set to `null`,
   * it will not watch any files and calling `add` or `unwatch` will have no effect.
   * https://github.com/paulmillr/chokidar/tree/3.6.0#api
   */
  watcher: FSWatcher
  /**
   * web socket server with `send(payload)` method
   */
  ws: WebSocketServer
  /**
   * An alias to `server.environments.client.hot`.
   * If you want to interact with all environments, loop over `server.environments`.
   */
  hot: NormalizedHotChannel
  /**
   * Rollup plugin container that can run plugin hooks on a given file
   */
  pluginContainer: PluginContainer
  /**
   * Module execution environments attached to the Vite server.
   */
  environments: Record<'client' | 'ssr' | (string & {}), DevEnvironment>
  /**
   * Module graph that tracks the import relationships, url to file mapping
   * and hmr state.
   */
  moduleGraph: ModuleGraph
  /**
   * The resolved urls Vite prints on the CLI (URL-encoded). Returns `null`
   * in middleware mode or if the server is not listening on any port.
   */
  resolvedUrls: ResolvedServerUrls | null
  /**
   * Programmatically resolve, load and transform a URL and get the result
   * without going through the http request pipeline.
   */
  transformRequest(
    url: string,
    options?: TransformOptions,
  ): Promise<TransformResult | null>
  /**
   * Same as `transformRequest` but only warm up the URLs so the next request
   * will already be cached. The function will never throw as it handles and
   * reports errors internally.
   */
  warmupRequest(url: string, options?: TransformOptions): Promise<void>
  /**
   * Apply vite built-in HTML transforms and any plugin HTML transforms.
   */
  transformIndexHtml(
    url: string,
    html: string,
    originalUrl?: string,
  ): Promise<string>
  /**
   * Transform module code into SSR format.
   */
  ssrTransform(
    code: string,
    inMap: SourceMap | { mappings: '' } | null,
    url: string,
    originalCode?: string,
  ): Promise<TransformResult | null>
  /**
   * Load a given URL as an instantiated module for SSR.
   */
  ssrLoadModule(
    url: string,
    opts?: { fixStacktrace?: boolean },
  ): Promise<Record<string, any>>
  /**
   * Returns a fixed version of the given stack
   */
  ssrRewriteStacktrace(stack: string): string
  /**
   * Mutates the given SSR error by rewriting the stacktrace
   */
  ssrFixStacktrace(e: Error): void
  /**
   * Triggers HMR for a module in the module graph. You can use the `server.moduleGraph`
   * API to retrieve the module to be reloaded. If `hmr` is false, this is a no-op.
   */
  reloadModule(module: ModuleNode): Promise<void>
  /**
   * Start the server.
   */
  listen(port?: number, isRestart?: boolean): Promise<ViteDevServer>
  /**
   * Stop the server.
   */
  close(): Promise<void>
  /**
   * Print server urls
   */
  printUrls(): void
  /**
   * Bind CLI shortcuts
   */
  bindCLIShortcuts(options?: BindCLIShortcutsOptions<ViteDevServer>): void
  /**
   * Restart the server.
   *
   * @param forceOptimize - force the optimizer to re-bundle, same as --force cli flag
   */
  restart(forceOptimize?: boolean): Promise<void>
  /**
   * Open browser
   */
  openBrowser(): void
  /**
   * Calling `await server.waitForRequestsIdle(id)` will wait until all static imports
   * are processed. If called from a load or transform plugin hook, the id needs to be
   * passed as a parameter to avoid deadlocks. Calling this function after the first
   * static imports section of the module graph has been processed will resolve immediately.
   */
  waitForRequestsIdle: (ignoredId?: string) => Promise<void>
  /**
   * @internal
   */
  _setInternalServer(server: ViteDevServer): void
  /**
   * @internal
   */
  _restartPromise: Promise<void> | null
  /**
   * @internal
   */
  _forceOptimizeOnRestart: boolean
  /**
   * @internal
   */
  _shortcutsOptions?: BindCLIShortcutsOptions<ViteDevServer>
  /**
   * @internal
   */
  _currentServerPort?: number | undefined
  /**
   * @internal
   */
  _configServerPort?: number | undefined
  /**
   * @internal
   */
  _ssrCompatModuleRunner?: ModuleRunner
}

export interface ResolvedServerUrls {
  local: string[]
  network: string[]
}

export function createServer(
  inlineConfig: InlineConfig | ResolvedConfig = {},
): Promise<ViteDevServer> {
  // 本地服务创建入口
  return _createServer(inlineConfig, { listen: true })
}

export async function _createServer(
  inlineConfig: InlineConfig | ResolvedConfig = {},
  options: {
    listen: boolean
    previousEnvironments?: Record<string, DevEnvironment>
  },
): Promise<ViteDevServer> {
  const config = isResolvedConfig(inlineConfig)
    ? inlineConfig
    : await resolveConfig(inlineConfig, 'serve')

  if (usedConfigs.has(config)) {
    throw new Error(`There is already a server associated with the config.`)
  }

  if (config.command !== 'serve') {
    throw new Error(
      `Config was resolved for a "build", expected a "serve" command.`,
    )
  }

  usedConfigs.add(config)

  const initPublicFilesPromise = initPublicFiles(config)

  const { root, server: serverConfig } = config
  const httpsOptions = await resolveHttpsConfig(config.server.https)
  const { middlewareMode } = serverConfig

  const resolvedOutDirs = getResolvedOutDirs(
    config.root,
    config.build.outDir,
    config.build.rollupOptions.output,
  )
  const emptyOutDir = resolveEmptyOutDir(
    config.build.emptyOutDir,
    config.root,
    resolvedOutDirs,
  )
  const resolvedWatchOptions = resolveChokidarOptions(
    {
      disableGlobbing: true,
      ...serverConfig.watch,
    },
    resolvedOutDirs,
    emptyOutDir,
    config.cacheDir,
  )

  const middlewares = connect() as Connect.Server
  const httpServer = middlewareMode
    ? null
    : await resolveHttpServer(serverConfig, middlewares, httpsOptions)

  const ws = createWebSocketServer(httpServer, config, httpsOptions)

  const publicFiles = await initPublicFilesPromise
  const { publicDir } = config

  if (httpServer) {
    setClientErrorHandler(httpServer, config.logger)
  }

  // eslint-disable-next-line eqeqeq
  const watchEnabled = serverConfig.watch !== null
  const watcher = watchEnabled
    ? (chokidar.watch(
        // config file dependencies and env file might be outside of root
        // 配置文件依赖项 和 环境文件 可能在根目录之外
        [
          root,
          ...config.configFileDependencies,
          ...getEnvFilesForMode(config.mode, config.envDir),
          // Watch the public directory explicitly because it might be outside
          // of the root directory.
          ...(publicDir && publicFiles ? [publicDir] : []),
        ],

        resolvedWatchOptions,
      ) as FSWatcher)
    : createNoopWatcher(resolvedWatchOptions)

  const environments: Record<string, DevEnvironment> = {}
  for (const [name, environmentOptions] of Object.entries(
    config.environments,
  )) {
    environments[name] = await environmentOptions.dev.createEnvironment(
      name,
      config,
      {
        ws,
      },
    )
  }

  for (const environment of Object.values(environments)) {
    const previousInstance = options.previousEnvironments?.[environment.name]
    // 创建插件容器，并标识已经初始化 _initiated
    await environment.init({ watcher, previousInstance })
  }

  // Backward compatibility  向后兼容性
  let moduleGraph = new ModuleGraph({
    client: () => environments.client.moduleGraph,
    ssr: () => environments.ssr.moduleGraph,
  })


  // 模块图 moduleGraph 里的 _resolveId函数里有访问 this.pluginContainer 的逻辑
  const pluginContainer = createPluginContainer(environments)

  const closeHttpServer = createServerCloseFn(httpServer)

  const devHtmlTransformFn = createDevHtmlTransformFn(config)

  // Promise used by `server.close()` to ensure `closeServer()` is only called once // 确保 closeServer() 只被调用一次
  let closeServerPromise: Promise<void> | undefined
  const closeServer = async () => {
    if (!middlewareMode) {
      teardownSIGTERMListener(closeServerAndExit)
    }

    await Promise.allSettled([
      watcher.close(),
      ws.close(),
      Promise.allSettled(
        Object.values(server.environments).map((environment) =>
          environment.close(),
        ),
      ),
      closeHttpServer(),
      server._ssrCompatModuleRunner?.close(),
    ])
    server.resolvedUrls = null
    server._ssrCompatModuleRunner = undefined
  }

  let server: {
    transformIndexHtml(url, html, originalUrl): Promise<string>;
    _forceOptimizeOnRestart: boolean;
    middlewares: Connect.Server;
    environments: Record<string, DevEnvironment>;
    _setInternalServer(_server: ViteDevServer): void;
    ssrLoadModule(url, opts?: { fixStacktrace?: boolean }): Promise<SSRModule>;
    ssrRewriteStacktrace(stack: string): string;
    transformRequest(url, options): Promise<TransformResult | null>;
    reloadModule(module): Promise<void>;
    hot: WebSocketServer;
    listen(port?: number, isRestart?: boolean): Promise<{
      transformIndexHtml(url, html, originalUrl): Promise<string>;
      _forceOptimizeOnRestart: boolean;
      middlewares: Connect.Server;
      environments: Record<string, DevEnvironment>;
      _setInternalServer(_server: ViteDevServer): void;
      ssrLoadModule(url, opts?: { fixStacktrace?: boolean }): Promise<SSRModule>;
      ssrRewriteStacktrace(stack: string): string;
      transformRequest(url, options): Promise<TransformResult | null>;
      reloadModule(module): Promise<void>;
      hot: WebSocketServer;
      listen(port?: number, isRestart?: boolean): Promise<ViteDevServer>;
      _shortcutsOptions: undefined;
      ssrTransform(code: string, inMap: (SourceMap | {
        mappings: ""
      } | null), url: string, originalCode?: string): Promise<TransformResult | null>;
      printUrls(): void;
      ssrFixStacktrace(e): void;
      _restartPromise: null;
      ws: WebSocketServer;
      resolvedUrls: null;
      close(): Promise<void>;
      watcher: FSWatcher;
      restart(forceOptimize?: boolean): Promise<void>;
      warmupRequest(url, options): Promise<any>;
      httpServer: http.Server<any, any> | Http2SecureServer<any, any, any, any> | null;
      waitForRequestsIdle(ignoredId?: string): Promise<void>;
      pluginContainer: PluginContainer;
      moduleGraph: ModuleGraph;
      bindCLIShortcuts(options): void;
      config: ResolvedConfig;
      openBrowser(): void
    }>;
    _shortcutsOptions: undefined;
    ssrTransform(code: string, inMap: (SourceMap | {
      mappings: ""
    } | null), url: string, originalCode?: string): Promise<TransformResult | null>;
    printUrls(): void;
    ssrFixStacktrace(e): void;
    _restartPromise: null;
    ws: WebSocketServer;
    resolvedUrls: null;
    close(): Promise<void>;
    watcher: FSWatcher;
    restart(forceOptimize?: boolean): Promise<null>;
    warmupRequest(url, options): Promise<any>;
    httpServer: null | http.Server<typeof IncomingMessage, typeof ServerResponse> | Http2SecureServer<typeof IncomingMessage, typeof ServerResponse, typeof Http2ServerRequest, typeof Http2ServerResponse>;
    waitForRequestsIdle(ignoredId?: string): Promise<void>;
    pluginContainer: PluginContainer;
    moduleGraph: ModuleGraph;
    bindCLIShortcuts(options): void;
    config: ResolvedConfig;
    openBrowser(): void
  } = {
    config,
    middlewares,
    httpServer,
    watcher,
    ws,
    hot: ws,

    environments,
    pluginContainer,
    get moduleGraph() {
      warnFutureDeprecation(config, 'removeServerModuleGraph')
      return moduleGraph
    },
    set moduleGraph(graph) {
      moduleGraph = graph
    },

    resolvedUrls: null, // will be set on listen
    ssrTransform(
      code: string,
      inMap: SourceMap | { mappings: '' } | null,
      url: string,
      originalCode = code,
    ) {
      return ssrTransform(code, inMap, url, originalCode, {
        json: {
          stringify:
            config.json.stringify === true && config.json.namedExports !== true,
        },
      })
    },
    // environment.transformRequest and .warmupRequest don't take an options param for now,
    // so the logic and error handling needs to be duplicated here.
    // The only param in options that could be important is `html`, but we may remove it as
    // that is part of the internal control flow for the vite dev server to be able to bail
    // out and do the html fallback
    // environment.transformRequest和。warmupRequest现在不接受options参数，所以这里需要复制逻辑和错误处理。选项中唯一重要的参数是“html ”,但我们可以删除它，因为它是vite dev服务器的内部控制流的一部分，以便能够退出并执行html回退
    transformRequest(url, options) {
      warnFutureDeprecation(
        config,
        'removeServerTransformRequest',
        'server.transformRequest() is deprecated. Use environment.transformRequest() instead.',
      )
      const environment = server.environments[options?.ssr ? 'ssr' : 'client']
      return transformRequest(environment, url, options)
    },
    async warmupRequest(url, options) {
      try {
        const environment = server.environments[options?.ssr ? 'ssr' : 'client']
        await transformRequest(environment, url, options)
      } catch (e) {
        if (
          e?.code === ERR_OUTDATED_OPTIMIZED_DEP ||
          e?.code === ERR_CLOSED_SERVER
        ) {
          // these are expected errors
          return
        }
        // Unexpected error, log the issue but avoid an unhandled exception
        server.config.logger.error(
          buildErrorMessage(e, [`Pre-transform error: ${e.message}`], false),
          {
            error: e,
            timestamp: true,
          },
        )
      }
    },
    transformIndexHtml(url, html, originalUrl) {
      return devHtmlTransformFn(server, url, html, originalUrl)
    },
    async ssrLoadModule(url, opts?: { fixStacktrace?: boolean }) {
      warnFutureDeprecation(config, 'removeSsrLoadModule')
      return ssrLoadModule(url, server, opts?.fixStacktrace)
    },
    ssrFixStacktrace(e) {
      ssrFixStacktrace(e, server.environments.ssr.moduleGraph)
    },
    ssrRewriteStacktrace(stack: string) {
      return ssrRewriteStacktrace(stack, server.environments.ssr.moduleGraph)
    },
    async reloadModule(module) {
      if (serverConfig.hmr !== false && module.file) {
        // TODO: Should we also update the node moduleGraph for backward compatibility?
        const environmentModule = (module._clientModule ?? module._ssrModule)!
        updateModules(
          environments[environmentModule.environment]!,
          module.file,
          [environmentModule],
          Date.now(),
        )
      }
    },
    async listen(port?: number, isRestart?: boolean) {
      // 服务构建好了，还是监听端口
      await startServer(server, port)
      if (httpServer) {
        server.resolvedUrls = await resolveServerUrls(
          httpServer,
          config.server,
          httpsOptions,
          config,
        )
        if (!isRestart && config.server.open) server.openBrowser()
      }
      return server
    },
    openBrowser() {
      const options = server.config.server
      const url = getServerUrlByHost(server.resolvedUrls, options.host)
      if (url) {
        const path =
          typeof options.open === 'string'
            ? new URL(options.open, url).href
            : url

        // We know the url that the browser would be opened to, so we can
        // start the request while we are awaiting the browser. This will
        // start the crawling of static imports ~500ms before.
        // preTransformRequests needs to be enabled for this optimization.
        if (server.config.server.preTransformRequests) {
          setTimeout(() => {
            const getMethod = path.startsWith('https:') ? httpsGet : httpGet

            getMethod(
              path,
              {
                headers: {
                  // Allow the history middleware to redirect to /index.html
                  Accept: 'text/html',
                },
              },
              (res) => {
                res.on('end', () => {
                  // Ignore response, scripts discovered while processing the entry
                  // will be preprocessed (server.config.server.preTransformRequests)
                })
              },
            )
              .on('error', () => {
                // Ignore errors
              })
              .end()
          }, 0)
        }

        _openBrowser(path, true, server.config.logger)
      } else {
        server.config.logger.warn('No URL available to open in browser')
      }
    },
    async close() {
      if (!closeServerPromise) {
        closeServerPromise = closeServer()
      }
      return closeServerPromise
    },
    printUrls() {
      if (server.resolvedUrls) {
        printServerUrls(
          server.resolvedUrls,
          serverConfig.host,
          config.logger.info,
        )
      } else if (middlewareMode) {
        throw new Error('cannot print server URLs in middleware mode.')
      } else {
        throw new Error(
          'cannot print server URLs before server.listen is called.',
        )
      }
    },
    bindCLIShortcuts(options) {
      bindCLIShortcuts(server, options)
    },
    async restart(forceOptimize?: boolean) {
      if (!server._restartPromise) {
        server._forceOptimizeOnRestart = !!forceOptimize
        server._restartPromise = restartServer(server).finally(() => {
          server._restartPromise = null
          server._forceOptimizeOnRestart = false
        })
      }
      return server._restartPromise
    },

    waitForRequestsIdle(ignoredId?: string): Promise<void> {
      return environments.client.waitForRequestsIdle(ignoredId)
    },

    _setInternalServer(_server: ViteDevServer) {
      // Rebind internal the server variable so functions reference the user
      // server instance after a restart
      server = _server
    },
    _restartPromise: null,
    _forceOptimizeOnRestart: false,
    _shortcutsOptions: undefined,
  }

  // maintain consistency with the server instance after restarting.
  const reflexServer = new Proxy(server, {
    get: (_, property: keyof ViteDevServer) => {
      return server[property]
    },
    set: (_, property: keyof ViteDevServer, value: never) => {
      server[property] = value
      return true
    },
  })

  const closeServerAndExit = async (_: unknown, exitCode?: number) => {
    try {
      await server.close()
    } finally {
      process.exitCode ??= exitCode ? 128 + exitCode : undefined
      process.exit()
    }
  }

  if (!middlewareMode) {
    setupSIGTERMListener(closeServerAndExit)
  }

  const onHMRUpdate = async (
    type: 'create' | 'delete' | 'update',
    file: string,
  ) => {
    if (serverConfig.hmr !== false) {
      await handleHMRUpdate(type, file, server)
    }
  }

  const onFileAddUnlink = async (file: string, isUnlink: boolean) => {
    file = normalizePath(file)
    reloadOnTsconfigChange(server, file)

    await pluginContainer.watchChange(file, {
      event: isUnlink ? 'delete' : 'create',
    })

    if (publicDir && publicFiles) {
      if (file.startsWith(publicDir)) {
        const path = file.slice(publicDir.length)
        publicFiles[isUnlink ? 'delete' : 'add'](path)
        if (!isUnlink) {
          const clientModuleGraph = server.environments.client.moduleGraph
          const moduleWithSamePath =
            await clientModuleGraph.getModuleByUrl(path)
          const etag = moduleWithSamePath?.transformResult?.etag
          if (etag) {
            // The public file should win on the next request over a module with the
            // same path. Prevent the transform etag fast path from serving the module
            clientModuleGraph.etagToModuleMap.delete(etag)
          }
        }
      }
    }
    if (isUnlink) {
      // invalidate module graph cache on file change
      for (const environment of Object.values(server.environments)) {
        environment.moduleGraph.onFileDelete(file)
      }
    }
    await onHMRUpdate(isUnlink ? 'delete' : 'create', file)
  }

  // 模块热更新：文件变化时触发
  watcher.on('change', async (file) => {
    file = normalizePath(file)
    reloadOnTsconfigChange(server, file)

    await pluginContainer.watchChange(file, { event: 'update' })
    // invalidate module graph cache on file change
    for (const environment of Object.values(server.environments)) {
      environment.moduleGraph.onFileChange(file)
    }
    await onHMRUpdate('update', file)
  })

  watcher.on('add', (file) => {
    onFileAddUnlink(file, false)
  })
  watcher.on('unlink', (file) => {
    onFileAddUnlink(file, true)
  })

  if (!middlewareMode && httpServer) {
    httpServer.once('listening', () => {
      // update actual port since this may be different from initial value
      serverConfig.port = (httpServer.address() as net.AddressInfo).port
    })
  }

  // apply server configuration hooks from plugins
  const configureServerContext = new BasicMinimalPluginContext(
    { ...basePluginContextMeta, watchMode: true },
    config.logger,
  )
  const postHooks: ((() => void) | void)[] = [] // TODO 这块干嘛的
  for (const hook of config.getSortedPluginHooks('configureServer')) {
    postHooks.push(await hook.call(configureServerContext, reflexServer))
  }

  // Internal middlewares ------------------------------------------------------

  // request timer
  if (process.env.DEBUG) {
    middlewares.use(timeMiddleware(root))
  }

  // disallows request that contains `#` in the URL
  middlewares.use(rejectInvalidRequestMiddleware())

  // cors
  const { cors } = serverConfig
  if (cors !== false) {
    middlewares.use(corsMiddleware(typeof cors === 'boolean' ? {} : cors))
  }

  // host check (to prevent DNS rebinding attacks)
  const { allowedHosts } = serverConfig
  // no need to check for HTTPS as HTTPS is not vulnerable to DNS rebinding attacks
  // 没有必要检查HTTPS，因为HTTPS不容易受到DNS重新绑定攻击
  if (allowedHosts !== true && !serverConfig.https) {
    middlewares.use(hostValidationMiddleware(allowedHosts, false))
  }

  middlewares.use(cachedTransformMiddleware(server))

  // proxy 本地服务代理中间件
  const { proxy } = serverConfig
  if (proxy) {
    const middlewareServer =
      (isObject(middlewareMode) ? middlewareMode.server : null) || httpServer
    middlewares.use(proxyMiddleware(middlewareServer, proxy, config))
  }

  // base
  if (config.base !== '/') {
    middlewares.use(baseMiddleware(config.rawBase, !!middlewareMode))
  }

  // open in editor support
  middlewares.use('/__open-in-editor', launchEditorMiddleware())

  // ping request handler
  // Keep the named function. The name is visible in debug logs via `DEBUG=connect:dispatcher ...`
  // 保留已命名的函数。通过“DEBUG=connect:dispatcher ”,可以在调试日志中看到该名称...`
  middlewares.use(function viteHMRPingMiddleware(req, res, next) {
    if (req.headers['accept'] === 'text/x-vite-ping') {
      res.writeHead(204).end()
    } else {
      next()
    }
  })

  // serve static files under /public
  // this applies before the transform middleware so that these files are served
  // as-is without transforms.
  // 在/public下提供静态文件这适用于转换中间件之前，因此这些文件按原样提供，没有转换。
  if (publicDir) {
    middlewares.use(servePublicMiddleware(server, publicFiles))
  }

  // main transform middleware
  // 主要的转换中间件
  middlewares.use(transformMiddleware(server))

  // serve static files
  middlewares.use(serveRawFsMiddleware(server))
  middlewares.use(serveStaticMiddleware(server))

  // html fallback
  if (config.appType === 'spa' || config.appType === 'mpa') {
    middlewares.use(htmlFallbackMiddleware(root, config.appType === 'spa'))
  }

  // run post config hooks
  // This is applied before the html middleware so that user middleware can
  // serve custom content instead of index.html.
  postHooks.forEach((fn) => fn && fn())

  if (config.appType === 'spa' || config.appType === 'mpa') {
    // transform index.html
    middlewares.use(indexHtmlMiddleware(root, server))

    // handle 404s
    middlewares.use(notFoundMiddleware())
  }

  // error handler
  middlewares.use(errorMiddleware(server, !!middlewareMode))

  // httpServer.listen can be called multiple times
  // when port when using next port number
  // this code is to avoid calling buildStart multiple times
  // 使用下一个端口号时，可以多次调用httpServer.listen
  // 这段代码是为了避免多次调用buildStart
  let initingServer: Promise<void> | undefined
  let serverInited = false

  // 重写 httpServer 的 listen 方法
  const initServer = async (onListen: boolean) => {
    if (serverInited) return
    if (initingServer) return initingServer

    initingServer = (async function () {
      // For backward compatibility, we call buildStart for the client
      // environment when initing the server. For other environments
      // buildStart will be called when the first request is transformed
      // 为了向后兼容，我们在初始化服务器时为客户机环境调用 buildStart。
      // 对于其他环境，当第一个请求被转换时，将调用 buildStart
      await environments.client.pluginContainer.buildStart()

      // ensure ws server started
      if (onListen || options.listen) {
        await Promise.all(
          Object.values(environments).map((e) => e.listen(server)),
        )
      }

      initingServer = undefined
      serverInited = true
    })()
    return initingServer
  }

  if (!middlewareMode && httpServer) {
    // overwrite listen to init optimizer before server start
    // 在服务器启动前，覆盖监听初始化优化程序
    const listen = httpServer.listen.bind(httpServer)
    httpServer.listen = (async (port: number, ...args: any[]) => {
      try {
        await initServer(true)
      } catch (e) {
        httpServer.emit('error', e)
        return
      }
      return listen(port, ...args)
    }) as any
  } else {
    await initServer(false)
  }

  return server
}

async function startServer(
  server: ViteDevServer,
  inlinePort?: number,
): Promise<void> {
  const httpServer = server.httpServer
  if (!httpServer) {
    throw new Error('Cannot call server.listen in middleware mode.')
  }

  const options = server.config.server
  const hostname = await resolveHostname(options.host)
  const configPort = inlinePort ?? options.port
  // When using non strict port for the dev server, the running port can be different from the config one.
  // When restarting, the original port may be available but to avoid a switch of URL for the running
  // browser tabs, we enforce the previously used port, expect if the config port changed.
  // 当对开发服务器使用非严格端口时，运行端口可以不同于配置端口。
  // 重新启动时，原来的端口可能是可用的，但为了避免运行浏览器选项卡的URL切换，我们强制使用以前使用的端口，除非配置端口发生了变化。
  const port =
    (!configPort || configPort === server._configServerPort
      ? server._currentServerPort
      : configPort) ?? DEFAULT_DEV_PORT
  server._configServerPort = configPort

  const serverPort = await httpServerStart(httpServer, {
    port,
    strictPort: options.strictPort,
    host: hostname.host,
    logger: server.config.logger,
  })
  server._currentServerPort = serverPort
}

export function createServerCloseFn(
  server: HttpServer | null,
): () => Promise<void> {
  if (!server) {
    return () => Promise.resolve()
  }

  let hasListened = false
  const openSockets = new Set<net.Socket>()

  server.on('connection', (socket) => {
    openSockets.add(socket)
    socket.on('close', () => {
      openSockets.delete(socket)
    })
  })

  server.once('listening', () => {
    hasListened = true
  })

  return () =>
    new Promise<void>((resolve, reject) => {
      openSockets.forEach((s) => s.destroy())
      if (hasListened) {
        server.close((err) => {
          if (err) {
            reject(err)
          } else {
            resolve()
          }
        })
      } else {
        resolve()
      }
    })
}

function resolvedAllowDir(root: string, dir: string): string {
  return normalizePath(path.resolve(root, dir))
}

export const serverConfigDefaults = Object.freeze({
  port: DEFAULT_DEV_PORT,
  strictPort: false,
  host: 'localhost',
  allowedHosts: [],
  https: undefined,
  open: false,
  proxy: undefined,
  cors: { origin: defaultAllowedOrigins },
  headers: {},
  // hmr
  // ws
  warmup: {
    clientFiles: [],
    ssrFiles: [],
  },
  // watch
  middlewareMode: false,
  fs: {
    strict: true,
    // allow
    deny: ['.env', '.env.*', '*.{crt,pem}', '**/.git/**'],
  },
  // origin
  preTransformRequests: true,
  // sourcemapIgnoreList
  perEnvironmentStartEndDuringDev: false,
  // hotUpdateEnvironments
} satisfies ServerOptions)

export function resolveServerOptions(
  root: string,
  raw: ServerOptions | undefined,
  logger: Logger,
): ResolvedServerOptions {
  const _server = mergeWithDefaults(
    {
      ...serverConfigDefaults,
      host: undefined, // do not set here to detect whether host is set or not
      sourcemapIgnoreList: isInNodeModules,
    },
    raw ?? {},
  )

  const server: ResolvedServerOptions = {
    ..._server,
    fs: {
      ..._server.fs,
      // run searchForWorkspaceRoot only if needed
      allow: raw?.fs?.allow ?? [searchForWorkspaceRoot(root)],
    },
    sourcemapIgnoreList:
      _server.sourcemapIgnoreList === false
        ? () => false
        : _server.sourcemapIgnoreList,
  }

  let allowDirs = server.fs.allow

  if (process.versions.pnp) {
    // running a command fails if cwd doesn't exist and root may not exist
    // search for package root to find a path that exists
    const cwd = searchForPackageRoot(root)
    try {
      const enableGlobalCache =
        execSync('yarn config get enableGlobalCache', { cwd })
          .toString()
          .trim() === 'true'
      const yarnCacheDir = execSync(
        `yarn config get ${enableGlobalCache ? 'globalFolder' : 'cacheFolder'}`,
        { cwd },
      )
        .toString()
        .trim()
      allowDirs.push(yarnCacheDir)
    } catch (e) {
      logger.warn(`Get yarn cache dir error: ${e.message}`, {
        timestamp: true,
      })
    }
  }

  allowDirs = allowDirs.map((i) => resolvedAllowDir(root, i))

  // only push client dir when vite itself is outside-of-root
  const resolvedClientDir = resolvedAllowDir(root, CLIENT_DIR)
  if (!allowDirs.some((dir) => isParentDirectory(dir, resolvedClientDir))) {
    allowDirs.push(resolvedClientDir)
  }

  server.fs.allow = allowDirs

  if (server.origin?.endsWith('/')) {
    server.origin = server.origin.slice(0, -1)
    logger.warn(
      colors.yellow(
        `${colors.bold('(!)')} server.origin should not end with "/". Using "${
          server.origin
        }" instead.`,
      ),
    )
  }

  if (
    process.env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS &&
    Array.isArray(server.allowedHosts)
  ) {
    const additionalHost = process.env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS
    server.allowedHosts = [...server.allowedHosts, additionalHost]
  }

  return server
}

async function restartServer(server: ViteDevServer) {
  global.__vite_start_time = performance.now()
  const shortcutsOptions = server._shortcutsOptions

  let inlineConfig = server.config.inlineConfig
  if (server._forceOptimizeOnRestart) {
    inlineConfig = mergeConfig(inlineConfig, {
      forceOptimizeDeps: true,
    })
  }

  // Reinit the server by creating a new instance using the same inlineConfig
  // This will trigger a reload of the config file and re-create the plugins and
  // middlewares. We then assign all properties of the new server to the existing
  // server instance and set the user instance to be used in the new server.
  // This allows us to keep the same server instance for the user.
  {
    let newServer: ViteDevServer | null = null
    try {
      // delay ws server listen
      newServer = await _createServer(inlineConfig, {
        listen: false,
        previousEnvironments: server.environments,
      })
    } catch (err: any) {
      server.config.logger.error(err.message, {
        timestamp: true,
      })
      server.config.logger.error('server restart failed', { timestamp: true })
      return
    }

    await server.close()

    // Assign new server props to existing server instance
    const middlewares = server.middlewares
    newServer._configServerPort = server._configServerPort
    newServer._currentServerPort = server._currentServerPort
    Object.assign(server, newServer)

    // Keep the same connect instance so app.use(vite.middlewares) works
    // after a restart in middlewareMode (.route is always '/')
    middlewares.stack = newServer.middlewares.stack
    server.middlewares = middlewares

    // Rebind internal server variable so functions reference the user server
    newServer._setInternalServer(server)
  }

  const {
    logger,
    server: { port, middlewareMode },
  } = server.config
  if (!middlewareMode) {
    await server.listen(port, true)
  } else {
    await Promise.all(
      Object.values(server.environments).map((e) => e.listen(server)),
    )
  }
  logger.info('server restarted.', { timestamp: true })

  if (shortcutsOptions) {
    shortcutsOptions.print = false
    bindCLIShortcuts(server, shortcutsOptions)
  }
}

/**
 * Internal function to restart the Vite server and print URLs if changed
 */
export async function restartServerWithUrls(
  server: ViteDevServer,
): Promise<void> {
  if (server.config.server.middlewareMode) {
    await server.restart()
    return
  }

  const { port: prevPort, host: prevHost } = server.config.server
  const prevUrls = server.resolvedUrls

  await server.restart()

  const {
    logger,
    server: { port, host },
  } = server.config
  if (
    (port ?? DEFAULT_DEV_PORT) !== (prevPort ?? DEFAULT_DEV_PORT) ||
    host !== prevHost ||
    diffDnsOrderChange(prevUrls, server.resolvedUrls)
  ) {
    logger.info('')
    server.printUrls()
  }
}
