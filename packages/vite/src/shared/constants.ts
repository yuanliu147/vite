/**
 * Prefix for resolved Ids that are not valid browser import specifiers
 */
export const VALID_ID_PREFIX = `/@id/`

/**
 * Plugins that use 'virtual modules' (e.g. for helper functions), prefix the
 * module ID with `\0`, a convention from the rollup ecosystem.
 * This prevents other plugins from trying to process the id (like node resolution),
 * and core features like sourcemaps can use this info to differentiate between
 * virtual modules and regular files.
 * `\0` is not a permitted char in import URLs so we have to replace them during
 * import analysis. The id will be decoded back before entering the plugins pipeline.
 * These encoded virtual ids are also prefixed by the VALID_ID_PREFIX, so virtual
 * modules in the browser end up encoded as `/@id/__x00__{id}`
 *
 *
 * 使用“虚拟模块”的插件(例如帮助函数)，在模块 ID 前加上 “\0 ”,这是来自 rollup 生态系统的约定。
 * 这可以防止其他插件试图处理 id (如节点解析)，核心特性如 sourcemaps 可以使用这些信息来区分虚拟模块和常规文件。
 * `\0 '不是导入 URL 中允许的字符，因此我们必须在导入分析期间替换它们。id 将在进入插件管道之前被解码。
 * 这些编码的虚拟 ID 也以 VALID_ID_PREFIX 为前缀，因此浏览器中的虚拟模块最终编码为 `/@id/__x00__{id} ` 的形式
 */
export const NULL_BYTE_PLACEHOLDER = `__x00__`

export let SOURCEMAPPING_URL = 'sourceMa'
SOURCEMAPPING_URL += 'ppingURL'

export const MODULE_RUNNER_SOURCEMAPPING_SOURCE =
  '//# sourceMappingSource=vite-generated'

export const ERR_OUTDATED_OPTIMIZED_DEP = 'ERR_OUTDATED_OPTIMIZED_DEP'
