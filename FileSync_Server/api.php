<?php
declare(strict_types=1);

/**
 * ============================================================================
 *  LiquidGlass 双端同步 API
 * ----------------------------------------------------------------------------
 *  部署位置：站点根目录（与 index.html 同级），通过
 *            https://<你的域名>/api.php 访问。
 *
 *  安全模型（双向 RSA 签名认证）：
 *    - 客户端（main.py）持有  client_private.pem  与  server_public.pem
 *    - 服务端（本文件）持有    server_private.pem 与  client_public.pem
 *    - 请求：客户端用 client_private 对规范串签名，服务端用 client_public 验签
 *    - 响应：服务端用 server_private 对规范串签名，客户端用 server_public 验签
 *    - 规范串包含时间戳与随机 nonce，服务端缓存已用 nonce，防止重放
 *    - 未通过验签的请求不会执行任何操作、不会返回任何数据
 *
 *  ---------------------------------------------------------------------------
 *  【密钥目录】按以下优先级自动查找，取第一个"真实存在且可读"的：
 *
 *      1. lg_config.php        （与本文件同目录，返回 ["key_dir" => "..."])
 *      2. 环境变量 LG_KEY_DIR
 *      3. 站点根的上一级 /lg_keys       <- 推荐
 *      4. 站点根内 /lg_keys、/.lg_keys  <- 需在 lg_config.php 中显式允许
 *
 *      推荐布局（站点根为 /www/wwwroot/example.com）：
 *
 *          /www/wwwroot/lg_keys/              <- 站点根之外，nginx 无法访问
 *              ├── server_private.pem         <- 服务端私钥（生成后放这里）
 *              ├── client_public.pem          <- 客户端公钥（生成后放这里）
 *              └── .lgstate/                  <- API 自动创建（nonce 缓存）
 *
 *          /www/wwwroot/example.com/          <- 站点根
 *              ├── api.php
 *              ├── index.html
 *              └── ignored/                   <- API 自动创建（多余文件归档）
 *
 *  ！！宝塔 / cPanel 等面板默认给站点开启 open_basedir（防跨站攻击），
 *    此时 PHP 访问不到站点根之外的目录，密钥目录会解析失败并返回 503。
 *    二选一即可：
 *      a) 宝塔「网站 → 设置 → 配置文件」，在 open_basedir 末尾追加
 *         ":/www/wwwroot/lg_keys"，保存后重载 nginx；
 *      b) 宝塔「网站 → 设置 → 网站目录」，关闭「防跨站攻击(open_basedir)」。
 *    若确实要把密钥放在站点根内，必须同时在 nginx 中 deny 该目录，
 *    并在 lg_config.php 里设置 "allow_keydir_in_docroot" => true。
 *
 *  ---------------------------------------------------------------------------
 *  nginx 建议配置（强烈建议）：
 *
 *      client_max_body_size 8m;                      # 允许上传较大文件
 *      location ~ ^/(ignored|\.lgstate)/ { deny all; }   # 禁止访问归档与状态目录
 *      location ~ \.(pem|key)$          { deny all; }    # 双保险：禁止访问密钥
 * ============================================================================
 */

/* ============================== 配置区 ============================== */

const LG_VERSION       = '1.1.0';
const LG_BUILD         = '2026-10-16.1';   // 构建标记：每次改动递增，用于确认服务端跑的是哪一版
const LG_FEATURES      = ['chunked_write', 'git'];  // 能力清单：客户端据此判断能否用分片/git 协议

const LG_CLIENT_PUB    = 'client_public.pem';   // 客户端公钥文件名
const LG_SERVER_PRIV   = 'server_private.pem';  // 服务端私钥文件名
const LG_STATE_DIRNAME = '.lgstate';            // 非临时状态目录（nonce 缓存）
const LG_IGNORED_DIR   = 'ignored';             // 多余文件归档目录
const LG_REPO_DIRNAME  = '.lgrepo';             // 提交历史 / 暂存区 / 对象库
const LG_TRASH_DIRNAME = '.lgtrash';            // 在线编辑器删除文件的回收站

const LG_MAX_SKEW      = 300;                   // 允许的时间戳偏差（秒）
const LG_MAX_BODY      = 8388608;               // 单次请求体上限 8 MiB

/** 站点根内永不覆盖、永不归档的受保护路径（含宝塔等面板的运行文件） */
const LG_PROTECTED     = ['api.php', 'lg_config.php', '.user.ini', '.htaccess',
                          '.well-known', '404.html', 'lg_keys'];

$LG_BASE_DIR = __DIR__;   // 同步根目录（= 本文件所在目录）

/* ============================== 输出保护 ============================== */
/* 无论服务器 display_errors 怎么开，都保证只输出干净 JSON：
   先开输出缓冲，真正返回前把缓冲里的一切（PHP 警告等）丢弃。 */
$LG_RESPONDED = false;
error_reporting(E_ALL);
@ini_set('display_errors', '0');
@ini_set('log_errors', '1');
if (function_exists('ob_start')) {
    ob_start();
}

register_shutdown_function(static function (): void {
    global $LG_RESPONDED, $LG_DEBUG;
    if ($LG_RESPONDED) {
        return;
    }
    $err = error_get_last();
    $fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
    if ($err === null || !in_array($err['type'], $fatal, true)) {
        return;
    }
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
    }
    $payload = ['ok' => false, 'error' => 'server_error', 'api_build' => LG_BUILD];
    if ($LG_DEBUG) {
        $payload['detail'] = $err['message'] . ' @ ' . $err['file'] . ':' . $err['line'];
    } else {
        $payload['hint'] = '服务端发生致命错误；在 lg_config.php 里加 "debug" => true 可看到详情';
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

/* ============================== 基础设施 ============================== */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: no-referrer');

$LG_SERVER_KEY = null;
$LG_KEY_TOP    = '';    // 密钥目录在站点根内时的顶层目录名（用于排除同步）
$LG_DEBUG      = false; // 由 lg_config.php 的 "debug" => true 打开
$LG_NONCE      = isset($_SERVER['HTTP_X_LG_NONCE']) ? (string)$_SERVER['HTTP_X_LG_NONCE'] : '';

/** 输出 JSON 响应；响应体会被服务端私钥签名（若私钥可用） */
function lg_respond(array $payload, int $code = 200): void
{
    global $LG_SERVER_KEY, $LG_NONCE, $LG_RESPONDED;

    // 每个响应都带上构建标记，方便确认服务端实际运行的版本
    $payload['api_build'] = LG_BUILD;

    $body = json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    if ($body === false) {
        $body = '{"ok":false,"error":"encode_error"}';
    }

    // 丢弃此前所有杂散输出（PHP 警告、BOM、被包含文件的多余内容等）
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    http_response_code($code);

    if ($LG_SERVER_KEY !== null) {
        $canonical = "lgresp1\n" . $LG_NONCE . "\n" . hash('sha256', $body);
        $sig = '';
        if (openssl_sign($canonical, $sig, $LG_SERVER_KEY, OPENSSL_ALGO_SHA256)) {
            header('X-LG-Signature: ' . base64_encode($sig));
        }
    }

    $LG_RESPONDED = true;
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

/** 失败响应：不泄露任何内部信息（$extra 仅供管理员排障） */
function lg_fail(string $error, int $code = 400, int $delayUs = 0, array $extra = []): void
{
    if ($delayUs > 0) {
        usleep($delayUs);
    }
    lg_respond(array_merge(['ok' => false, 'error' => $error], $extra), $code);
}

/** 递归删除空目录（自底向上），不触碰受保护目录 */
function lg_prune_empty_dirs(string $dir, string $baseDir): void
{
    $items = @scandir($dir);
    if ($items === false) {
        return;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $full = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($full)) {
            lg_prune_empty_dirs($full, $baseDir);
            // 删除后若为空则移除自身
            $left = @scandir($full);
            if ($left !== false && count($left) <= 2) {
                @rmdir($full);
            }
        }
    }
}

/** 校验并归一化相对路径；非法返回 null */
function lg_safe_relpath(string $path): ?string
{
    $path = str_replace('\\', '/', trim($path));
    $path = ltrim($path, '/');
    if ($path === '' || strlen($path) > 1024) {
        return null;
    }
    foreach (explode('/', $path) as $seg) {
        if ($seg === '' || $seg === '.' || $seg === '..') {
            return null;
        }
    }
    return $path;
}

/** 是否为受保护 / 内部路径（相对站点根）；受保护的顶层目录，其下内容一并保护 */
function lg_is_reserved(string $rel): bool
{
    global $LG_KEY_TOP;

    $rel = trim(str_replace('\\', '/', $rel), '/');
    if ($rel === '') {
        return true;
    }
    $reserved = array_merge(
        [LG_IGNORED_DIR, LG_STATE_DIRNAME, LG_REPO_DIRNAME, LG_TRASH_DIRNAME],
        LG_PROTECTED
    );
    // 密钥目录万一被放在站点根内，绝不能被扫描、更不能被归档
    if (!empty($LG_KEY_TOP)) {
        $reserved[] = $LG_KEY_TOP;
    }
    // 写入过程的中间产物：既不能被列出、也不能被归档，更不能被当成写入目标
    //   .lgpart  分片上传的累积文件
    //   .lgtmp.  整文件写入的临时文件
    $base = basename($rel);
    if (strpos($base, '.lgpart') !== false || strpos($base, '.lgtmp.') !== false) {
        return true;
    }
    $top = explode('/', $rel)[0];
    return in_array($top, $reserved, true) || in_array($rel, $reserved, true);
}

/** 递归列出同步根下的文件（相对路径 => 信息），跳过归档/状态/受保护内容 */
function lg_scan(string $dir, string $baseDir, array &$out): void
{
    $items = @scandir($dir);
    if ($items === false) {
        return;
    }
    sort($items);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $full = $dir . DIRECTORY_SEPARATOR . $item;
        if (strncmp($full, $baseDir, strlen($baseDir)) !== 0) {
            continue;
        }
        $rel = substr($full, strlen($baseDir));
        $rel = str_replace('\\', '/', ltrim($rel, '/\\'));

        if (is_dir($full)) {
            if (lg_is_reserved($rel . '/')) {
                continue;
            }
            lg_scan($full, $baseDir, $out);
            continue;
        }
        if (lg_is_reserved($rel)) {
            continue;
        }
        $size = @filesize($full);
        $sha  = @hash_file('sha256', $full);
        $out[$rel] = [
            'path'  => $rel,
            'size'  => $size === false ? 0 : (int)$size,
            'sha256'=> $sha === false ? '' : $sha,
            'mtime' => (int)@filemtime($full),
        ];
    }
}

/** 统计归档目录里的文件数 */
function lg_count_ignored(string $baseDir): int
{
    $dir = $baseDir . DIRECTORY_SEPARATOR . LG_IGNORED_DIR;
    if (!is_dir($dir)) {
        return 0;
    }
    $n = 0;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $f) {
        if ($f->isFile()) {
            $n++;
        }
    }
    return $n;
}

/* ============================== 仓库存储（git 协议） ============================== */

/** 仓库内路径（相对 .lgrepo/）；不传参数返回仓库根 */
function lg_repo_path(string $name = ''): string
{
    global $LG_BASE_DIR;
    $dir = $LG_BASE_DIR . DIRECTORY_SEPARATOR . LG_REPO_DIRNAME;
    if ($name === '') {
        return $dir;
    }
    return $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $name);
}

/** 确保仓库目录与对象库存在 */
function lg_repo_init(): void
{
    foreach ([lg_repo_path(), lg_repo_path('objects')] as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }
}

/** 读取仓库 JSON 文件；不存在或损坏时返回默认值 */
function lg_repo_read(string $name, array $default = []): array
{
    $file = lg_repo_path($name);
    if (!is_file($file)) {
        return $default;
    }
    $raw = @file_get_contents($file);
    if ($raw === false || trim($raw) === '') {
        return $default;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

/** 原子写入仓库 JSON 文件 */
function lg_repo_write(string $name, array $data): bool
{
    lg_repo_init();
    $file = lg_repo_path($name);
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return false;
    }
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

/** 把文件内容存进对象库（按 sha256 去重） */
function lg_repo_store_object(string $sha, string $content): bool
{
    if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
        return false;
    }
    lg_repo_init();
    $file = lg_repo_path('objects/' . $sha);
    if (is_file($file)) {
        return true;
    }
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $content, LOCK_EX) === false) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

/** 提交记录容器 {head, commits[]} */
function lg_repo_state(): array
{
    $repo = lg_repo_read('commits.json', ['head' => '', 'commits' => []]);
    if (!isset($repo['commits']) || !is_array($repo['commits'])) {
        $repo['commits'] = [];
    }
    if (!isset($repo['head']) || !is_string($repo['head'])) {
        $repo['head'] = '';
    }
    return $repo;
}

/** 取某个提交的 manifest（path => sha256） */
function lg_repo_manifest(array $commits, string $id): array
{
    if ($id === '') {
        return [];
    }
    foreach ($commits as $c) {
        if ((string)($c['id'] ?? '') === $id) {
            $m = $c['manifest'] ?? [];
            return is_array($m) ? $m : [];
        }
    }
    return [];
}

/** 站点根下某个相对路径的绝对路径 */
function lg_site_file(string $rel): string
{
    global $LG_BASE_DIR;
    return $LG_BASE_DIR . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
}

/* ============================== 1. 基础校验 ============================== */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    lg_fail('method_not_allowed', 405);
}

/* ---------------- 密钥目录解析 ----------------
 * 优先级：lg_config.php > 环境变量 LG_KEY_DIR > 默认候选目录
 *
 * 注意：宝塔 / cPanel 等面板默认给站点开启 open_basedir（防跨站攻击），
 * 站点根之外的目录 PHP 根本访问不到，is_dir() 会直接失败。
 * 这里可以给出多个候选，自动挑第一个"真实存在且可读"的目录。
 * ------------------------------------------------------------------ */

function lg_load_config(string $baseDir): array
{
    $file = $baseDir . DIRECTORY_SEPARATOR . 'lg_config.php';
    if (!is_file($file)) {
        return [];
    }
    try {
        $cfg = @include $file;
    } catch (\Throwable $e) {
        // 配置文件语法错误等：明确报出来，而不是丢一个空白 500
        lg_fail('server_not_configured', 503, 0, [
            'hint' => 'lg_config.php 无法解析：' . $e->getMessage(),
            'fix'  => ['检查该文件的 PHP 语法；或先删除它（删除即回退到默认密钥目录）'],
        ]);
        return [];
    }
    return is_array($cfg) ? $cfg : [];
}

/** nonce 缓存目录：优先密钥目录，失败则退到系统临时目录 */
function lg_resolve_state_dir(string $keyDir): array
{
    $candidates = [
        $keyDir . DIRECTORY_SEPARATOR . LG_STATE_DIRNAME,
        rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR
            . LG_STATE_DIRNAME . '-' . substr(sha1($keyDir), 0, 10),
    ];
    $tried = [];
    foreach ($candidates as $dir) {
        if ($dir === '') {
            continue;
        }
        $tried[] = $dir;
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        if (is_dir($dir) && is_writable($dir)) {
            return ['dir' => $dir, 'ok' => true, 'tried' => $tried];
        }
    }
    return ['dir' => '', 'ok' => false, 'tried' => $tried];
}

function lg_abs_path(string $path, string $baseDir): string
{
    $path = str_replace('\\', '/', trim($path));
    if ($path === '') {
        return '';
    }
    if ($path[0] !== '/' && !preg_match('#^[A-Za-z]:/#', $path)) {
        $path = rtrim(str_replace('\\', '/', $baseDir), '/') . '/' . $path;
    }
    return rtrim($path, '/');
}

function lg_is_inside(string $path, string $root): bool
{
    $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
    $root = rtrim(str_replace('\\', '/', $root), '/') . '/';
    return strncmp($path, $root, strlen($root)) === 0;
}

/** @return array{dir:string, tried:string[], found:bool} */
function lg_resolve_key_dir(string $baseDir, array $cfg): array
{
    $baseDir = rtrim(str_replace('\\', '/', $baseDir), '/');
    $candidates = [];

    if (!empty($cfg['key_dir']) && is_string($cfg['key_dir'])) {
        $candidates[] = lg_abs_path($cfg['key_dir'], $baseDir);
    }
    $env = getenv('LG_KEY_DIR');
    if (is_string($env) && $env !== '') {
        $candidates[] = lg_abs_path($env, $baseDir);
    }
    $candidates[] = dirname($baseDir) . '/lg_keys';   // 站点根之外（推荐）
    $candidates[] = $baseDir . '/lg_keys';
    $candidates[] = $baseDir . '/.lg_keys';

    $tried = [];
    foreach ($candidates as $dir) {
        if ($dir === '' || in_array($dir, $tried, true)) {
            continue;
        }
        $tried[] = $dir;
        if (@is_dir($dir) && @is_readable($dir)) {
            // 规范化（消掉 ../ 与符号链接），否则「站点根/../lg_keys」会被误判成站点根内
            $real = @realpath($dir);
            $resolved = $real !== false ? str_replace('\\', '/', $real) : $dir;
            return ['dir' => $resolved, 'tried' => $tried, 'found' => true];
        }
    }
    return ['dir' => '', 'tried' => $tried, 'found' => false];
}

$LG_CONFIG  = lg_load_config($LG_BASE_DIR);
$LG_DEBUG   = !empty($LG_CONFIG['debug']);
$LG_KEYINFO = lg_resolve_key_dir($LG_BASE_DIR, $LG_CONFIG);

if ($LG_KEYINFO['found'] !== true) {
    lg_fail('server_not_configured', 503, 0, [
        'hint'         => '密钥目录不存在或不可读（常见原因：宝塔等面板的 open_basedir 限制）',
        'tried'        => $LG_KEYINFO['tried'],
        'open_basedir' => (string)ini_get('open_basedir'),
        'fix'          => [
            '推荐：把密钥目录加入站点 open_basedir —— 宝塔「网站→设置→配置文件」，'
                . '在 open_basedir 末尾追加 ":<密钥目录绝对路径>"',
            '或：在该站点关闭「防跨站攻击(open_basedir)」',
            '或：在本文件同目录建 lg_config.php，内容 <?php return ["key_dir" => "/可访问的绝对路径"];',
        ],
    ]);
}

$LG_KEY_DIR = $LG_KEYINFO['dir'];

/* 密钥目录若在站点根内，记录其顶层目录名，确保同步时永不触碰 */
if (lg_is_inside($LG_KEY_DIR, $LG_BASE_DIR)) {
    $lgKeyRel = ltrim(
        substr(str_replace('\\', '/', $LG_KEY_DIR),
               strlen(rtrim(str_replace('\\', '/', $LG_BASE_DIR), '/'))),
        '/'
    );
    $LG_KEY_TOP = $lgKeyRel === '' ? '' : explode('/', $lgKeyRel)[0];
}

/* 密钥目录若落在站点根内，必须显式确认，否则可能被 nginx 当静态文件读走 */
$lgDocRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
if ($lgDocRoot !== '' && lg_is_inside($LG_KEY_DIR, $lgDocRoot)
    && empty($LG_CONFIG['allow_keydir_in_docroot'])) {
    lg_fail('server_not_configured', 503, 0, [
        'hint'    => '密钥目录位于站点根内，存在被静态访问泄露的风险，已拒绝服务',
        'key_dir' => $LG_KEY_DIR,
        'fix'     => [
            '推荐：把密钥目录移到站点根之外（例如站点根的上一级 lg_keys/），'
                . '并把它加入 open_basedir',
            '若已用 nginx 禁止访问该目录与 *.pem 文件，可在本文件同目录建 lg_config.php，内容：'
                . '<?php return ["allow_keydir_in_docroot" => true];',
        ],
    ]);
}

$LG_CLIENT_PUB_KEY = @file_get_contents($LG_KEY_DIR . '/' . LG_CLIENT_PUB);
$lg_privPem        = @file_get_contents($LG_KEY_DIR . '/' . LG_SERVER_PRIV);

if ($LG_CLIENT_PUB_KEY === false || $lg_privPem === false) {
    $lgBadFiles = [];
    if ($LG_CLIENT_PUB_KEY === false) {
        $lgBadFiles[] = LG_CLIENT_PUB;
    }
    if ($lg_privPem === false) {
        $lgBadFiles[] = LG_SERVER_PRIV;
    }
    lg_fail('server_not_configured', 503, 0, [
        'hint'    => '密钥目录访问正常，但目录内的密钥文件读取失败（多半是文件属主/权限问题）',
        'key_dir' => $LG_KEY_DIR,
        'files'   => $lgBadFiles,
        'fix'     => [
            '先看文件是否真的存在、属主是谁：ls -la ' . $LG_KEY_DIR,
            '把整个目录连同内部文件一起交给 PHP 运行用户：chown -R www:www ' . $LG_KEY_DIR,
            '再给文件读权限：chmod 640 ' . $LG_KEY_DIR . '/*.pem',
            '（注意 chown 要带 -R，只改目录不改文件是无效的）',
        ],
    ]);
}

$LG_SERVER_KEY = openssl_pkey_get_private($lg_privPem);
$lg_clientKey  = openssl_pkey_get_public($LG_CLIENT_PUB_KEY);

if ($LG_SERVER_KEY === false || $lg_clientKey === false) {
    $lgPrivOk = ($LG_SERVER_KEY !== false);
    $lgPubOk  = ($lg_clientKey !== false);
    // 必须在报错前清空：false 会被误当成"有私钥"而触发签名致命错误
    $LG_SERVER_KEY = null;
    lg_fail('server_not_configured', 503, 0, [
        'hint'    => '密钥文件能读到了，但不是合法的 PEM 私钥/公钥（内容损坏，或公私钥放反了）',
        'key_dir' => $LG_KEY_DIR,
        'parse'   => [
            LG_SERVER_PRIV => $lgPrivOk ? '正常' : '解析失败',
            LG_CLIENT_PUB  => $lgPubOk ? '正常' : '解析失败',
        ],
        'fix'     => [
            '两个文件开头的 -----BEGIN 行应分别是：'
                . 'server_private.pem -> BEGIN PRIVATE KEY，client_public.pem -> BEGIN PUBLIC KEY',
            '若放反了或内容不完整，重新生成后再传：python main.py --genkeys --force',
        ],
    ]);
}

/* ============================== 2. 读取并验签请求 ============================== */

$lg_ts    = $_SERVER['HTTP_X_LG_TIMESTAMP'] ?? '';
$lg_sig   = $_SERVER['HTTP_X_LG_SIGNATURE'] ?? '';

if (!ctype_digit($lg_ts) || !preg_match('/^[0-9a-f]{32}$/', $LG_NONCE) || $lg_sig === '') {
    lg_fail('unauthorized', 401, 300000);
}

$lg_timeDiff = abs(time() - (int)$lg_ts);
if ($lg_timeDiff > LG_MAX_SKEW) {
    lg_fail('unauthorized', 401, 300000);
}

$lg_raw = file_get_contents('php://input', false, null, 0, LG_MAX_BODY + 1);
if ($lg_raw === false || strlen($lg_raw) > LG_MAX_BODY) {
    lg_fail('body_too_large', 413);
}

$lg_req = json_decode($lg_raw, true);
if (!is_array($lg_req) || !isset($lg_req['action']) || !is_string($lg_req['action'])) {
    lg_fail('bad_request', 400, 200000);
}
$lg_action = $lg_req['action'];

$lg_canonical = "lg1\n" . $lg_action . "\n" . $lg_ts . "\n" . $LG_NONCE . "\n"
              . hash('sha256', $lg_raw);

$lg_sigBin = base64_decode($lg_sig, true);
if ($lg_sigBin === false ||
    openssl_verify($lg_canonical, $lg_sigBin, $lg_clientKey, OPENSSL_ALGO_SHA256) !== 1) {
    lg_fail('unauthorized', 401, 300000);
}

/* ============================== 3. nonce 防重放 ============================== */

$LG_STATE_INFO = lg_resolve_state_dir($LG_KEY_DIR);
if ($LG_STATE_INFO['ok'] !== true) {
    lg_fail('server_error', 500, 0, [
        'hint'  => '无法创建 nonce 缓存目录（用于防重放），通常是密钥目录的写权限问题',
        'tried' => $LG_STATE_INFO['tried'],
        'fix'   => [
            '把密钥目录交给 PHP 运行用户：chown -R www:www ' . $LG_KEY_DIR,
            '或给它写权限：chmod 755 ' . $LG_KEY_DIR,
        ],
    ]);
}
$LG_STATE_DIR = $LG_STATE_INFO['dir'];

$lg_nonceFile = $LG_STATE_DIR . '/' . $LG_NONCE;
$lg_nonceFp   = @fopen($lg_nonceFile, 'x');
if ($lg_nonceFp === false) {
    // 该 nonce 已被使用过
    lg_fail('unauthorized', 401, 300000);
}
fwrite($lg_nonceFp, (string)time());
fclose($lg_nonceFp);

// 顺手清理过期 nonce（超出时间容差两倍即可失效）
$lg_expire = time() - LG_MAX_SKEW * 2;
$lg_handle = @opendir($LG_STATE_DIR);
if ($lg_handle !== false) {
    while (($f = readdir($lg_handle)) !== false) {
        if ($f === '.' || $f === '..') {
            continue;
        }
        $fp = $LG_STATE_DIR . '/' . $f;
        if (is_file($fp) && @filemtime($fp) < $lg_expire) {
            @unlink($fp);
        }
    }
    closedir($lg_handle);
}

/* ============================== 4. 分发 ============================== */

switch ($lg_action) {

    /* ---- 连通性 / 配置自检 ---- */
    case 'ping': {
        $ignoredCount = lg_count_ignored($LG_BASE_DIR);
        lg_respond([
            'ok'            => true,
            'version'       => LG_VERSION,
            'api_build'     => LG_BUILD,
            'features'      => LG_FEATURES,
            'server_time'   => time(),
            'base_dir'      => basename($LG_BASE_DIR),
            'max_body'      => LG_MAX_BODY,
            'ignored_count' => $ignoredCount,
            'php_version'   => PHP_VERSION,
        ]);
        break;
    }

    /* ---- 列出同步根下的所有文件 ---- */
    case 'list': {
        $files = [];
        lg_scan($LG_BASE_DIR, $LG_BASE_DIR, $files);
        $list = array_values($files);
        lg_respond([
            'ok'            => true,
            'files'         => $list,
            'count'         => count($list),
            'ignored_count' => lg_count_ignored($LG_BASE_DIR),
            'server_time'   => time(),
        ]);
        break;
    }

    /* ---- 读取单个文件（base64） ---- */
    case 'read': {
        $rel = lg_safe_relpath((string)($lg_req['path'] ?? ''));
        if ($rel === null || lg_is_reserved($rel)) {
            lg_fail('bad_path', 400);
        }
        $full = $LG_BASE_DIR . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
        if (!is_file($full)) {
            lg_fail('not_found', 404);
        }
        $data = @file_get_contents($full);
        if ($data === false) {
            lg_fail('read_error', 500);
        }
        lg_respond([
            'ok'          => true,
            'path'        => $rel,
            'size'        => strlen($data),
            'sha256'      => hash('sha256', $data),
            'mtime'       => (int)@filemtime($full),
            'content_b64' => base64_encode($data),
        ]);
        break;
    }

    /* ---- 写入 / 覆盖：整文件 + 分片追加 ---- */
    case 'write': {
        $files = $lg_req['files'] ?? null;
        if (!is_array($files)) {
            lg_fail('bad_request', 400);
        }
        $written = [];
        $errors  = [];
        foreach ($files as $f) {
            $rel = lg_safe_relpath((string)($f['path'] ?? ''));
            if ($rel === null || lg_is_reserved($rel)) {
                $errors[] = ['path' => (string)($f['path'] ?? ''), 'error' => 'bad_path'];
                continue;
            }
            $full = $LG_BASE_DIR . DIRECTORY_SEPARATOR
                  . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            $parent = dirname($full);
            if (!is_dir($parent) && !@mkdir($parent, 0755, true) && !is_dir($parent)) {
                $errors[] = ['path' => $rel, 'error' => 'mkdir_failed'];
                continue;
            }
            $sha = (string)($f['sha256'] ?? '');

            /* ---------------- 分片上传 ----------------
             * 客户端把文件切成若干片，每片一个请求：
             *   offset=0 的片重新开始累积，其余片校验偏移后续写；
             *   final=true 的那片负责校验总大小 + 整体 sha256，然后原子改名。
             * 中间产物是 .lgpart，已被 lg_is_reserved 排除，
             * 所以既不会出现在 list / 对比里，也不会被 prune 归档掉。 */
            if (isset($f['chunk_b64'])) {
                $offset = (int)($f['offset'] ?? -1);
                $total  = (int)($f['total']  ?? -1);
                $isLast = !empty($f['final']);
                $chunk  = base64_decode((string)$f['chunk_b64'], true);
                if ($chunk === false) {
                    $errors[] = ['path' => $rel, 'error' => 'bad_base64'];
                    continue;
                }
                if ($offset < 0 || $total < 0) {
                    $errors[] = ['path' => $rel, 'error' => 'bad_range'];
                    continue;
                }
                $part = $parent . DIRECTORY_SEPARATOR . '.' . basename($full) . '.lgpart';

                if ($offset === 0) {
                    $ok = @file_put_contents($part, $chunk, LOCK_EX) !== false;
                } else {
                    clearstatcache(true, $part);
                    $have = @filesize($part);
                    if ($have === false) {
                        $errors[] = ['path' => $rel, 'error' => 'chunk_not_started'];
                        continue;
                    }
                    if ((int)$have !== $offset) {
                        // 说明上一片没落盘（或并发写了同一个文件），让客户端从头来
                        $errors[] = ['path' => $rel, 'error' => 'chunk_offset_mismatch'];
                        continue;
                    }
                    $fh = @fopen($part, 'ab');
                    $ok = ($fh !== false) && (@fwrite($fh, $chunk) === strlen($chunk));
                    if ($fh !== false) {
                        @fclose($fh);
                    }
                }
                if (!$ok) {
                    @unlink($part);
                    $errors[] = ['path' => $rel, 'error' => 'write_failed'];
                    continue;
                }
                if (!$isLast) {
                    continue;                      // 中间分片：不进 written，客户端不计数
                }

                clearstatcache(true, $part);
                $size = (int)@filesize($part);
                if ($total > 0 && $size !== $total) {
                    @unlink($part);
                    $errors[] = ['path' => $rel, 'error' => 'size_mismatch'];
                    continue;
                }
                $digest = @hash_file('sha256', $part);
                if ($sha !== '' && ($digest === false || !hash_equals($sha, $digest))) {
                    @unlink($part);
                    $errors[] = ['path' => $rel, 'error' => 'hash_mismatch'];
                    continue;
                }
                if (!@rename($part, $full)) {
                    @unlink($part);
                    $errors[] = ['path' => $rel, 'error' => 'rename_failed'];
                    continue;
                }
                $written[] = [
                    'path'   => $rel,
                    'size'   => $size,
                    'sha256' => $digest === false ? '' : $digest,
                ];
                continue;
            }

            /* ---------------- 整文件（保留兼容） ---------------- */
            $content = base64_decode((string)($f['content_b64'] ?? ''), true);
            if ($content === false) {
                $errors[] = ['path' => $rel, 'error' => 'bad_base64'];
                continue;
            }
            if ($sha !== '' && !hash_equals($sha, hash('sha256', $content))) {
                $errors[] = ['path' => $rel, 'error' => 'hash_mismatch'];
                continue;
            }

            $tmp = $full . '.lgtmp.' . bin2hex(random_bytes(4));
            if (@file_put_contents($tmp, $content, LOCK_EX) === false) {
                @unlink($tmp);
                $errors[] = ['path' => $rel, 'error' => 'write_failed'];
                continue;
            }
            if (!@rename($tmp, $full)) {
                @unlink($tmp);
                $errors[] = ['path' => $rel, 'error' => 'rename_failed'];
                continue;
            }
            $written[] = [
                'path'   => $rel,
                'size'   => strlen($content),
                'sha256' => hash('sha256', $content),
            ];
        }
        lg_respond([
            'ok'      => true,
            'written' => $written,
            'errors'  => $errors,
        ]);
        break;
    }

    /* ---- 归档多余文件：不在 keep 名单内的文件移入 ignored/ ---- */
    case 'prune': {
        $keep = $lg_req['keep'] ?? null;
        if (!is_array($keep)) {
            lg_fail('bad_request', 400);
        }
        $keepMap = [];
        foreach ($keep as $k) {
            $rel = lg_safe_relpath((string)$k);
            if ($rel !== null) {
                $keepMap[$rel] = true;
            }
        }

        $existing = [];
        lg_scan($LG_BASE_DIR, $LG_BASE_DIR, $existing);

        $ignoredRoot = $LG_BASE_DIR . DIRECTORY_SEPARATOR . LG_IGNORED_DIR;
        $moved  = [];
        $errors = [];

        foreach ($existing as $rel => $info) {
            if (isset($keepMap[$rel])) {
                continue;                       // 保留
            }
            if (lg_is_reserved($rel)) {
                continue;                       // 受保护 / 内部
            }
            $src = $LG_BASE_DIR . DIRECTORY_SEPARATOR
                 . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            $dst = $ignoredRoot . DIRECTORY_SEPARATOR
                 . str_replace('/', DIRECTORY_SEPARATOR, $rel);

            $dstParent = dirname($dst);
            if (!is_dir($dstParent) && !@mkdir($dstParent, 0755, true) && !is_dir($dstParent)) {
                $errors[] = ['path' => $rel, 'error' => 'mkdir_failed'];
                continue;
            }
            if (is_file($dst)) {
                @unlink($dst);                  // 同名备份以最新为准
            }
            if (!@rename($src, $dst)) {
                $errors[] = ['path' => $rel, 'error' => 'move_failed'];
                continue;
            }
            $moved[] = $rel;
        }

        // 清理因移动而变空的目录
        lg_prune_empty_dirs($LG_BASE_DIR, $LG_BASE_DIR);

        lg_respond([
            'ok'            => true,
            'moved'         => $moved,
            'moved_count'   => count($moved),
            'kept_count'    => count($existing) - count($moved),
            'errors'        => $errors,
            'ignored_count' => lg_count_ignored($LG_BASE_DIR),
        ]);
        break;
    }

    /* ---- git：提交历史 ---- */
    case 'git_log': {
        $repo = lg_repo_state();
        $limit = (int)($lg_req['limit'] ?? 50);
        if ($limit <= 0 || $limit > 200) {
            $limit = 50;
        }
        $list = [];
        foreach (array_reverse($repo['commits']) as $c) {
            if (count($list) >= $limit) {
                break;
            }
            $list[] = [
                'id'      => (string)($c['id'] ?? ''),
                'message' => (string)($c['message'] ?? ''),
                'time'    => (int)($c['time'] ?? 0),
                'author'  => (string)($c['author'] ?? ''),
                'parent'  => (string)($c['parent'] ?? ''),
                'changes' => is_array($c['changes'] ?? null) ? $c['changes'] : [],
            ];
        }
        lg_respond([
            'ok'      => true,
            'head'    => $repo['head'],
            'total'   => count($repo['commits']),
            'commits' => $list,
        ]);
        break;
    }

    /* ---- git：单个提交详情 ---- */
    case 'git_show': {
        $id = (string)($lg_req['id'] ?? '');
        $repo = lg_repo_state();
        if ($id === '' || strtoupper($id) === 'HEAD') {
            $id = $repo['head'];
        }
        $found = null;
        foreach ($repo['commits'] as $c) {
            if ((string)($c['id'] ?? '') === $id) {
                $found = $c;
                break;
            }
        }
        if ($found === null) {
            lg_fail('not_found', 404);
        }
        lg_respond(['ok' => true, 'commit' => $found, 'head' => $repo['head']]);
        break;
    }

    /* ---- git：HEAD 与暂存区概况 ---- */
    case 'git_state': {
        $repo = lg_repo_state();
        $index = lg_repo_read('index.json', ['files' => []]);
        $files = is_array($index['files'] ?? null) ? $index['files'] : [];
        lg_respond([
            'ok'          => true,
            'head'        => $repo['head'],
            'total'       => count($repo['commits']),
            'index_files' => array_keys($files),
        ]);
        break;
    }

    /* ---- git：登记一次提交（文件需先用 write 上传） ---- */
    case 'git_commit': {
        $commit = $lg_req['commit'] ?? null;
        if (!is_array($commit)) {
            lg_fail('bad_request', 400);
        }
        $id = strtolower((string)($commit['id'] ?? ''));
        if (!preg_match('/^[0-9a-f]{6,40}$/', $id)) {
            lg_fail('bad_request', 400, 0, ['hint' => 'commit id 必须是 6~40 位十六进制']);
        }
        $message = trim((string)($commit['message'] ?? ''));
        if ($message === '' || strlen($message) > 4000) {
            lg_fail('bad_request', 400, 0, ['hint' => '提交信息不能为空，且不超过 4000 字节']);
        }
        $manifest = $commit['manifest'] ?? null;
        if (!is_array($manifest)) {
            lg_fail('bad_request', 400);
        }
        $changes = $commit['changes'] ?? [];
        if (!is_array($changes)) {
            $changes = [];
        }

        $repo  = lg_repo_state();
        $head  = $repo['head'];
        $parent = (string)($commit['parent'] ?? '');

        // 幂等：同一个 commit id 重复推送时直接算成功
        foreach ($repo['commits'] as $c) {
            if ((string)($c['id'] ?? '') === $id) {
                lg_respond([
                    'ok'        => true,
                    'id'        => $id,
                    'head'      => $head,
                    'total'     => count($repo['commits']),
                    'duplicate' => true,
                ]);
            }
        }

        if ($parent !== $head) {
            lg_fail('conflict', 409, 0, [
                'hint' => '服务端 HEAD 与本地提交的 parent 不一致，请先 pull 再 push',
                'head' => $head,
            ]);
        }

        // 清单只做路径与格式校验（不逐个哈希，避免大站每次 push 都全量读盘）
        $cleanManifest = [];
        foreach ($manifest as $path => $sha) {
            $rel = lg_safe_relpath((string)$path);
            if ($rel === null || lg_is_reserved($rel)) {
                lg_fail('bad_path', 400, 0, ['path' => (string)$path]);
            }
            $sha = strtolower((string)$sha);
            if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
                lg_fail('bad_request', 400, 0, ['path' => $rel, 'hint' => 'sha256 格式不对']);
            }
            $cleanManifest[$rel] = $sha;
        }

        // 只校验本次改动涉及的文件（防止"记录说改了，文件却没传上来"）
        $touched = [];
        foreach ($changes as $ch) {
            if (!is_array($ch) || (string)($ch['status'] ?? '') === 'deleted') {
                continue;
            }
            $rel = lg_safe_relpath((string)($ch['path'] ?? ''));
            if ($rel !== null) {
                $touched[$rel] = true;
            }
        }
        foreach ($touched as $rel => $_) {
            $sha = (string)($cleanManifest[$rel] ?? '');
            if ($sha === '') {
                continue;
            }
            $full = lg_site_file($rel);
            if (!is_file($full)) {
                lg_fail('sync_conflict', 409, 0, [
                    'path' => $rel,
                    'hint' => '清单里的文件在服务器上不存在，请先 push 文件内容',
                ]);
            }
            $actual = @hash_file('sha256', $full);
            if ($actual === false || !hash_equals($sha, $actual)) {
                lg_fail('sync_conflict', 409, 0, [
                    'path' => $rel,
                    'hint' => '服务器文件内容与提交清单不一致，请先拉取或重新上传',
                ]);
            }
        }

        // 变化过的文本文件内容进对象库，供后续提交计算 +X -Y
        $parentManifest = lg_repo_manifest($repo['commits'], $parent);
        foreach ($touched as $rel => $_) {
            $sha = (string)($cleanManifest[$rel] ?? '');
            if ($sha === '' || (string)($parentManifest[$rel] ?? '') === $sha) {
                continue;
            }
            $content = @file_get_contents(lg_site_file($rel));
            if ($content === false || strlen($content) > 2 * 1024 * 1024) {
                continue;
            }
            if (strpos(substr($content, 0, 8192), "\0") !== false) {
                continue;                     // 二进制不存快照
            }
            lg_repo_store_object($sha, $content);
        }

        $commits = $repo['commits'];
        $commits[] = [
            'id'       => $id,
            'message'  => $message,
            'time'     => (int)($commit['time'] ?? time()),
            'author'   => (string)($commit['author'] ?? 'client'),
            'parent'   => $parent,
            'changes'  => $changes,
            'manifest' => $cleanManifest,
        ];
        if (!lg_repo_write('commits.json', ['head' => $id, 'commits' => $commits])) {
            lg_fail('write_failed', 500, 0, [
                'hint' => '无法写入 .lgrepo/commits.json，请检查站点根目录的写权限',
            ]);
        }

        // 提交成功后清空服务端暂存区
        lg_repo_write('index.json', ['files' => []]);

        lg_respond([
            'ok'    => true,
            'id'    => $id,
            'head'  => $id,
            'total' => count($commits),
        ]);
        break;
    }

    default:
        lg_fail('unknown_action', 400);
}
