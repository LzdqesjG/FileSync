<?php
declare(strict_types=1);

/**
 * ============================================================================
 * FileSync 在线代码编辑器
 * ----------------------------------------------------------------------------
 * 部署位置：站点根/code/index.php（与 api.php 同级的 code 目录）
 *
 * 能力：
 *   - 浏览/编辑站点根下除受保护文件外的所有文件
 *   - 代码高亮（CodeMirror，无自动补全）、等宽字体、Ctrl+S 保存
 *   - 删除文件 -> 回收站（可复原）
 *   - 暂存改动 -> 提交 commit（与 api.php / 客户端共用 .lgrepo/ 数据）
 *
 * 认证：
 *   在站点根的 lg_config.php（或 code/config.php）里配置：
 *       "editor_password" => "你的密码",        // 明文或 password_hash() 结果均可
 *   未配置密码时本页面拒绝访问（安全默认）。
 *
 * 受保护路径（不可编辑）：
 *   api.php、lg_config.php、.lgrepo/、.lgtrash/、ignored/、.lgstate/、
 *   lg_keys/、*.pem、以及 .htaccess / .user.ini 等服务器文件。
 * ============================================================================
 */

@ini_set('display_errors', '0');
@ini_set('log_errors', '1');
error_reporting(E_ALL);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    ]);
    session_start();
}

$SITE_ROOT = rtrim(str_replace('\\', '/', dirname(__DIR__)), '/');
$CODE_DIR  = __DIR__;
$REPO_DIR  = $SITE_ROOT . '/.lgrepo';
$TRASH_DIR = $SITE_ROOT . '/.lgtrash';

/** 站点根下永不开放编辑的顶层名字 */
const EDITOR_PROTECTED = [
    'api.php', 'lg_config.php', '.user.ini', '.htaccess', '404.html',
    'lg_keys', '.lg_keys', 'ignored', '.lgstate', '.lgrepo', '.lgtrash',
];

/* ============================== 配置 ============================== */

function editor_config(): array
{
    global $SITE_ROOT, $CODE_DIR;
    $cfg = [];
    foreach ([$SITE_ROOT . '/lg_config.php', $CODE_DIR . '/config.php'] as $file) {
        if (!is_file($file)) {
            continue;
        }
        try {
            $part = @include $file;
        } catch (Throwable $e) {
            $part = [];
        }
        if (is_array($part)) {
            $cfg = array_merge($cfg, $part);
        }
    }
    return $cfg;
}

function editor_password_ok(string $input, string $stored): bool
{
    if ($stored === '') {
        return false;
    }
    if (preg_match('/^\$(2[aby]|argon2)/', $stored)) {
        return password_verify($input, $stored);
    }
    return hash_equals($stored, $input);
}

/* ============================== 基础工具 ============================== */

function json_out(array $payload, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(string $message, int $code = 400, array $extra = []): void
{
    json_out(array_merge(['ok' => false, 'error' => $message], $extra), $code);
}

function safe_rel(string $path): ?string
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

function is_protected(string $rel): bool
{
    $top = explode('/', $rel)[0];
    if (in_array($top, EDITOR_PROTECTED, true)) {
        return true;
    }
    $lower = strtolower($rel);
    if (str_ends_with($lower, '.pem')) {
        return true;
    }
    if (str_contains($rel, '.lgpart') || str_contains($rel, '.lgtmp.')) {
        return true;
    }
    return false;
}

function site_file(string $rel): string
{
    global $SITE_ROOT;
    return $SITE_ROOT . '/' . str_replace('/', DIRECTORY_SEPARATOR, $rel);
}

function ensure_dir(string $dir): bool
{
    return is_dir($dir) || @mkdir($dir, 0755, true) || is_dir($dir);
}

function read_json(string $file, array $default = []): array
{
    if (!is_file($file)) {
        return $default;
    }
    $raw = @file_get_contents($file);
    if ($raw === false) {
        return $default;
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : $default;
}

function write_json(string $file, array $data): bool
{
    if (!ensure_dir(dirname($file))) {
        return false;
    }
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

function is_binary(string $data): bool
{
    return str_contains(substr($data, 0, 8192), "\0");
}

/* ============================== 仓库（.lgrepo） ============================== */

function repo_commits(): array
{
    global $REPO_DIR;
    $repo = read_json($REPO_DIR . '/commits.json', ['head' => '', 'commits' => []]);
    if (!isset($repo['commits']) || !is_array($repo['commits'])) {
        $repo['commits'] = [];
    }
    if (!isset($repo['head']) || !is_string($repo['head'])) {
        $repo['head'] = '';
    }
    return $repo;
}

function repo_object_file(string $sha): string
{
    global $REPO_DIR;
    return $REPO_DIR . '/objects/' . $sha;
}

function repo_store_object(string $sha, string $content): bool
{
    if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
        return false;
    }
    $file = repo_object_file($sha);
    if (is_file($file)) {
        return true;
    }
    if (!ensure_dir(dirname($file))) {
        return false;
    }
    $tmp = $file . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $content, LOCK_EX) === false) {
        @unlink($tmp);
        return false;
    }
    return @rename($tmp, $file);
}

function repo_read_object(string $sha): ?string
{
    if ($sha === '' || !preg_match('/^[0-9a-f]{64}$/', $sha)) {
        return null;
    }
    $file = repo_object_file($sha);
    if (!is_file($file)) {
        return null;
    }
    $data = @file_get_contents($file);
    return $data === false ? null : $data;
}

function repo_manifest_of(array $commits, string $id): array
{
    if ($id === '') {
        return [];
    }
    foreach ($commits as $c) {
        if (($c['id'] ?? '') === $id) {
            return is_array($c['manifest'] ?? null) ? $c['manifest'] : [];
        }
    }
    return [];
}

function repo_index(): array
{
    global $REPO_DIR;
    $index = read_json($REPO_DIR . '/index.json', ['files' => []]);
    if (!isset($index['files']) || !is_array($index['files'])) {
        $index['files'] = [];
    }
    return $index;
}

function repo_save_index(array $index): bool
{
    global $REPO_DIR;
    return write_json($REPO_DIR . '/index.json', $index);
}

/** 行级差异统计（新增行数, 删除行数）；二进制返回 [0,0] */
function line_stats(string $old, string $new): array
{
    if (is_binary($old) || is_binary($new)) {
        return [0, 0];
    }
    $a = $old === '' ? [] : preg_split('/\r\n|\r|\n/', rtrim($old, "\r\n"));
    $b = $new === '' ? [] : preg_split('/\r\n|\r|\n/', rtrim($new, "\r\n"));
    $n = count($a);
    $m = count($b);

    $start = 0;
    while ($start < $n && $start < $m && $a[$start] === $b[$start]) {
        $start++;
    }
    $endA = $n - 1;
    $endB = $m - 1;
    while ($endA >= $start && $endB >= $start && $a[$endA] === $b[$endB]) {
        $endA--;
        $endB--;
    }

    $ma = $endA - $start + 1;
    $mb = $endB - $start + 1;
    if ($ma <= 0 && $mb <= 0) {
        return [0, 0];
    }
    if ($ma <= 0) {
        return [$mb, 0];
    }
    if ($mb <= 0) {
        return [0, $ma];
    }
    if ($ma * $mb > 400000) {
        return [$mb, $ma];
    }

    $dp = array_fill(0, $ma + 1, array_fill(0, $mb + 1, 0));
    for ($i = $ma - 1; $i >= 0; $i--) {
        for ($j = $mb - 1; $j >= 0; $j--) {
            $dp[$i][$j] = ($a[$start + $i] === $b[$start + $j])
                ? $dp[$i + 1][$j + 1] + 1
                : max($dp[$i + 1][$j], $dp[$i][$j + 1]);
        }
    }
    $lcs = $dp[0][0];
    return [$mb - $lcs, $ma - $lcs];
}

/* ============================== 自动登录 ============================== */

$CONFIG = editor_config();
$PASSWORD = trim((string)($CONFIG['editor_password'] ?? ''));
$AUTH = !empty($_SESSION['lg_editor_auth']);

if ($PASSWORD === '') {
    $AUTH = false;
}

if (empty($_SESSION['lg_editor_csrf'])) {
    $_SESSION['lg_editor_csrf'] = bin2hex(random_bytes(16));
}
$CSRF = (string)$_SESSION['lg_editor_csrf'];

/* ============================== API ============================== */

$api = isset($_GET['api']) ? (string)$_GET['api'] : '';

if ($api === 'login') {
    $input = (string)($_POST['password'] ?? '');
    $tries = (int)($_SESSION['lg_editor_tries'] ?? 0);
    if ($tries >= 8) {
        fail('登录尝试次数过多，请重启浏览器会话后再试', 429);
    }
    if ($PASSWORD === '') {
        fail('服务端尚未配置 editor_password（见 lg_config.php）', 503);
    }
    if (!editor_password_ok($input, $PASSWORD)) {
        $_SESSION['lg_editor_tries'] = $tries + 1;
        usleep(400000);
        fail('密码错误', 401);
    }
    $_SESSION['lg_editor_auth'] = true;
    $_SESSION['lg_editor_tries'] = 0;
    $_SESSION['lg_editor_csrf'] = bin2hex(random_bytes(16));
    json_out(['ok' => true, 'csrf' => $_SESSION['lg_editor_csrf']]);
}

if ($api === 'logout') {
    $_SESSION['lg_editor_auth'] = false;
    json_out(['ok' => true]);
}

if ($api !== '') {
    if (!$AUTH) {
        fail('未登录', 401);
    }
    $token = (string)($_SERVER['HTTP_X_CSRF'] ?? '');
    if (!hash_equals($CSRF, $token)) {
        fail('CSRF 校验失败，请刷新页面', 403);
    }
}

/** 读取 JSON 请求体 */
function json_body(): array
{
    $raw = @file_get_contents('php://input');
    $data = json_decode((string)$raw, true);
    return is_array($data) ? $data : [];
}

if ($api !== '') {
switch ($api) {
    case 'list': {
        $files = [];
        $root = $SITE_ROOT;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $file) {
            /** @var SplFileInfo $file */
            $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));
            if ($rel === '' || is_protected($rel)) {
                continue;
            }
            $base = basename($rel);
            if ($base !== '' && $base[0] === '.') {
                continue;
            }
            if ($file->isDir()) {
                continue;
            }
            $files[] = [
                'path'  => $rel,
                'size'  => (int)$file->getSize(),
                'mtime' => (int)$file->getMTime(),
            ];
        }
        usort($files, static fn(array $a, array $b): int => strcmp($a['path'], $b['path']));
        json_out(['ok' => true, 'files' => $files, 'root' => basename($root)]);
    }

    case 'read': {
        $rel = safe_rel((string)($_GET['path'] ?? ''));
        if ($rel === null || is_protected($rel)) {
            fail('路径不合法', 400);
        }
        $full = site_file($rel);
        if (!is_file($full)) {
            fail('文件不存在', 404);
        }
        $size = (int)@filesize($full);
        if ($size > 4 * 1024 * 1024) {
            fail('文件超过 4MB，请用 FTP/SFTP 编辑', 413);
        }
        $content = @file_get_contents($full);
        if ($content === false) {
            fail('读取失败', 500);
        }
        if (is_binary($content)) {
            json_out(['ok' => false, 'binary' => true, 'error' => '二进制文件，无法编辑',
                      'path' => $rel, 'size' => $size]);
        }
        $utf8ok = function_exists('mb_check_encoding')
            ? mb_check_encoding($content, 'UTF-8')
            : (bool)preg_match('//u', $content);
        if (!$utf8ok) {
            json_out(['ok' => false, 'binary' => true, 'error' => '非 UTF-8 文本，无法编辑',
                      'path' => $rel, 'size' => $size]);
        }
        json_out([
            'ok'      => true,
            'path'    => $rel,
            'content' => $content,
            'size'    => $size,
            'sha256'  => hash('sha256', $content),
        ]);
    }

    case 'save': {
        $body = json_body();
        $rel = safe_rel((string)($body['path'] ?? ''));
        if ($rel === null || is_protected($rel)) {
            fail('路径不合法', 400);
        }
        $content = (string)($body['content'] ?? '');
        $full = site_file($rel);
        if (!ensure_dir(dirname($full))) {
            fail('无法创建目录', 500);
        }
        if (is_file($full)) {
            $old = @file_get_contents($full);
            if ($old !== false && is_binary($old)) {
                fail('二进制文件不允许在线保存', 400);
            }
        }
        $tmp = $full . '.lgtmp.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, $content, LOCK_EX) === false) {
            @unlink($tmp);
            fail('写入失败（目录权限？）', 500);
        }
        if (!@rename($tmp, $full)) {
            @unlink($tmp);
            fail('保存失败（改名失败）', 500);
        }
        json_out([
            'ok'     => true,
            'path'   => $rel,
            'size'   => strlen($content),
            'sha256' => hash('sha256', $content),
        ]);
    }

    case 'delete': {
        $body = json_body();
        $rel = safe_rel((string)($body['path'] ?? ''));
        if ($rel === null || is_protected($rel)) {
            fail('路径不合法', 400);
        }
        $full = site_file($rel);
        if (!is_file($full)) {
            fail('文件不存在', 404);
        }
        $stamp = date('Ymd-His');
        $trashRel = $stamp . '/' . $rel;
        $trashFull = $TRASH_DIR . '/' . $trashRel;
        if (!ensure_dir(dirname($trashFull))) {
            fail('无法创建回收站目录', 500);
        }
        if (!@rename($full, $trashFull)) {
            fail('移入回收站失败（权限？）', 500);
        }
        $trashIndex = read_json($TRASH_DIR . '/index.json', ['items' => []]);
        if (!isset($trashIndex['items']) || !is_array($trashIndex['items'])) {
            $trashIndex['items'] = [];
        }
        $trashIndex['items'][] = ['path' => $rel, 'trash' => $trashRel, 'time' => time()];
        write_json($TRASH_DIR . '/index.json', $trashIndex);

        // 删除也进暂存区，提交时记为 deleted
        $index = repo_index();
        $index['files'][$rel] = ['status' => 'deleted', 'sha256' => '', 'time' => time()];
        repo_save_index($index);

        json_out(['ok' => true, 'path' => $rel, 'trash' => $trashRel]);
    }

    case 'trash': {
        $trashIndex = read_json($TRASH_DIR . '/index.json', ['items' => []]);
        $items = is_array($trashIndex['items'] ?? null) ? $trashIndex['items'] : [];
        json_out(['ok' => true, 'items' => array_reverse($items)]);
    }

    case 'restore': {
        $body = json_body();
        $rel = safe_rel((string)($body['path'] ?? ''));
        if ($rel === null || is_protected($rel)) {
            fail('路径不合法', 400);
        }
        $trashIndex = read_json($TRASH_DIR . '/index.json', ['items' => []]);
        $items = is_array($trashIndex['items'] ?? null) ? $trashIndex['items'] : [];
        $found = null;
        foreach ($items as $i => $item) {
            if (($item['path'] ?? '') === $rel) {
                $found = $item;
                $foundIndex = $i;
                break;
            }
        }
        if ($found === null) {
            fail('回收站里没有这个文件', 404);
        }
        $src = $TRASH_DIR . '/' . $found['trash'];
        $dst = site_file($rel);
        if (!is_file($src)) {
            fail('回收站文件已丢失', 404);
        }
        if (!ensure_dir(dirname($dst))) {
            fail('无法创建目标目录', 500);
        }
        if (is_file($dst)) {
            fail('目标位置已存在同名文件，请先移走它', 409);
        }
        if (!@rename($src, $dst)) {
            fail('复原失败（权限？）', 500);
        }
        unset($items[$foundIndex]);
        write_json($TRASH_DIR . '/index.json', ['items' => array_values($items)]);

        $index = repo_index();
        unset($index['files'][$rel]);
        repo_save_index($index);

        json_out(['ok' => true, 'path' => $rel]);
    }

    case 'status': {
        $repo = repo_commits();
        $manifest = repo_manifest_of($repo['commits'], $repo['head']);
        $index = repo_index();
        $changed = [];
        foreach ($manifest as $path => $sha) {
            $full = site_file($path);
            if (!is_file($full)) {
                $changed[$path] = 'deleted';
                continue;
            }
            $now = @hash_file('sha256', $full);
            if ($now !== false && $now !== $sha) {
                $changed[$path] = 'modified';
            }
        }
        json_out([
            'ok'      => true,
            'head'    => $repo['head'],
            'staged'  => $index['files'],
            'changed' => $changed,
        ]);
    }

    case 'stage': {
        $body = json_body();
        $paths = $body['paths'] ?? null;
        $all = !empty($body['all']);
        $repo = repo_commits();
        $manifest = repo_manifest_of($repo['commits'], $repo['head']);
        $index = repo_index();

        $targets = [];
        if ($all) {
            foreach ($manifest as $path => $sha) {
                $full = site_file($path);
                if (!is_file($full)) {
                    $targets[] = $path;
                    continue;
                }
                $now = @hash_file('sha256', $full);
                if ($now !== false && $now !== $sha) {
                    $targets[] = $path;
                }
            }
            // 未跟踪的新文件也一并暂存
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($SITE_ROOT, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($SITE_ROOT) + 1));
                if ($rel === '' || is_protected($rel) || basename($rel)[0] === '.') {
                    continue;
                }
                if (!isset($manifest[$rel])) {
                    $targets[] = $rel;
                }
            }
        } else {
            if (!is_array($paths)) {
                fail('参数不合法', 400);
            }
            foreach ($paths as $p) {
                $rel = safe_rel((string)$p);
                if ($rel === null || is_protected($rel)) {
                    continue;
                }
                $targets[] = $rel;
            }
        }

        $staged = 0;
        foreach (array_unique($targets) as $rel) {
            $full = site_file($rel);
            if (!is_file($full)) {
                $index['files'][$rel] = ['status' => 'deleted', 'sha256' => '', 'time' => time()];
                $staged++;
                continue;
            }
            $content = @file_get_contents($full);
            if ($content === false) {
                continue;
            }
            $sha = hash('sha256', $content);
            // 只为「文本且不大」的文件保存内容快照，避免把视频/安装包塞进对象库
            if (strlen($content) <= 2 * 1024 * 1024 && !is_binary($content)) {
                repo_store_object($sha, $content);
            }
            $index['files'][$rel] = [
                'status'  => isset($manifest[$rel]) ? 'modified' : 'added',
                'sha256'  => $sha,
                'time'    => time(),
            ];
            $staged++;
        }

        if (!repo_save_index($index)) {
            fail('无法写入 .lgrepo/index.json（权限？）', 500);
        }
        json_out(['ok' => true, 'staged' => $staged, 'index' => $index['files']]);
    }

    case 'unstage': {
        $body = json_body();
        $paths = $body['paths'] ?? [];
        $index = repo_index();
        foreach ((array)$paths as $p) {
            unset($index['files'][(string)$p]);
        }
        repo_save_index($index);
        json_out(['ok' => true, 'index' => $index['files']]);
    }

    case 'commit': {
        $body = json_body();
        $message = trim((string)($body['message'] ?? ''));
        if ($message === '') {
            fail('提交信息不能为空', 400);
        }
        $repo = repo_commits();
        $index = repo_index();
        if (empty($index['files'])) {
            fail('暂存区为空，请先暂存改动', 400);
        }

        $parent = $repo['head'];
        $manifest = repo_manifest_of($repo['commits'], $parent);
        $changes = [];

        foreach ($index['files'] as $rel => $item) {
            $status = (string)($item['status'] ?? 'modified');
            $oldSha = (string)($manifest[$rel] ?? '');
            $old = repo_read_object($oldSha) ?? '';

            if ($status === 'deleted') {
                unset($manifest[$rel]);
                [$added, $removed] = line_stats($old, '');
                $changes[] = ['path' => $rel, 'status' => 'deleted',
                              'added' => 0, 'removed' => $removed];
                continue;
            }

            $full = site_file($rel);
            if (!is_file($full)) {
                unset($manifest[$rel]);
                $changes[] = ['path' => $rel, 'status' => 'deleted', 'added' => 0,
                              'removed' => line_stats($old, '')[1]];
                continue;
            }
            $content = @file_get_contents($full);
            if ($content === false) {
                fail('读取文件失败：' . $rel, 500);
            }
            $sha = hash('sha256', $content);
            if (strlen($content) <= 2 * 1024 * 1024 && !is_binary($content)) {
                repo_store_object($sha, $content);
            }
            $manifest[$rel] = $sha;
            [$added, $removed] = line_stats($old, $content);
            $changes[] = [
                'path'   => $rel,
                'status' => $oldSha === '' ? 'added' : 'modified',
                'added'  => $added,
                'removed'=> $removed,
            ];
        }

        $payload = json_encode(
            ['p' => $parent, 'm' => $message, 'f' => $manifest],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
        $commitId = substr(hash('sha256', $parent . "\n" . $message . "\n" . $payload . "\n" . microtime(true)), 0, 12);

        $commit = [
            'id'       => $commitId,
            'message'  => $message,
            'time'     => time(),
            'author'   => 'editor',
            'parent'   => $parent,
            'changes'  => $changes,
            'manifest' => $manifest,
        ];
        $repo['commits'][] = $commit;
        $repo['head'] = $commitId;
        if (!write_json($REPO_DIR . '/commits.json', $repo)) {
            fail('无法写入 .lgrepo/commits.json（权限？）', 500);
        }
        repo_save_index(['files' => []]);

        json_out(['ok' => true, 'commit' => $commit, 'head' => $commitId]);
    }

    case 'log': {
        $repo = repo_commits();
        $limit = (int)($_GET['limit'] ?? 20);
        if ($limit <= 0 || $limit > 200) {
            $limit = 20;
        }
        $out = [];
        foreach (array_reverse($repo['commits']) as $c) {
            if (count($out) >= $limit) {
                break;
            }
            $out[] = [
                'id'      => (string)($c['id'] ?? ''),
                'message' => (string)($c['message'] ?? ''),
                'time'    => (int)($c['time'] ?? 0),
                'author'  => (string)($c['author'] ?? ''),
                'changes' => is_array($c['changes'] ?? null) ? $c['changes'] : [],
            ];
        }
        json_out(['ok' => true, 'head' => $repo['head'], 'commits' => $out,
                  'total' => count($repo['commits'])]);
    }

    default:
        fail('未知接口', 404);
}
}   // end if ($api !== '')

/* ============================== 页面 ============================== */

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$csrfJson = json_encode($CSRF);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>代码编辑器 - <?= htmlspecialchars(basename($SITE_ROOT), ENT_QUOTES, 'UTF-8') ?></title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/lib/codemirror.css">
<link rel="stylesheet" href="style.css">
</head>
<body>

<?php if (!$AUTH): ?>
<div class="login-wrap">
  <form class="login-card" id="login-form" autocomplete="off">
    <h1>代码编辑器</h1>
    <p class="muted">请输入访问密码</p>
    <?php if ($PASSWORD === ''): ?>
      <p class="error">服务端未配置 editor_password，请在 lg_config.php 中添加后刷新。</p>
    <?php else: ?>
      <input type="password" id="login-password" placeholder="密码" autofocus>
      <button type="submit">进入</button>
      <p class="error" id="login-error"></p>
    <?php endif; ?>
  </form>
</div>
<script>
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('login-password');
  const err = document.getElementById('login-error');
  const body = new FormData();
  body.append('password', input.value);
  const res = await fetch('?api=login', { method: 'POST', body });
  const data = await res.json().catch(() => ({}));
  if (data.ok) { location.reload(); } else { err.textContent = data.error || '登录失败'; }
});
</script>
<?php else: ?>

<div id="app">
  <aside id="sidebar">
    <div class="side-head">
      <span class="root-name"><?= htmlspecialchars(basename($SITE_ROOT), ENT_QUOTES, 'UTF-8') ?></span>
      <button id="btn-refresh" title="刷新文件列表">⟳</button>
    </div>
    <input id="filter" type="search" placeholder="筛选文件…" autocomplete="off">
    <ul id="file-list"></ul>
  </aside>

  <main id="main">
    <header id="toolbar">
      <button id="btn-menu" class="only-mobile" title="文件列表">☰</button>
      <span id="current-file" class="file-name">未选择文件</span>
      <span id="dirty-dot" class="dot" title="未保存"></span>
      <span class="spacer"></span>
      <button id="btn-save" title="保存 (Ctrl+S)">保存</button>
      <button id="btn-stage" title="把当前文件加入暂存区">暂存</button>
      <button id="btn-commit" title="提交暂存区的全部改动">提交</button>
      <button id="btn-delete" title="删除到回收站">删除</button>
      <button id="btn-trash" title="回收站">回收站</button>
      <button id="btn-logout" title="退出登录">退出</button>
    </header>

    <div id="editor-wrap">
      <textarea id="editor" spellcheck="false"></textarea>
      <div id="placeholder" class="placeholder">从左侧选择文件开始编辑</div>
    </div>

    <footer id="statusbar">
      <span id="status-text">就绪</span>
      <span class="spacer"></span>
      <span id="cursor-pos"></span>
      <span id="file-size"></span>
    </footer>
  </main>
</div>

<div id="trash-panel" class="panel hidden">
  <div class="panel-head">
    <strong>回收站</strong>
    <button id="btn-close-trash">关闭</button>
  </div>
  <ul id="trash-list"></ul>
</div>

<div id="toast" class="toast"></div>

<div id="rotate-tip">
  <div>请将手机横屏使用</div>
</div>

<script>window.LG_CSRF = <?= $csrfJson ?>;</script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/lib/codemirror.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/xml/xml.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/javascript/javascript.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/css/css.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/htmlmixed/htmlmixed.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/php/php.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/clike/clike.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/markdown/markdown.js"></script>
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.16/mode/python/python.js"></script>
<script src="app.js"></script>
<?php endif; ?>

</body>
</html>
