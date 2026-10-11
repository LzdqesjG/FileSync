# File Sync - Client

把一个本地目录（`local_files/`）同步到远端站点，并提供双端文件的**按行对比**。
带 **RSA-2048 双向签名**：没有客户端私钥的人，无法让远端 `api.php` 执行任何操作、
也拿不到任何数据。

配套的服务端只有一个 PHP 文件（`FileSync_Server/api.php`），扔到站点根目录即可，
不需要数据库、不需要框架。

> 想说清楚的一件事：**这不是"云盘客户端"**。它面向的场景是
> 「我本地有一个网站的目录，我要把它推到我的服务器上，并且能核对两边到底差在哪」。
> 多余的文件不会删，而是被移进远端的 `ignored/` 归档目录，方便随时找回。

***

## 目录

- [它由什么组成](#它由什么组成)
- [快速开始](#快速开始)
- [第 1 步：装客户端](#第-1-步装客户端)
- [第 2 步：生成密钥](#第-2-步生成密钥)
- [第 3 步：部署服务端](#第-3-步部署服务端)
- [第 4 步：自检](#第-4-步自检)
- [使用](#使用)
- [命令行参考](#命令行参考)
- [它是怎么工作的](#它是怎么工作的)
- [出错时怎么查](#出错时怎么查)
- [什么会被同步，什么不会](#什么会被同步什么不会)
- [已知限制](#已知限制)

***

## 它由什么组成

| 路径                                      | 是什么                   | 放哪              |
| --------------------------------------- | --------------------- | --------------- |
| `main.py`                               | 客户端（PyQt6 图形界面 + 命令行） | 你本机             |
| `requirements.txt`                      | Python 依赖             | 你本机             |
| `keys/`                                 | 密钥目录（4 个 pem 文件）      | 一半在你本机，一半要传到服务器 |
| `local_files/`                          | **要被同步上去的目录**         | 你本机             |
| `client_config.json`                    | 远端接口地址                | 你本机             |
| `FileSync_Server/api.php`               | 服务端全部逻辑               | 服务器站点根目录        |
| `FileSync_Server/lg_config.example.php` | 服务端可选配置               | 服务器（可选）         |
| `FileSync_Server/nginx.conf.example`    | nginx 配置片段            | 服务器             |

两条线的分工：

```
你本机                                    服务器
──────                                    ──────
local_files/  ──┐
                ├─ 签名请求 ──────────────► api.php ──► 站点根目录
keys/           │                          ▲
                └─ 验签响应 ◄──────────────┘
```

***

## 快速开始

```bash
# 1. 装依赖
pip install -r requirements.txt

# 2. 生成密钥（会告诉你哪个文件放哪里）
python main.py --genkeys

# 3. 按下面"第 3 步"把服务端部署好，然后自检
python main.py --ping

# 4. 打开界面
python main.py
```

`--ping` 打印 `[成功] 连通性与双向签名校验通过` 就说明两边都通了。

> 第一次打开图形界面时，如果发现 `local_files/` / `keys/` / `client_config.json`
> 不齐，会弹一个初始化向导，让你从当前目录里挑文件移进 `local_files/`。
> 详见[第 2 步](#第-2-步生成密钥)之后的说明。

***

## 第 1 步：装客户端

需要 **Python 3.10 或更高**（开发环境是 3.13.5），**不建议** 使用 **3.14** 或更高的版本。

```bash
pip install -r requirements.txt
```

三个直接依赖：`PyQt6`（界面）、`requests`（网络）、`cryptography`（签名）。
不用虚拟环境也能跑，但建议用。

***

## 第 2 步：生成密钥

```bash
python main.py --genkeys
```

生成 **两对** RSA-2048 密钥到 `keys/`：

| 文件                   | 干什么用         | **放哪里**                   |
| -------------------- | ------------ | ------------------------- |
| `client_private.pem` | 给你的每个请求签名    | **只留在本机。绝对不能给别人、不能传到服务器** |
| `client_public.pem`  | 服务端用它验证你的签名  | 传到服务器的密钥目录                |
| `server_private.pem` | 服务端用它给响应签名   | 传到服务器的密钥目录                |
| `server_public.pem`  | 本机用它验证服务端的响应 | **只留在本机**                 |

想要重新生成：`python main.py --genkeys --force`
（**旧密钥立即失效**，服务端上那两个文件必须同步换掉，否则全部 401。）

> 密钥已经存在时 `--genkeys` 不会覆盖，只会提示你。

### 初始化向导

每次打开图形界面都会检查一遍本地结构。以下三项**缺任一项**就会弹窗：

```
local_files/          要被同步上去的目录
keys/                 且里面要有 client_private.pem 与 server_public.pem
client_config.json    远端接口地址
```

点「确定」后会弹出当前目录的**文件列表**，勾选要放进 `local_files/` 的条目，
确认后就会：建目录 → 补配置（默认地址 `https://example.com/file_sync/api.php`）
→ 补密钥 → 把勾中的条目**移动**进 `local_files/`。

列表里的三类条目：

| 类别                                               | 样子          | 能不能勾           |
| ------------------------------------------------ | ----------- | -------------- |
| 正在运行的本文件、`client_config.json`                    | 不显示         | —              |
| `local_files/`、`keys/`、`FileSync_Server/`、`.git` | 灰色 + ⛔ + 原因 | **不能**（勾选框都不给） |
| 被 `.gitignore` 标记的条目                             | **橙色**      | 能，但默认不勾 —— 请谨慎 |
| 其余                                               | 普通          | 能，默认不勾         |

底部有一行橙色提示：`🟠 橙色标注的文件被 .gitignore 标记，请谨慎勾选`。
`.gitignore` 支持注释、`!` 反选、`*.log` 通配、`build/output` 带斜杠路径。
**项目里没有** **`.gitignore`** **时会退回一份内置清单**（`.venv`/`__pycache__`/`*.pyc`…），
并在提示里如实说明。

⚠️ **移动是真正的移动**，原位置不再保留；目标已有同名文件时会**跳过、不覆盖**。
不放心就先自己备份。

***

## 第 3 步：部署服务端

服务器需要 **PHP 8+**（开发环境 8.2.32）和 nginx。以下以宝塔面板为例。

### 3.1 放 `api.php`

上传到**站点根目录**（和 `index.html` 同级），确认能通过
`https://你的域名/api.php` 访问到。

> ⚠️ `api.php` 是**受保护路径**，同步工具**不会覆盖它**。
> 以后每次改了它，都要**手动重新上传**，否则服务器上跑的还是旧版。

### 3.2 放密钥

推荐把密钥目录放在**站点根之外**（这样 nginx 根本访问不到）：

```
/www/wwwroot/lg_keys/                ← 站点根的上一级
├── server_private.pem               ← 从你本机 keys/ 传上来
├── client_public.pem                ← 从你本机 keys/ 传上来
└── .lgstate/                        ← api.php 自动创建（防重放的 nonce 缓存）
```

`server_public.pem` 和 `client_private.pem` **不要传**。

`api.php` 按这个顺序找密钥目录，取第一个"存在且可读"的：

1. `lg_config.php` 里配的 `key_dir`
2. 环境变量 `LG_KEY_DIR`
3. **站点根的上一级** **`/lg_keys`** ← 推荐
4. 站点根内的 `/lg_keys`、`/.lg_keys` ← 需要下面 3.3 显式允许，且 nginx 必须 deny

### 3.3 `lg_config.php`（可选）

不是必需的。需要时才把 `lg_config.example.php` 复制成 `lg_config.php`，
放到 `api.php` 同目录：

```php
return [
    // "key_dir" => "/www/wwwroot/lg_keys",   // 填了就只用这个目录
    "allow_keydir_in_docroot" => true,        // 允许密钥放在站点根内（需先 nginx deny）
    // "debug" => true,                       // 致命错误带上文件与行号（排查完改回 false）
];
```

### 3.4 权限（**两个坑，请照做**）

密钥目录的属主必须是 PHP 运行用户（宝塔默认 `www`），**并且需要写权限** ——
因为 `api.php` 要在里面建 `.lgstate/` 缓存来防重放。

```bash
chown -R www:www /www/wwwroot/lg_keys
chmod 740 /www/wwwroot/lg_keys
```

> **坑 1**：`chown` **不带** **`-R`** 只改目录、不改里面的文件，会导致 `api.php` 读不到密钥。
> 一定要带 `-R`。
>
> **坑 2**：宝塔/cPanel 默认给站点开着 **`open_basedir`（防跨站攻击）**，
> 此时 PHP 访问不到站点根之外的目录，密钥目录会解析失败并返回
> `server_not_configured (503)`。二选一：
>
> - 宝塔「网站 → 设置 → 配置文件」，在 `open_basedir` 末尾追加
>   `:/www/wwwroot/lg_keys`，保存后重载 nginx
> - 或「网站 → 设置 → 网站目录」，关掉「防跨站攻击(open\_basedir)」

### 3.5 nginx

把 `nginx.conf.example` 里的内容加到站点配置的 `server { ... }` 块里。

⚠️ **必须放在宝塔默认那两段** **`location`** **之前**（nginx 的正则 location 是
「按先后顺序，先匹配到的先生效」），否则不生效：

```nginx
client_max_body_size 8m;                          # 分片上传的请求体上限
location ~ ^/(ignored|\.lgstate)/ { deny all; }   # 禁止访问归档与状态目录
location ~ \.pem$ { deny all; }                   # 双保险：禁止访问密钥
```

里面还带了缓存策略（`js|css|html` 永不缓存、媒体 30 天缓存）和 gzip 配置，
细节看文件里的注释。

***

## 第 4 步：自检

```bash
python main.py --ping        # 或临时指向别处：python main.py --url https://... --ping
```

会依次校验：能不能连上 → 服务端密钥配置对不对 → 双向签名能不能互相验通。

看重两点：

- `[成功] 连通性与双向签名校验通过` —— 通了
- `api_build: 2026-10-03.1` —— **服务端跑的是哪一版**。
  如果这里显示的版本和你本地的 `FileSync_Server/api.php` 对不上，
  说明**服务器上还是旧** **`api.php`**（这也是很多怪问题的根因）。

***

## 使用

`python main.py` 打开界面，左侧三个入口。

### 上传文件

```
local_files/  →  远端站点根目录
```

点「扫描两端」先看差异，再点「上传并归档」。流程是：

1. 扫两边，列出要上传 / 要归档的
2. **刷新页面里的静态资源版本号**（可关，见下）
3. 重新计算哈希（保证"内容 + 哈希"一致）
4. 分批上传，同名覆盖
5. 远端多出来的文件 → 移进 `ignored/`（不删）

两个勾选框（都在上传页，默认都开）：

| 勾选框                | 作用           |
| ------------------ | ------------ |
| 跳过内容完全相同的文件（推荐）    | 哈希相同就不传，省流量  |
| 自动刷新静态资源版本号（`?v=`） | 见下面「它是怎么工作的」 |

### 文件对比

按行对比两端同名文件，自研的 LCS 行级 diff：
先裁掉公共前后缀，再对中间部分跑动态规划，最后把操作块合并成连续区块。
只在一端存在的文件会明确标出来（远端独有的会被归档、本地独有的会被上传）。

### 设置

右上角「设置」里可以：

- 改**远端接口地址**（保存后写入 `client_config.json`，上传与对比立即生效）
- 直接跑 4 个快捷命令：`--ping` / `--list` / `--genkeys` / `--genkeys --force`

***

## 命令行参考

```bash
python main.py                      # 打开图形界面
python main.py --genkeys            # 生成两对密钥（已存在时不覆盖）
python main.py --genkeys --force    # 强制重新生成（旧密钥立即失效）
python main.py --ping               # 自检：连通性 + 双向签名 + 服务端配置
python main.py --list               # 列出远端文件
python main.py --upload             # 一键上传：同步 local_files/ 到远端并归档多余文件
python main.py --url URL ...        # 临时指定接口地址（不写入配置）
```

***

## 它是怎么工作的

### 双向签名

每个请求都带三个头：`X-LG-Timestamp`、`X-LG-Nonce`、`X-LG-Signature`。

```
请求规范串 = "lg1\n" + action + "\n" + 时间戳 + "\n" + nonce + "\n" + sha256(请求体)
请求签名   = RSA-SHA256(你的 client_private.pem, 规范串)

响应规范串 = "lgresp1\n" + nonce + "\n" + sha256(响应体)
响应签名   = RSA-SHA256(服务端的 server_private.pem, 规范串)   ← 你用 server_public 验
```

- 服务端缓存用过的 nonce，**重复使用直接拒绝**（防重放）
- 时间偏差超过 **300 秒**就拒绝 —— 所以**服务器时间必须准**
- 签名不对的请求，`api.php` 不会执行任何操作、不会返回任何数据

### 分片上传

大文件会**按字节切片**，每片一个请求，服务端累积到 `.lgpart` 临时文件，
最后一片校验总大小 + 整体 sha256，再原子改名成正式文件。

被 `413` 拒绝时（服务器或 nginx 的请求体上限更低），客户端会**自动降档重试**：

```
2 MiB → 1 MiB → 512 KiB → 256 KiB → 128 KiB
```

降下来的档位本次会话内记住，不会反复试探。

### 静态资源版本号

上传前会给页面里的本地资源自动加 `?v=<文件内容 sha256 前 12 位>`：

```
liquid_glass.css?v=d7ea8fcfd2a6
bg.webp?v=3395772cace8
fetch('bg.lrc?v=300baecd54f7')
```

好处是：**内容不变 → URL 不变 → 浏览器一直用缓存；内容一改 → URL 自动变 → 立刻刷新**，
不用手动强刷，也不用把 `Cache-Control` 设成永不缓存。

覆盖三处：标签的 `href`/`src`、内联 `<style>` 里的 `url(...)`、
以及内联 `<script>` 里的字符串（`fetch('bg.lrc')` 这种）。
外部链接、`data:`、`#锚点`、`<a href>` 都不会碰。

***

## 出错时怎么查

遇到问题的第一件事：**`python main.py --ping`，看** **`api_build`**。

| 现象                              | 原因 / 怎么办                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `服务端返回了非 JSON 内容（HTTP 503）`     | 服务器上 PHP 的 warning 污染了输出。`api.php` 已经用输出缓冲兜住这种情况；若仍出现，多半是**密钥目录或权限不对**（见 3.4）                                            |
| `server_not_configured (503)`   | 密钥目录解析失败。检查 `open_basedir`、目录属主、以及密钥文件是否真的放对了位置                                                                          |
| `unauthorized (401)`（全部请求都 401） | ① 本机和服务器的**时间差超过 5 分钟**；② 服务端上的 `client_public.pem` / 和你本机 `client_private.pem` 不是同一对；③ 你用了 `--genkeys --force` 但忘了更新服务端 |
| `请求体过大（body_too_large，413）`     | 调大 nginx 的 `client_max_body_size`（客户端会自动降档，但调大能少发很多请求）                                                                   |
| `unknown_action (400)`          | **服务端** **`api.php`** **是旧版**，去传新的                                                                                       |
| 只显示了版本号、没有排障信息                  | 服务器上跑的还是旧 `api.php`（新版会带 `api_build` 标记）                                                                                 |
| 密钥读不出来 / `.lgstate` 建不了         | `chown` 忘了带 `-R`。用 `chown -R www:www <密钥目录>`                                                                             |
| 大文件上传报错说"服务端 api.php 可能不是最新版"   | 同上，是 `api.php` 没更新 —— 旧版不支持分片，会静默写出空文件，所以客户端宁可拒绝                                                                         |

服务端返回的错误码有一份**中文文案映射**在客户端里（`_describe_error`）；
如果你改了 `api.php` 的错误码，记得同步改它。

***

## 什么会被同步，什么不会

**会被同步**：`local_files/` 下的**所有文件**（含子目录）。

**永远不会被覆盖、也不会被归档**（服务端的受保护路径）：

```
api.php    lg_config.php    .user.ini    .htaccess    .well-known    404.html    lg_keys
```

**永远不会被列出 / 归档 / 写入**：`ignored/`、`.lgstate/`、
以及上传过程中的临时文件（`.lgpart`、`.lgtmp.`）。

### ⚠️ 一个安全提醒

**不要把** **`keys/`** **放进** **`local_files/`。**

`api.php` 的 `lg_is_reserved()` 拦的是**顶层目录名**（它认识 `lg_keys`，但不认识 `keys`），
所以放在 `local_files/keys/` 下的 `client_private.pem` **会被真的上传到站点根**。
阻止它被下载的防线是 nginx 的 `location ~ \.pem$ { deny all; }` —— 请务必部署。

初始化向导已经把 `keys` 列为 ⛔ 禁止移动，但别手动搬。

***

## 已知限制

- **多余的文件是"归档"不是"删除"** —— 移进远端 `ignored/`。磁盘会慢慢涨，
  隔段时间自己去清理。
- **不做增量 diff 上传** —— 文件只要内容变了就是整份传（大文件走分片）。
- **对比是"按行"的** —— 不做字符级 diff；超大文件（超过 `MAX_DIFF_CELLS`）会退化成
  整块替换，不做精细对齐。
- **`api.php`** **需要手动部署** —— 它是受保护路径，同步工具不会覆盖它，这是刻意的。
- 远程请求走 HTTPS；如果站点是纯 HTTP，签名仍在但内容会明文传输，**不要这么用**。

***

## 内部实现

每个参数的含义、踩过的坑、协议的完整字段、`api.php` 的全部错误码，
见 [`local_files/DEVELOP.md`](local_files/DEVELOP.md)。
