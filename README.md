# FileSync —— 仿 git 的文件同步

把本地 `local_files/` 当作工作区，用 git 的思维同步到远端站点根目录。
服务端另带一个 **在线代码编辑器**（`code/`），手机横屏也能用。

```
本地                                       服务器
────                                       ──────
local_files/  ── add → commit → push ──►   站点根目录
      ▲                                          │
      └────────────── pull（自动备份）───────────┘
```

***

## 它由什么组成

| 路径 | 是什么 | 放哪 |
| --- | --- | --- |
| `main.py` | 命令行客户端 | 本机 |
| `requirements.txt` | Python 依赖（requests / cryptography） | 本机 |
| `keys/` | 两对 RSA 密钥 | 一半本机、一半服务器 |
| `local_files/` | 工作区（要同步的网站文件） | 本机 |
| `client_config.json` | 远端接口地址 | 本机 |
| `.filesync/` | 本地仓库：暂存区 / 提交历史 / 对象库 / 备份 | 本机（自动生成） |
| `FileSync_Server/api.php` | 服务端同步接口 | 站点根 |
| `FileSync_Server/code/` | 在线代码编辑器 | 站点根 `code/` |
| `FileSync_Server/nginx.conf.example` | nginx 配置片段 | 服务器 |

***

## 快速开始

```bash
# 1. 依赖
pip install -r requirements.txt

# 2. 生成密钥（输出会告诉你哪个文件放哪里）
python main.py --genkeys

# 3. 部署服务端：把 api.php 和 code/ 传到站点根，密钥传到 lg_keys/

# 4. 配置远端地址（二选一）
#    a) 写进 client_config.json：  {"server_url": "https://你的域名/api.php"}
#    b) 每次用参数：               python main.py --url https://... --ping

# 5. 自检
python main.py --ping
```

`--ping` 里重点看两行：`features` 是否包含 `git`，`api_build` 是否和你本地一致。
对不上说明服务器上还是旧版 `api.php`。

***

## 命令

| 命令 | 作用 |
| --- | --- |
| `python main.py` | 打开 tkinter 图形界面（`gui` 子命令同效） |
| `python main.py pull` | 拉取远端文件到 `local_files/`，覆盖前自动备份到 `.filesync/backups/<时间>/` |
| `python main.py status` | 查看工作区 / 暂存区状态 |
| `python main.py add [路径…]` | 暂存改动（不带参数 = 全部） |
| `python main.py commit -m 说明` | 生成提交（自动生成 commit id；多词可直接跟，不必加引号） |
| `python main.py push` | 推送本地提交（文件 + 提交信息 + commit id） |
| `python main.py check <id>` | 查看某次提交：提交信息 + 文件改动（绿色 `+X` / 红色 `-Y`） |
| `python main.py check list [N]` | 查看提交记录，默认最近 20 条 |
| `python main.py diff [路径]` | 查看暂存区相对 HEAD 的行级差异 |
| `python main.py rm <路径…>` | 删除工作区文件（备份到 `.filesync/trash/`）并暂存删除 |
| `python main.py restore <路径> [--from ID]` | 从某次提交恢复文件（默认 HEAD） |
| `python main.py --ping` / `--list` | 连通性自检 / 列出远端文件 |
| `python main.py --genkeys [--force]` | 生成 / 重新生成密钥 |

### 典型流程

```bash
python main.py pull                      # 先把远端拉下来（会备份本地改动）
# …编辑 local_files/ 里的文件…
python main.py status                    # 看看改了什么
python main.py add                       # 暂存
python main.py commit -m "首页改版"       # 提交
python main.py push                      # 推上去
python main.py check list 10             # 看看最近 10 条
python main.py check a1b2c3d4e5f6        # 看某次提交的文件改动
```

`check` 的输出示例：

```
commit a1b2c3d4e5f6
Author: client
Date:   2026-10-16 12:00

    首页改版

变更文件：
  M index.html
      +12  -3
  A css/app.css
      +40  -0
  D old.html
      +0  -25
```

## 图形界面

`python main.py`（无参数）打开 tkinter 界面：

- 顶部：连接测试 / 拉取 / 刷新状态
- 左侧：工作区状态列表（待提交 / 未暂存 / 未跟踪，彩色标记）
- 右侧：提交信息、暂存选中、暂存全部、提交、推送、提交历史
- 底部：实时操作日志
- 「提交历史」窗口双击某行可看该次提交的 `+X / -Y`

所有耗时操作（pull / push / 扫描）都在后台线程执行，界面不会卡住。

代码结构：

```
main.py              入口
filesync/config.py   路径与常量
filesync/client.py   签名请求 / 密钥
filesync/diff.py     行级 diff
filesync/workspace.py 扫描 / 本地仓库
filesync/ops.py      业务操作
filesync/cli.py      命令行
filesync/gui.py      tkinter 界面
```

***

## 在线代码编辑器

访问 `https://你的域名/code/`。

### 配置密码（必须）

在站点根的 `lg_config.php` 里加一项（没有该文件就新建）：

```php
<?php
return [
    // 明文或 password_hash() 的结果都可以
    "editor_password" => "换成一个足够长的密码",
    // "editor_password" => '$2y$10$....',
];
```

生成 hash：

```bash
php -r "echo password_hash('你的密码', PASSWORD_DEFAULT), PHP_EOL;"
```

未配置密码时编辑器**拒绝访问**（安全默认）。

### 能做什么

- 浏览站点根下除受保护文件外的所有文件
- 代码高亮（CodeMirror，无自动补全）、等宽字体、`Ctrl+S` 保存
- 复制 / 粘贴 / 剪切（浏览器原生）
- 删除文件 → `.lgtrash/` 回收站，可一键复原
- 暂存改动 → 提交 commit（与客户端共用同一套 `.lgrepo/` 历史）
- 手机横屏可用（竖屏会提示旋转，文件列表可折叠）

### 不能编辑的（受保护）

```
api.php  lg_config.php  .lgrepo/  .lgtrash/  ignored/  .lgstate/
lg_keys/  *.pem  .htaccess  .user.ini
```

### nginx（重要）

把 `nginx.conf.example` 的规则加到站点配置里。**必须包含**：

```nginx
location ~ ^/(ignored|\.lgstate|\.lgrepo|\.lgtrash)/ { deny all; }
location ~ \.pem$ { deny all; }
```

`.lgrepo/` 里存着全站文件的内容快照，能访问它等于源码泄露。

***

## 数据存在哪

**本地** `.filesync/`

```
index.json    暂存区
commits.json  head / pushed / head_manifest / 提交列表
objects/      按 sha256 存放的文件内容快照
backups/      pull 覆盖前的备份
trash/        rm 删除文件的备份
```

**服务端**（站点根）

```
.lgrepo/commits.json   提交历史（含每次提交的 manifest）
.lgrepo/index.json     编辑器暂存区
.lgrepo/objects/       文本文件内容快照（≤2MB）
.lgtrash/              编辑器删除的文件 + index.json
```

客户端 `push` 会先上传文件内容，再调 `git_commit` 登记提交；
服务端会校验改动文件的实际 sha256 与清单一致，避免"记录说改了、文件没传上来"。

***

## 安全提醒

1. **`api.php` 是受保护文件**，同步工具永远不会覆盖它 —— 改了要手动上传。
2. 密钥目录建议放在**站点根之外**（如 `../lg_keys`），并加进 `open_basedir`。
3. 不要 `--genkeys --force` 之后忘记更新服务器上的两个 pem，否则全部 401。
4. 服务器时间偏差超过 300 秒会全部 401。
5. 在线编辑器使用 session 登录，请务必用 HTTPS。

***

## 常见问题

| 现象 | 原因 |
| --- | --- |
| `unknown_action` | 服务端 `api.php` 是旧版，去传新的 |
| `server_not_configured (503)` | 密钥目录不存在/不可读，或被 `open_basedir` 挡住 |
| `unauthorized (401)` | 客户端与服务端密钥不配对、时间偏差过大、或 nonce 被重放 |
| `conflict (409)` | 服务端有新提交，先 `pull` 再 `push` |
| `sync_conflict (409)` | 服务器文件与提交清单不一致，重新 `push` 或先 `pull` |
| `body_too_large (413)` | 调大 nginx 的 `client_max_body_size`（客户端会自动降档重试） |
| 编辑器打不开 / 一直要求密码 | 没配 `editor_password`，或密码错误次数过多（重启浏览器会话） |
