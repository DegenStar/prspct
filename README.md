# PRSPCT GPU 挖矿器

面向 **Robinhood Chain 主网（Chain ID `4663`）** 上 PRSPCT 合约的原生 GPU 挖矿程序。用 CUDA 跑 keccak-256 暴力搜索，命中后直接签名并广播 `claim(nonce)` 交易。

- **合约地址**：`0xd078008c3D887A52CE722A3cA0539cA1F4971dD1`
- **官网**：https://prspct.xyz
- **市场（OpenSea）**：https://opensea.io/collection/prspct
- **纯汗挖矿**：`value = 0`、`maxPriorityFeePerGas = 0`，除了 gas 不花任何钱
- **双模式提交**：C++ host 端原生签名广播（libsecp256k1 + libcurl），或退回到 Python 提交

---

## 工作原理

矿工要找一个 `uint256 nonce`，使得下面这个哈希小于链上当前 target：

```
hash = keccak256(abi.encodePacked(bytes32 seed, address sender, uint256 nonce))
```

- `seed` 每个 epoch（或 target 变化时）由合约的 `state()` 给出
- `sender` 是你的钱包地址，所以**每个人要搜的空间不同，share 无法转发**
- 消息一共 84 字节，恰好塞进一个 keccak 区块（rate 136），所以每算一个哈希只需要**一次** Keccak-f 置换
- nonce 占 32 字节，其中高 24 字节恒为 0，实际只扰动低 8 字节（每个线程线上递增）

命中后向合约发送 `claim(nonce)`：

```
selector = keccak256("claim(uint256)")[:4] = 0x379607f5
```

合约会自行验证哈希是否低于 target，然后把 share 记到你名下（`depth` 递增，上限 8888）。

---

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `prspct_cuda.cu` | CUDA 挖矿核心。单区块 keccak 模板搜索，stdin/stdout 行协议，可选原生发交易 |
| `prspct_miner.py` | Python 编排层。轮询合约状态、下发任务、校验 GPU 结果、Python 兜底提交 |
| `prspct_tx.h` | Header-only C++17 交易模块。主机端 keccak-256、RLP 编码、EIP-1559 签名、多 RPC 并发广播 |

---

## 环境要求

**编译 native 模式（推荐）**

- CUDA Toolkit（`nvcc`）
- `libsecp256k1`（开发包）
- `libcurl`（开发包）
- 支持 CUDA 的 NVIDIA 显卡

**纯 Python 模式（不装 libsecp256k1 / libcurl）**

- CUDA Toolkit + 显卡

**运行依赖**

```bash
pip install -r requirements.txt
```

> 请按 `requirements.txt` 安装：`web3` 7.x 要求 `eth-account>=0.13.6`，若环境里残留旧版
> `eth-account`，启动时会直接报 `ImportError: cannot import name 'SignedSetCodeAuthorization'`。

系统包（Debian/Ubuntu 示例）：

```bash
sudo apt install build-essential libsecp256k1-dev libcurl4-openssl-dev
```

---

## 编译

```bash
# 完整版：原生签名 + 广播
nvcc -O3 -arch=native -o prspct_cuda prspct_cuda.cu -lsecp256k1 -lcurl -lpthread

# 精简版：不带 libsecp256k1 / libcurl，交易改由 Python 发送
nvcc -O3 -arch=native -DPR_NO_NATIVE -o prspct_cuda prspct_cuda.cu
```

> 编译产物 `prspct_cuda` 需要和 `prspct_miner.py` 在同一目录，或用 `CUDA_BIN` 指定路径。

---

## 运行

**方式一：`.env` 文件（推荐）**

```bash
cp .env.example .env
$EDITOR .env          # 至少填 MINER_PRIVATE_KEY
python3 prspct_miner.py
```

脚本启动时会自动加载**与 `prspct_miner.py` 同目录**的 `.env`（也可直接把变量 export 出来）。
已经存在于 shell 环境中的变量优先级更高，所以 `MINER_PRIVATE_KEY=0x... python3 prspct_miner.py`
会覆盖文件里的值。`.env` 已写入 `.gitignore`，**里面是私钥，请勿提交**。

**方式二：直接 export**

```bash
export MINER_PRIVATE_KEY=0x<你的 64 位十六进制私钥>
python3 prspct_miner.py
```

两种方式设置的环境变量都会原样传给 `prspct_cuda` 子进程，因此 native 模式同样生效。
若没装 `python-dotenv`，脚本会打印一条警告并照常使用 shell 环境变量。

钱包里至少要留一点 ETH 付 gas（低于 `0.001 ETH` 时脚本会警告）。**建议使用一次性 burner 钱包**，因为私钥会出现在环境变量里。

### 环境变量

> 下表中的变量既可以通过 `.env` 提供，也可以直接 export；shell 环境变量优先级更高。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MINER_PRIVATE_KEY` | 无（必填） | `0x` + 64 位十六进制私钥 |
| `RPC_URLS` | 3 个公共主网 RPC | 逗号分隔，启动时随机打乱顺序 |
| `CUDA_BIN` | `./prspct_cuda` | 挖矿二进制路径 |
| `REFRESH_SEC` | `0.5` | 状态轮询间隔（秒） |
| `MIN_TIP_WEI` | `0` | `maxPriorityFeePerGas`（wei）。默认 0 = 纯汗；仅当 RPC 拒收 0 tip 交易时才需要调高 |

默认 RPC：

```
https://rpc.mainnet.chain.robinhood.com
https://robinhood-rpc.publicnode.com
https://rpc.ordofi.network
```

---

## CUDA 二进制行协议

`prspct_miner.py` 通过 stdin/stdout 与 `prspct_cuda` 通信，也可以单独驱动它：

**输入（stdin）**

```
JOB <seed_hex64> <sender_hex40> <target_hex64>   # 新任务
TX  <txNonce> <maxFeeWei>                        # 每轮刷新交易参数
STOP                                             # 暂停挖矿
```

**输出（stdout）**

```
INFO device <型号> sm=<计算能力> SMs=<SM 数>
INFO txmode native|python ...
INFO job accepted
RATE <hashes_per_sec>                             # 每 2 秒上报一次
FOUND <nonce_decimal> <hash_hex64>
SENT  <txhash> <nonce> <txNonce>                  # native 模式
TXRES ok|err <ms> <url> [msg]
```

### 原生提交 vs Python 兜底

- 设置了 `MINER_PRIVATE_KEY` 并且编译时链接了 libsecp256k1/libcurl → **native 模式**，CUDA 程序自己构建并广播交易，省掉 Python 往返，抢块更快。
- 其他情况 → **python 模式**，`prspct_cuda` 只报 `FOUND`，由 `prspct_miner.py` 签名发送。

无论哪种模式，Python 层都会用 `Web3.keccak` 本地复算 GPU 报的哈希，不一致就直接丢弃（防止 GPU 结果被伪造或算错）。

### 关于 gas tip

默认 `maxPriorityFeePerGas = 0`（纯汗挖矿，只付 gas）。如果日志里出现大量
`TXRES err ... underpriced` 或 `tip too low`，说明节点要求非零小费，此时设置
`MIN_TIP_WEI`（例如 `export MIN_TIP_WEI=1000000000` 即 1 gwei）即可，native 与 Python 两种模式都会生效。

---

## 日志速查

| 日志 | 含义 |
| --- | --- |
| `[*] balance=... ETH` | 启动时读取的钱包余额 |
| `[STATE] seed/target changed` | seed 或 target 变化，已下发新任务 |
| `[RATE] ... GH/s` | 实时算力、当前 target 位数、按平均概率估算的等待时间 |
| `[FOUND] nonce=...` | 找到满足条件的 nonce，正在提交 |
| `[TX] sent ...` | 交易已广播 |
| `[OK] SHARE CLAIMED!` | 交易上链成功，share 已入账 |
| `[RPC] ... pause ...` | RPC 报错（如 429 限流），自动切换节点并退避 |
| `[!] GPU/CPU hash mismatch` | GPU 结果校验失败，已跳过 |
| `[!] CUDA process died` | 挖矿进程退出，自动重启并重新下发任务 |

---

## 常见问题

**`no binary at ./prspct_cuda`**
编译产物不在当前目录，用 `CUDA_BIN` 指定完整路径。

**`txmode python` 但想要原生提交**
确认 `MINER_PRIVATE_KEY` 已导出，且编译时**没有**加 `-DPR_NO_NATIVE`，同时 libsecp256k1 与 libcurl 链接成功。

**频繁出现 429 / RPC 超时**
多填几个 `RPC_URLS`，脚本会轮换并做指数退避；也可以换自建节点。

**交易报 nonce 冲突**
脚本会自动重读 `pending` nonce 并重试（Python 模式最多 3 次，native 模式带自动 resync），一般无需干预。

**算力低于预期**
`blocks = SM 数 × 64`、`threads = 256`、每线程 64 个 nonce。可以自行调大，注意观察 `RATE` 与显卡温度。

---

## 相关链接

| 名称 | 链接 |
| --- | --- |
| 官网 | https://prspct.xyz |
| OpenSea 市场 | https://opensea.io/collection/prspct |
| 本仓库 | https://github.com/DegenStar/prspct |

---

## 风险提示

- 私钥通过环境变量传递，会出现在进程环境中，**请务必使用专用 burner 钱包**，不要用主钱包。
- 挖矿结果取决于链上 target 难度与全网算力，收益不保证。
- 请自行确认当地对加密资产及挖矿的合规要求。
