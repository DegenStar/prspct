# ⛏️ PRSPCT 挖矿器

PRSPCT 挖矿器在 Robinhood Chain 主网（Chain ID `4663`）上搜索满足链上 `target` 的 nonce，并提交 `claim(nonce)` 交易。

- 项目官网：🔗 https://prspct.xyz

## 功能

- 使用 Keccak-256 计算 `seed + sender + nonce` 哈希。
- 支持 macOS Apple Silicon 的 Metal + CPU 后端。
- 支持 Linux + NVIDIA 和 Windows + NVIDIA 的 CUDA 后端。
- 支持 Windows 纯 CPU 后端（无需 CUDA 或 NVIDIA 显卡）。
- 支持原生交易签名广播，也支持 Python 交易回退模式。
- Python 编排器会轮询链上状态、下发任务并校验挖矿结果。

## 安装与使用

不同系统的安装、编译、配置和启动步骤请参阅：

📖 [安装使用指南.md](Installation-Guide.md)

指南覆盖以下环境：

- macOS（Apple Silicon，Metal + CPU）
- Linux + NVIDIA（CUDA）
- Windows + NVIDIA（CUDA）
- Windows 纯 CPU

## 项目文件

| 文件 | 说明 |
| --- | --- |
| `prspct_miner.py` | Python 编排器：轮询状态、分发任务、校验结果、提交交易 |
| `prspct_cuda.cu` | CUDA 挖矿核心，适用于 NVIDIA 显卡 |
| `prspct_local.mm` | macOS Metal + CPU 挖矿核心 |
| `prspct/prspct_cpu.py` | 便携式纯 Python CPU 挖矿后端 |
| `prspct_tx.h` | C++ 原生签名、交易编码和 RPC 广播模块 |
| `prspct_keccak.py` | Python Keccak-256 实现 |
| `prspct_eth.py` | Python 地址派生和校验和工具 |
| `tests/` | 离线测试与协议测试 |

## 工作原理

矿工搜索满足以下条件的 `nonce`：

```text
keccak256(abi.encodePacked(bytes32 seed, address sender, uint256 nonce)) < target
```

找到候选结果后，程序会在提交前再次校验哈希。合约地址为：

```text
0xd078008c3D887A52CE722A3cA0539cA1F4971dD1
```

## 安全提示

请使用专用 burner 钱包，不要使用主钱包。私钥通过环境变量传递给挖矿进程，`.env` 文件已加入 `.gitignore`，不要提交到仓库。

## 相关链接

- 官网：https://prspct.xyz
- X：
- OpenSea：https://opensea.io/collection/prspct
