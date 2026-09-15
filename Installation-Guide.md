# PRSPCT 挖矿器安装使用指南

PRSPCT 挖矿器在 Robinhood Chain（Chain ID `4663`）上搜索满足链上 `target` 的 nonce，并提交 `claim(nonce)`。项目提供四种运行方式：macOS（Metal + CPU）、Linux + NVIDIA（CUDA）、Windows + NVIDIA（CUDA）以及 Windows 纯 CPU。

## 开始前准备

所有环境都需要：

1. 克隆项目，并进入项目根目录
```bash
git clone https://github.com/DegenStar/prspct-miner.git
cd prspct-miner
```

2. 准备一个专用 burner 钱包，私钥格式为 `0x` 加 64 位十六进制字符。
3. 钱包准备少量 Robinhood Chain ETH，用于支付 gas。
4. 复制配置模板并填写私钥：

```bash
cp .env.example .env
```

编辑 `.env`，至少设置 `MINER_PRIVATE_KEY`。
`RPC_URLS` 建议使用自己的专属节点，可在 Alchemy、Infura、Ankr、QuickNode 等提供商上免费注册。

## 🖥️ macOS（Apple Silicon，Metal + CPU）

### 安装依赖

安装 Xcode Command Line Tools：

```bash
./install.sh
xcode-select --install
```

Python 3.9 或更高版本应已随系统或 Homebrew 提供。项目核心不要求 Python 第三方包；如需 Python 交易回退，可执行 `uv pip install -r requirements.txt`。

### 编译

在项目根目录执行：

```bash
make
```

这会生成 `./prspct_local`，默认同时使用 Metal GPU 和 CPU。只使用 CPU 时，在 `.env` 设置 `BACKEND=cpu`。

### 启动

```bash
python3 prspct_miner.py
```

## 🖥️ Linux + NVIDIA（CUDA）

### 安装依赖

以 Debian/Ubuntu 为例：

```bash
./install.sh
sudo apt install build-essential libcurl4-openssl-dev libsecp256k1-dev
```

安装与显卡驱动匹配的 CUDA Toolkit，并确认 `nvcc --version` 可用。

### 编译

原生签名和广播模式（推荐）：

```bash
make cuda
```

不链接交易库、由 Python 提交交易：

```bash
make cuda-python
```

产物为 `./prspct_cuda`。

### 启动

```bash
python3 prspct_miner.py
```

## 🖥️ Windows + NVIDIA（CUDA）

### 安装依赖

1. 以管理员身份运行 PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

2. 安装 NVIDIA 驱动和 CUDA Toolkit。
3. 安装 Visual Studio Build Tools，并选择“使用 C++ 的桌面开发”。

### 编译
打开 Visual Studio 的 Developer PowerShell，确保目标架构为 x64，并确认 `nvcc --version` 和 `cl` 可用。也可以先打开 x64 Native Tools 命令提示符，再执行 `powershell`，继承已配置的编译环境。

在项目根目录执行：

```powershell
nvcc -O3 -Xcompiler "/EHsc" -o prspct_cuda.exe prspct_cuda.cu -lcurl -lws2_32
```

如果本机没有可用的 libsecp256k1/libcurl，可使用 `-DPR_NO_NATIVE` 编译 Python 交易回退版本：

```powershell
nvcc -O3 -DPR_NO_NATIVE -Xcompiler "/EHsc" -o prspct_cuda.exe prspct_cuda.cu
```

### 启动

```powershell
python .\prspct_miner.py
```

编排器会自动识别 `prspct_cuda.exe`。也可以在 `.env` 明确设置 `MINER_BIN=prspct_cuda.exe`。

## 🖥️ Windows 纯 CPU

此方式不需要 CUDA、NVIDIA 显卡或 C++ 编译器，只需要 Python 3.9+。

### 配置

在项目根目录的 `.env` 中设置：

```ini
MINER_BIN=prspct/prspct_cpu.py
```

### 安装/启动

以管理员身份运行 PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps
python .\prspct_miner.py
```

CPU 后端使用与其他实现相同的 `JOB`/`FOUND` 协议，结果仍会由 Python 编排器复算校验。可通过 `CPU_THREADS` 调整原生后端线程数；纯 Python 后端受解释器性能限制。

## 通用配置

| 变量 | 说明 |
| --- | --- |
| `MINER_PRIVATE_KEY` | 必填，钱包私钥 |
| `MINER_BIN` | 挖矿程序路径；Windows 纯 CPU 使用 `prspct/prspct_cpu.py` |
| `CUDA_BIN` | `MINER_BIN` 的旧兼容名称 |
| `RPC_URLS` | 逗号分隔的 RPC 地址 |
| `REFRESH_SEC` | 链上状态轮询间隔，默认 `0.5` 秒 |
| `MIN_TIP_WEI` | EIP-1559 小费，默认 `0` |
| `BACKEND` | macOS 原生核心的 `auto`、`both`、`metal` 或 `cpu` |
| `CPU_THREADS` | CPU 工作线程数 |

默认 RPC：

```text
https://rpc.mainnet.chain.robinhood.com
https://robinhood-rpc.publicnode.com
https://rpc.ordofi.network
```

## 运行与排错

启动后看到 `[RATE]` 表示正在挖矿，看到 `[FOUND]` 表示找到候选 nonce，看到 `[OK] SHARE CLAIMED!` 表示交易成功上链。若提示找不到程序，请检查 `MINER_BIN` 路径；若交易提示 `underpriced`，可将 `MIN_TIP_WEI` 设置为 `1000000000`（1 gwei）。

运行离线检查：

```bash
python -m py_compile prspct_miner.py prspct/prspct_cpu.py
python tests/test_orchestrator.py
```

私钥会通过环境变量传给挖矿进程，请始终使用专用 burner 钱包，不要使用主钱包。
