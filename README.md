# mdnsmap

`mdnsmap` 是一个使用 Go 编写的 mDNS/DNS-SD 资产发现 CLI。它在指定网卡的本地二层网络中发送标准 mDNS 查询，解析 `PTR`、`SRV`、`TXT`、`A`、`AAAA` 记录，并按 CIDR 与服务端口范围过滤结果。

> 仅在你拥有或已获授权的网络中使用本工具。

## 功能

- 发现 `_workstation`、`_http`、`_smb`、`_qdiscover`、`_device-info`、`_afpovertcp` 等常见服务。
- 自动查询 `_services._dns-sd._udp.local.` 并跟进发现的服务类型。
- 聚合 `PTR → SRV/TXT → A/AAAA` 证据链。
- 输出 IP、端口、主机名、服务名、TTL 和 TXT banner。
- 深度解析 QNAP `qdiscover` 型号、固件、访问方式等字段。
- 支持文本和 JSONL 输出。
- 校验 mDNS 响应的 IP TTL，默认只接受 TTL 为 `255` 的本地链路响应。
- 对网络返回的控制字符进行转义，避免终端注入。

## 协议边界

mDNS 固定使用 `UDP/5353`，IPv4 组播地址为 `224.0.0.251`。命令参数的含义如下：

- `--cidr` 是结果地址过滤条件，不会对 CIDR 中的每个 IP 逐一探测。
- `--ports` 过滤 DNS-SD `SRV` 记录中声明的服务端口，不是 TCP/UDP 端口扫描范围。
- 输出状态为 `advertised`，表示设备通过 mDNS 广告了服务，不代表业务端口已经验证开放。
- mDNS 通常不会跨越路由器或 VLAN。目标设备应位于所选网卡能够接收 mDNS 组播的二层网络中。

当前版本通过 IPv4 mDNS 组播发现设备，同时可以解析响应中携带的 `AAAA` 记录。IPv6 mDNS 组播主动发现尚未实现。

## 环境要求

- Go `1.25` 或更高版本。
- macOS 或 Linux。
- 网络允许收发 IPv4 组播和 `UDP/5353`。

## 构建

```bash
git clone git@github.com:poroCookie/mdnsmap.git
cd mdnsmap
go build -o mdnsmap ./cmd/mdnsmap
```

## 使用方法

```bash
./mdnsmap scan \
  --cidr 192.0.2.0/24 \
  --ports 1-65535 \
  --interface en0 \
  --timeout 8s \
  --format text
```

`scan` 可以省略：

```bash
./mdnsmap --cidr 192.0.2.0/24 --interface en0
```

### 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--cidr` | 必填 | 目标 CIDR，可重复传入 |
| `--ports` | `1-65535` | `SRV` 端口过滤表达式，例如 `80,443,5000-5100` |
| `--interface` | 自动选择 | 执行扫描的网卡，例如 macOS 的 `en0` |
| `--timeout` | `8s` | 扫描和接收响应的总时长 |
| `--format` | `text` | 输出格式：`text` 或 `jsonl` |
| `--strict-hop-limit` | `true` | 仅接受 IP TTL 为 `255` 的 mDNS 响应 |

如 CIDR 无法自动匹配本机网卡，需要显式传入 `--interface`。

## 示例

### 过滤多个服务端口

```bash
./mdnsmap scan \
  --cidr 192.0.2.0/24 \
  --ports 445,548,5000-5100 \
  --interface en0
```

### JSONL 输出

```bash
./mdnsmap scan \
  --cidr 192.0.2.0/24 \
  --interface en0 \
  --format jsonl
```

每行对应一个服务发现结果，主要字段包括：

```json
{"ip":"192.0.2.10","ipv4":["192.0.2.10"],"port":5000,"transport":"tcp","host":"nas.local","service":"qdiscover","instance":"nas","state":"advertised","metadata_only":false,"ttl":10,"txt_raw":["accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9"],"fingerprint":{"vendor":"QNAP","model":"TS-X64"},"banner":"Name=nas\nIPv4=192.0.2.10\nHostname=nas.local\nTTL=10\n..."}
```

### 文本输出

```text
services:
5000/tcp qdiscover:
Name=nas
IPv4=192.0.2.10
Hostname=nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9
answers:
PTR:
_qdiscover._tcp.local
```

## 开发与测试

```bash
go test ./...
go test -race ./...
go vet ./...
```

完整的协议设计、数据模型和验收标准见 [`DESIGN.md`](./DESIGN.md)。

