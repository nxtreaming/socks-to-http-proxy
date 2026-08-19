# sthp 0.9.9 不停机迁移（DNS 切换）

目标：把流量采集从旧 `sthp` 实例迁到新机器，**不停止 NetWatch**。旧 IP 上仍在增长的流量应出现在新实例的 `GET /stats` 上，且采集器不能读到一次“成功但明显变小”的计数（会被当成计费清零）。

需要 **0.9.9** 及以上。旧实例可以仍是 0.9.8；没有 `epoch` 时，新实例无法可靠识别旧进程重启，只能按 watermark 忽略回落。

## 约束

- NetWatch cron 通过 HTTP 代理拉 `GET /stats`。拉取失败会跳过写库；**成功但 rx/tx 突然变小** 才是危险情况。
- 典型采集：

  ```bash
  curl -s -x http://USER:PASS@api.example.com:12323 \
    http://api.example.com:12323/stats
  ```

  这是绝对形式 URI。新实例必须加 `--stats-host api.example.com`（以及绑 `0.0.0.0` 时的公网 IP，如需要），否则该请求会被当成普通代理转发，而不是返回本机统计。
- `--stats-sync-from` 必须指向**旧机器的 IPv4**，不能写正在切换的域名（域名切过来之后会打到自己）。不支持 IPv6 URL（`http://[addr]:port`）。
- 不要把旧机的 `traffic_stats_*.txt` 拷到新机当“迁移完成”。文件里的 `epoch` 不会作为本机 generation 恢复；直接拷文件也无法带上 DNS 重叠期间旧机上继续产生的字节。

## 原理（操作上需要知道的）

新实例把旧实例的 `GET /stats` 当成**旧机绝对计数**，只加上相对上次同步的正增量（watermark）。

| 旧机样本 | 新实例行为 |
| --- | --- |
| 同 `epoch`，rx/tx 增长 | 只加差值 |
| 同 `epoch`，rx/tx 回落 | 视为乱序/过期样本，忽略 |
| `epoch` 变化（旧机重启或 `/stats/reset`） | 两边 watermark 跟着新 totals 走，**不扣** 新机已有计数；旧 generation 退役，延迟样本不能再激活 |
| 旧机宕机、拉取失败 | 新机本地计数不变 |
| `epoch` 为 0 或省略 | 当作无 generation；回落会忽略，检测不到重启 |

本机 `GET /stats` 的 `epoch` 是计数 generation：进程启动时新建，`POST /stats/reset` 时递增，不从统计文件恢复。

退役 generation 最多保留 32 个，不淘汰旧项。满了之后再出现的未知 `epoch` 会被忽略，不再同步新 generation。正常 DNS 切换远到不了这个上限。

## 迁移前

1. 记下旧 IPv4、HTTP 端口、`--http-basic`、NetWatch 使用的 Host（域名或公网 IP）。
2. 新机装好 **0.9.9** 二进制；上游 SOCKS、白名单、`conn-per-ip` 等与旧机对齐。
3. 确认新机打得到旧 IP 的 `12323`（或实际端口），且旧机仍在跑。
4. 在旧机或跳板上看一眼当前计数，作对照：

   ```bash
   curl -s -x http://USER:PASS@OLD_IP:12323 http://OLD_IP:12323/stats
   # 期望类似 {"port":12323,"rx":...,"tx":...,"epoch":...}
   ```

## 推荐步骤（自动拉取）

**保持旧进程运行。** 先在新 IP 上启动 0.9.9，再改 DNS。

```bash
./sthp --listen-ip NEW_IP \
  --http-basic USER:PASS \
  --no-httpauth 0 \
  -p 12323 \
  --stats-host api.example.com \
  --stats-sync-from http://OLD_IP:12323/stats \
  --stats-sync-interval 5
```

说明：

- `--http-basic` 在 0.9.8+ 默认开启鉴权；`--no-httpauth 0` 明确要求鉴权（与生产一致）。
- 同步会复用 `--http-basic` 去拉旧机 `GET /stats`（等同 `curl -x USER:PASS@OLD_IP:...`）。也可以把账密写进 URL：`--stats-sync-from http://USER:PASS@OLD_IP:12323/stats`。
- 绑的是具体 `NEW_IP` 时，该 IP 的管理 URI 视为本机。若改绑 `0.0.0.0`，采集器用公网 IP 绝对 URI 时还要 `--stats-host PUBLIC_IP`。
- 启动日志应出现 `Stats sync from OLD_IP:12323/stats every 5s ...`。有增量时会打 `Stats sync added rx=... tx=...`。

启动后立刻核对新机（走新 IP，不要走域名）：

```bash
curl -s -x http://USER:PASS@NEW_IP:12323 http://NEW_IP:12323/stats
```

新机 `rx`/`tx` 应接近「新机本地流量 + 已从旧机导入的增量」，并随 `--stats-sync-interval` 跟着旧机涨。旧机计数不应被这次操作清零。

再用采集器同款 URL 打新机（DNS 尚未切换时，把域名先写进 `--stats-host`，用新 IP 当代理）：

```bash
curl -s -x http://USER:PASS@NEW_IP:12323 http://api.example.com:12323/stats
```

应返回**新实例**的 JSON，而不是上游错误或另一台机器的统计。

## 切换 DNS

新机同步稳定后，把 `api.example.com`（或实际记录）指到 `NEW_IP`。

重叠期：

- 新机继续按旧 IP 拉 `--stats-sync-from`，把仍打到旧机的流量补进来。
- NetWatch 继续用原来的 `curl -x ... http://api.example.com:12323/stats`；`--stats-host` 保证切过来之后仍读本机。

观察新机 `rx`/`tx` 是否仍在涨，且没有突然掉到接近 0。旧机拉取失败是正常的（会 warn，连续失败后重试间隔拉长到至少 60s），**不会改新机计数**。

## 下线旧机

同时满足再停旧进程：

1. DNS 已指向新 IP，TTL 已过。
2. 新机日志里对旧 IP 的 sync 已失败/backoff，且新机 `GET /stats` 仍随本机流量增长。
3. 新旧 `rx`/`tx` 差距不再扩大（只剩旧机残留连接）。

停旧机后可去掉 `--stats-sync-from` 再拉起新进程（可选）。去掉之后不会再从旧 IP 补数；本地计数和 watermark 仍在 `traffic_stats_<port>.txt` 里。

不要在迁移窗口对**新机**做 `POST /stats/reset`。那会抬高本机 `epoch`，采集器若把新旧都当数据源，可能把新 generation 的低计数当成一次清零。

## 手动补数（可选）

自动 sync 不可用时，在新机 loopback 或带 `--http-basic` 的客户端上：

```bash
OLD_STATS=$(curl -s -x http://USER:PASS@OLD_IP:12323 http://OLD_IP:12323/stats)
curl -s -X POST http://NEW_IP:12323/stats/add \
  -H "Proxy-Authorization: Basic $(printf 'USER:PASS' | base64)" \
  -H 'Content-Type: application/json' \
  --data-binary "$OLD_STATS"
```

未配置 HTTP 鉴权时，`POST /stats/add` **只接受 loopback**（例如 `http://127.0.0.1:12323/stats/add`）。远程未认证请求返回 403。`--stats-sync-from` 不走这条 HTTP 路由。

可重复执行；相同或更小的同 epoch 样本不会双计。成功时类似：

```json
{"ok":true,"port":12323,"added_rx":...,"added_tx":...,"rx":...,"tx":...}
```

## 失败与回退

| 现象 | 处理 |
| --- | --- |
| 新机 `GET /stats` 明显小于旧机，且不再追上 | 检查 `--stats-sync-from` 是否为旧 IPv4、账密、防火墙；看是否有 `Stats sync from ... failed` |
| 采集 URL 打到新机却像普通网页/上游错误 | 缺 `--stats-host`，绝对 URI 被转发了 |
| 同步失败但本地计数还在涨 | 预期行为；旧机不可达时不改 watermark |
| 误拷了旧统计文件到新机 | 本机 `epoch` 仍是新进程的；用 `--stats-sync-from` 或 `/stats/add` 继续追旧机绝对计数 |
| DNS 已切但要回滚 | 把域名指回旧 IP。旧机计数未因迁移清零。新机已导入的增量不会自动撤销 |

## 限制

- `--stats-sync-from` 不支持 IPv6。
- 退役 generation 上限 32；满后未知 `epoch` 不再采纳。升级时若文件里的 retired 列表更长，加载时截成 32 项。
- 管理接口与代理共用 HTTP 鉴权；`POST /stats/add` 在关闭鉴权时仅 loopback。
- 管理接口只在 HTTP 监听器上（纯 SOCKS 模式没有这些路径）。
