# lk-unlock 分支交接文档

> 面向接手本分支的 agent / 维护者。读完应能独立构建、验证、继续开发。
> 本文件已脱敏：不含密钥、设备标识、机型名、第三方作者信息或本地路径。

## 0. 一句话

在原版 lk-unlock（替换解锁公钥 + cert2 hash-override + no-wipe 补丁）之上，
本分支增加了两项可选能力：

1. **fastboot 层 lk 写保护**：拦截 `flash:` / `erase:`，让 `lk` / `lk_a` / `lk_b`
   不可被刷写或擦除，其他分区不受影响；
2. **Android 层伪回锁**：向内核 cmdline 追加
   `androidboot.verifiedbootstate=green`，系统显示“已验证/已锁定”，
   而 bootloader 实际仍是解锁态，可以继续刷 boot/system 等分区。

另附：`resign` 子命令、Unicorn 离线验证脚本、README 说明。

## 1. 背景

小米 MTK 机型解锁依赖 RSA：设备生成 token，服务器签名，LK 用内置公钥验签。
原版工具的做法是：

- 把 LK 里的小米公钥模数替换成本地生成的 2048 位公钥；
- 修改过的分区用 **cert2 hash override**（`A0 len + OID/BitString 对`）绕过
  secure boot 校验，cert1 保持原厂签名；
- 可选地打 no-wipe 补丁，避免解锁时清 userdata。

解锁之后，任何一次刷整包（fastboot / OTA）都可能把 lk 覆盖回原厂，从而失去解锁。
本分支要解决的就是这一点，并且让系统侧看起来仍处于已锁定状态。

## 2. 与原项目的区别

| 方面 | 原项目 | 本分支 |
|---|---|---|
| CLI 子命令 | `patch` / `sign` / `unlock` | 增加 `resign` |
| `patch` 选项 | `--wrap` / `--no-wipe-block` | 增加 `--lk-protect {fail,okay,off}`、`--fake-lock` |
| 默认行为 | 只改公钥 / no-wipe / cert2 | **默认安装 `--lk-protect fail`**；`off` 可恢复原行为 |
| 新文件 | — | `lk_unlock/inject.py`、`lk_unlock/protect.py`、`tests/emu_check.py`、`HANDOFF.md` |
| 证书处理 | override / wrap | 不变；注入后仍由 `apply_cert_bypass` 统一重算 |
| 依赖 | liblk / pyasn1 / cryptography | 不变；测试额外需要 `unicorn` |
| 许可证 | AGPL-3.0 | 不变，保留上游署名 |

行为变化只有一处：**现在 `patch` 默认会给 lk 加写保护**。不需要的人显式传
`--lk-protect off`。

## 3. 实现

### 3.1 lk 写保护（`lk_unlock/protect.py`）

**定位 handler**：扫描 `fastboot_register` 的调用模式——
指向命令名字符串（`flash:` / `erase:`）的 `adrp+add`，随后若干条内出现
`adr x1, #handler` 和 `bl`。handler 地址由 `adr` 立即数给出。

**打补丁**：每个 handler 入口只改第二条指令：

```
原:  paciasp
     sub sp, sp, #N        ← 改成 b <cave>
新:  paciasp
     b   cave
```

保留第一条 `paciasp` 是有意的：它同时是 BTI 合法落点，也保证
`autiasp` 的签名/校验配对不被打乱。

**cave 逻辑**：

- 逐字节比较 `x0` 指向的分区名，命中 `lk`、`lk_a`、`lk_b`、`lk_ab` 四种；
- 命中：保存 `x29/x30`（LR 已被 paciasp 签名）→ 调 `fastboot_fail` 或
  `fastboot_okay` → 恢复 → `autiasp` → `ret`；
- 未命中：重放 `sub sp, sp, #N`，跳回 `handler + 8`，原逻辑完全不变。

`sub sp` 的立即数从原 handler 第二条指令里解析，不硬编码。

**回复模式**：`fail` 回 `FAIL <msg>`；`okay` 回 `OKAY <msg>`（刷机脚本不中断，
但也不会真正写入）。

### 3.2 伪回锁（`apply_fake_lock`）

`cmdline_append` 通过 `adrp+add "androidboot.bootreason=reboot"` 后的 `bl` 定位。
把该调用点改成 `bl cave`，cave 内：

```
append("androidboot.verifiedbootstate=green")
append("androidboot.bootreason=reboot")
ret
```

即“多追加一条，再补回原来那条”，不动其他 cmdline 逻辑。

**没有**修改 `androidboot.vbmeta.device_state`：原厂 `avb_cmdline` 的行为保持不变，
避免影响依赖该属性的组件。

### 3.3 code cave 与证书

- cave 放在 lk 数据内、字符串表之前的零填充区（4 字节对齐，从 `0x40000` 起找）；
- 不改变 `lk` 分区大小，处理器入口只改 4 字节；
- 修改完成后由 `apply_cert_bypass` 重新生成 cert2 override，两个 hash 分别覆盖
  header 与（按 16 字节对齐的）data。

### 3.4 `resign`

对“数据已改、但 cert2 仍是原厂”的镜像重算 override 块。
已经过 `patch` 的镜像 cert2 已被前缀块替换（`Certificate.from_bytes` 会因尾随数据
失败），不适用 `resign`，需从原厂镜像重新 patch。

## 4. 验证

已做（离线）：

- `LkImage` 重新解析：5 个分区、cert 数量不变；
- 逐分区对比：只有 `lk` 的 data 与 cert2 变化，cert1 与其他分区逐字节一致；
- cert2 override：块内两个 hash 与当前 `compute_hashes()` 完全相等；
- `tests/emu_check.py`（Unicorn）：模拟执行 cave，校验
  - `flash`：`lk`/`lk_a`/`lk_b`/`lk_ab` 命中，`lk2`/`boot`/`lk_a1` 放行；
  - `erase`：`lk`/`lk_a` 命中，`system` 放行；
  - 伪回锁 cave 依次追加 green 与原 bootreason；
- 两种模式（fail / okay）以及 `--lk-protect off` 均构建通过；
- `tests/verify_build.py`：对成品镜像做发布前检查（分区结构、非 lk 分区与全部 cert1
  是否与原厂一致、cert2 override hash、私钥与镜像内模数是否配对），任一失败返回非零。

未做（必须在真机确认）：

- 首次启动是否正常；
- cave 所在零填充区在运行时是否可执行、是否会被其他数据占用；
- 实际刷写时 `flash:` / `erase:` 的拦截效果；
- OTA 与 loop 重定向模块的配合。

## 5. 风险与限制

- **未做真机启动验证**。刷入前必须准备好回滚路径（原厂镜像、BROM 或已放行的 LK）。
- cave 依赖镜像中存在足够大的零填充；不同固件可能找不到，届时会直接报错而不是乱写。
- 只覆盖 fastboot。手机上的 OTA 通过内核块层写 lk，需要 loop 重定向类模块配合，
  否则 lk 仍会被 OTA 覆盖。
- 伪回锁只影响 cmdline 对用户态可见的状态，不会欺骗 TEE / KeyStore 证明。
- 首次刷入需要 BROM、由现有 LK 放行 lk 写入，或 root 直接写**真实**块设备节点
  （注意 `/dev/block/by-name` 可能被 loop 重定向模块替换）。
- 固件更新后需要基于新镜像重新构建；地址全部由扫描得到，但 cave 位置需要重新确认。
- 实测：写保护只覆盖**当前活动槽**的 lk，空闲槽可以正常写入（见第 9 节）；因此可以
  先在空闲槽上做实验，但切槽后系统是否可启动、boot reason 是否保留，取决于机型。

## 6. 复现步骤

```bash
# 构建（需要 xiaomi.pem；会生成 private.pem / public.pem，务必备份）
python lk-unlock.py patch lk.img -o lk_new.img --lk-protect fail --fake-lock

# 离线验证（需要 pip install unicorn）
python3 tests/emu_check.py lk_new.img

# 仅重算 cert2（cert2 必须仍是原厂）
python lk-unlock.py resign edited.img -o resigned.img

# 解锁（原流程不变）
python lk-unlock.py unlock
```

刷入建议：两个 lk 槽都写，避免切槽回到旧 LK；刷完保留 `private.pem`，
它对应新 LK 里嵌入的公钥。

## 7. 待办

- [ ] 用二分构建（仅 liblk 重建 / 仅换 key / 仅 no-wipe / 完整镜像）在空闲槽上定位
      “镜像能写入但进不了 fastboot”的原因（最高优先级）。
- [ ] 真机启动与拦截效果验证。
- [ ] `verify_build.py` 接入构建流程（构建后自动跑一遍）。
- [ ] 可选 `--fake-lock-full`：同时把 `androidboot.vbmeta.device_state` 改为 locked；
      由于用户态模块已能覆盖该属性，优先做成模块而不是 LK 补丁。
- [ ] cave 探测增加后备策略（函数间对齐填充、按段大小裁剪）。
- [ ] 为 `inject.py` / `protect.py` 增加不依赖 Unicorn 的单元测试（编码器、发现逻辑）。
- [ ] 固定 liblk 版本（当前依赖 `@master`，存在漂移风险）。
- [ ] 把 `--lk-protect` 的默认值决策写进发布说明。

## 8. 脱敏说明

本分支提交内容已排除：私钥/公钥文件、设备序列号与机型名、构建指纹、
第三方作者与社群信息、附件路径、镜像哈希。
文档中的具体地址仅作原理说明，实际值在构建时由代码扫描得到。

## 9. 现场测试记录（2026-11-21）

测试条件：A/B 机型、bootloader 锁定、临时 root（KernelSU）、无 BROM；活动槽为 a，
lk_a、lk_b、userdata 均已备份。

| # | 操作 | 结果 |
|---|---|---|
| 1 | root 下 `dd` 写活动槽 lk_a | `Buffer I/O error ... lost async page write`，回读仍是原厂；同分区 8 MiB 偏移处可写 → **范围级写保护，覆盖活动槽镜像区** |
| 2 | root 下 `dd` 写空闲槽 lk_b | **成功**，回读 hash 与构建镜像一致 → 写保护只覆盖活动槽 |
| 3 | `fastboot set_active b` 后重启 | 命令在 locked 状态可用；b 槽 system 无效 → 反复重启，随后自动回退 a；lk_b 内容保留 |
| 4 | 原厂 lk.img 写入 lk_b，切 b + `reboot-bootloader` | **能进 fastboot** → b 槽与 reboot-bootloader 路径本身可用 |
| 5 | 本分支构建的镜像写入 lk_b，同样操作 | **未能进 fastboot**（反复重启），原因未定位 |

由 #4、#5 可知：问题被缩小到“本分支构建的镜像”或“该镜像在 b 槽的启动条件”，
与槽位切换机制无关。下一步在空闲槽上用二分构建（仅 liblk 重建 / 仅换 key /
仅 no-wipe / 完整镜像）复现并定位。

同一轮还确认：生态中 `ro.boot.vbmeta.device_state=locked` 等“伪回锁”属性是
KernelSU 模块用 `resetprop` 在用户态设置的，**LK 未参与**；本分支不改
`device_state` 的决定保持不变。

## 10. 变更记录

### v0.2 — 发布前校验脚本与现场记录

- 新增 `tests/verify_build.py`（分区 / cert1 / cert2 / 密钥配对检查）；
- 第 9 节增加现场测试记录；
- 明确“伪回锁属性由用户态模块负责、LK 不参与”的边界。

### v0.1 — lk 写保护与伪回锁

- 新增 `--lk-protect {fail,okay,off}`，默认 `fail`；
- 新增 `--fake-lock`（cmdline 伪回锁）；
- 新增 `resign` 子命令；
- 新增 `tests/emu_check.py`（Unicorn 离线验证）；
- 新增 `lk_unlock/inject.py`（AArch64 编码器与扫描工具）；
- 新增 `lk_unlock/protect.py`（两项功能的注入实现）；
- README 增加对应章节；
- 修复：`patch` 的异常提示拆分为“解析失败 / 注入失败 / 证书重算失败”。
