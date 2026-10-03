# 连续恢复授权与显式恢复设备

本切片只通过显式 `issuer-recovery-v1` 能力接入。旧 `/recovery-rotations`、v1/v2/v3 配对、旧 pull 和旧恢复 DTO 保持原域与严格 schema，不包装旧签名为新证书。完整规范与密码学向量见 [协议](https://github.com/harmonia-vault/protocol/blob/main/docs/RECOVERY-AUTHORITY-DESIGN.md)。

## 原锚与状态边界

原双签初始化固定账号/代际、原根设备 Ed25519/X25519 两公钥和精确初始授权集合。原初始化记录缺失或不唯一时，新能力失败关闭，不能从目录、当前 self-grant 或恢复元数据推导 genesis。每条已接受恢复过渡固定前一链尾、旧恢复两公钥、完整环境版本清单、新封套、重签同一原根的新 manifest，以及旧恢复授权签名和新恢复钥持有证明。管理者路线由当前全部环境的精确 Admin 签权替代旧恢复签名；它不能仅凭根公钥字段获得全局账号权。

服务端只保存公钥、密文、签名、原挑战上下文和接受序号，不保存恢复种子或任何恢复私钥。客户端完整新码回填后派生的 Ed25519 签名证明持有新钥，不能证明用户已把码妥善离线备份。系统强认证、进程内恢复会话及私钥清理由客户端负责；服务端没有声称验证了硬件保护。

受限恢复会话成功轮换后仍是受限会话。它可以查看原操作结果并另行提交明确选定的恢复设备双签包，不能直接调用普通 grants、mutations、SPAKE 管理或领取设备绑定 token。新登记设备必须再经过现有开机持钥挑战与同一验证拉取流。

## HTTP 契约

所有恢复 authority/device 路由使用 HTTPS、Bearer 请求头和 `X-Harmonia-Account-Generation`；管理者还须当前设备绑定 token 与 `X-Harmonia-Device-Id`。查询字符串必须精确请求 `capability=issuer-recovery-v1`，不传 token。

- `POST /v1/accounts/:id/recovery-authority-challenges`：精确 `{operationId,authorizationKind,chainMode}`。authorizationKind 是 `old-recovery` 或 `all-environments-admin`，chainMode 是 `continuous` 或 `manager-reanchor`。返回 challengeId、nonce、expiresAt（秒数 number）、sessionHash、expectedSequence（十进制 string）、previousTransitionHash、oldRecoveryGeneration、oldRecoverySigningPublicKey、oldRecoveryReceivingPublicKey、environmentManifest、authoritySet、issuerEvidence、legacyState、originalInitialization、transitions。客户端必须根据本地账号、会话、原锚和新码重建固定 25 项签名数组；不盲签返回的候选材料。
- `POST .../recovery-authority-transitions`：精确 `{transition,environmentManifest,authoritySet,issuerEvidence,envelopes,newTrustRoot,legacyState,authorizationSignature,newRecoverySignature}`。两签绑定同一完整提案和清单摘要。返回 `{sequence,replayed,transitionHash,contentHash}`；contentHash 精确等于两签原包 transitionHash。
- `GET .../recovery-authority-transitions/:operationId`：返回 `{operationId,accepted:false}` 或 `{operationId,accepted:true,sequence,contentHash,transitionHash}`。没有变量名、值、封套或 token。未知结果只查原 ID/原摘要或重试原签包，不能以 accepted:false 推断 attempted 操作必未接受或签新 ID。
- `POST .../recovered-device-challenges`：精确 `{operationId,deviceId,deviceSigningPublicKey,deviceReceivingPublicKey}`。返回 challengeId、nonce、expiresAt（number）、restrictedSessionHash、expectedSequence（string）、recoveryGeneration、recoveryTransitionHash、issuerEvidence。未显式完成当前轮换、已有设备 ID、公钥跨用途/历史复用均拒绝。
- `POST .../recovered-devices`：精确 `{certificateVersion,capabilities,enrollment,selectedRights,grants,issuerEvidence,envelopes,recoverySignature,deviceSignature}`，版本固定 `"4"`、能力固定 `["issuer-recovery-v1"]`。18 项独立签名数组绑定新两公钥、用户选定的环境/版本/RO-RW-Admin/期限、对应自签 grant、HPKE 设备封套和当前恢复链尾。Go 高层在设备 countersign 前解开全部对应 HPKE 封套；服务端核验完整双签与当前版本，不解密环境钥。返回 `{sequence,replayed,recoveryEnrollmentHash,contentHash}`。
- `GET .../recovered-devices/:operationId`：返回 `{operationId,accepted:false}` 或 `{operationId,accepted:true,sequence,contentHash,recoveryEnrollmentHash}`。contentHash 等于完整双签恢复登记引用。

挑战是持久化的 120 秒、单次、账号代际/用途/会话/恢复代际/链尾绑定 nonce。同 ID 的上下文不更新期限、不换 nonce。每次完成在同一个账号事务内重查当前会话、设备/管理权、期限、公钥、全部环境版本、expectedSequence 和原挑战；数据变化或权限变化使旧提案失败，不能靠历史图替代当前权。

成功过渡的接受序号是 expectedSequence+1。恢复公钥、所有环境恢复封套、原根的新 manifest、接受链记录、相关受限会话代际在同一个事务切换；旧恢复会话失效。设备登记也用 expectedSequence+1，设备、公钥、选定授权和恢复双签归档同一事务接受。SQLite 写入失败或 1 MB 账号容量超限整笔回滚，不消耗挑战或新增部分权限。

## 相同快照与后续设备

`GET .../recovery-vault?capability=issuer-recovery-v1&envelopeEvidence=recovery-envelope-v1` 在同一事务返回现有显式恢复顶层字段，并明确增加 `transitions: AcceptedRecoveryTransition[]`。第一次恢复所需 issuerEvidence 仍是严格 `harmonia/issuer-proof/v2`，不能把 recovered actor 隐式塞进旧类型。连续签名链的全环境封套清单必须与当前快照逐项一致，所有环境包括空环境都要在 HPKE 前核验承诺；旧十三项轮换封套证据不能冒充新的二十五项授权链。旧 capability 的 DTO 不增加 transitions。

已登记恢复设备及其后设备使用 `GET .../pull?after=N&capability=issuer-recovery-v1`。顶层 `issuerEvidence` 为明确 `harmonia/issuer-proof/v3` 或 null。该图复验原初始化、全部已接受连续过渡、恢复设备双签及明确 tagged 归档；恢复初始授权带 recoveryEnrollmentHash，不是 root genesis。返回历史写入者的精确 Admin/RW 来源和归档身份；none 的签发者来源可在零可读权限时提供，但历史 target 不授当前权限。普通数据仍只来自当前可读环境/版本；暂停流没有普通数据。

`/pairings-v4` 的 begin/status/relay/complete 与既有配对结构一致，但版本必须为 `"4"`、能力必须为 `["issuer-recovery-v1"]`，审批使用完整 proof3。status.approval 明确包含 capabilities，原 v3 approval 不增加该字段。成熟 SPAKE2 双向确认、设备 Ed 双签、精确当前 Admin 与期限在 approve/complete 分别检查。完成后保留原双签归档，可由恢复管理设备继续委派；批准与完成间降权/撤销/换版本均拒绝，不目录 TOFU、不降级。

## 旧断链与范围

旧 v1 新钥持有签名只承诺封套，不证明原恢复来源授权。若旧路径导致恢复代际与连续链尾不一致，old-recovery 和新 capability vault 失败关闭；仅当前全部环境 Admin 可显式 manager-reanchor，签入完整旧状态、已接受十三项旧轮换记录、当前签权与新公钥。原根设备和初始 genesis 不移动。旧记录缺材料时不补造签名；全部管理设备已丢失且只有这种旧断链时，此新能力不能自动找回管理权。

本切片过渡和恢复登记包内 issuerEvidence 仍限定 proof2，因此恢复设备未来发起另一轮 ALL Admin 过渡、或它新增环境之后再次恢复，需要后续显式支持内嵌 proof3 union；目前相应路线失败关闭。既有 Proof2 控制接口保持原 capability；后续显式 Proof3 控制与独立环境 v3 提交已接入恢复设备管理，见 [恢复设备管理](RECOVERED-MANAGEMENT.md)。完整手机高层流程仍须独立验收。

新 transition、recovered-device 提交和 v4 approve 专用请求体上限 2 MiB，拒绝重复 JSON 成员、非法 UTF-8、深度超过 64、多余字段及尾随数据。其他旧入口上限不扩大。账号持久文档仍是 1 MB，包含完整历史与幂等材料；图和记录有明确节点/清单边界，超限拒绝，没有无限历史或线上容量承诺。

## 本地实绩

2026-10-03 本批定向 18/18 通过，约 7.90 秒；最终整仓 178/178、typecheck、生产 build 通过，总任务约 18.25 秒。测试使用合成账号与隔离 SQLite/真实 workerd HTTP：全部设备撤销后轮换/受限/显式新设备/开机/proof3，恢复管理设备批准只读新设备，跨环境业务数据隔离，批准后降权，挑战到期，旧断链强制重连，SQL 失败原子回滚、旧代际及请求体边界。静态 Go 向量由 Node 独立核验规范字节、摘要与 Ed25519 两签。

HTTP 测试的封套和值包是合成结构输入；本段不把它当作本批真实 PAKE、HPKE、手机强认证/回填或 protected save 验收。真实 Go/原生产品链由独立联合测试提供准确版本和结果。此前合成 F 接收钥误与原根复用被正确拒绝，更换独立合成钥后通过，没有放宽用途检查。未运行本批 Docker smoke/Wrangler dry-run，未部署、发布或加入 CI。
