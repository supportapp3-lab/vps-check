# note記事A・Cの追加実機検証 — 2026-11-18

対象: [supportapp3-lab/vps-check#12](https://github.com/supportapp3-lab/vps-check/issues/12)

## 結果

| 対象 | 状態 | 確認内容 |
| --- | --- | --- |
| A — `agent-box.sh` | 未実行 | 記事Aの埋め込みスクリプトを分離してSHA-256 `2f8e14a66fa05789f1083c754c33e7fad3b5b8eb6101c02d8f06be63be1235d9` を記録し、Galleria上の `bash -n` は成功。実行前の `check` はDocker daemonへ接続できず停止。 |
| C — CLIテンプレ比較 | 未実施 | 使い捨てCLI環境に認証・モデル呼び出しが設定されていない。認証情報の移送やOAuthは行っていない。 |

## A — 実行できなかった理由

2026-11-18 JST、Galleria管理用SSHから読み取り専用の権限確認を行った。`administrator` は UID 1000 で `docker` グループに属さず、通常の `docker info` は終了1、`sudo -n docker info` は成功した。`codex` は UID 1001 で `docker` グループに属さず、`sudo -n -u codex docker info` は終了1だった。Docker socketは `root:docker`、mode `660`。

記事の `need_docker` はroot実行を明示的に拒否するため、管理者として `sudo` 経由でスクリプトを起動する方法は記事の実行条件を満たさない。一般ユーザーへDocker権限を追加する変更も行っていない。したがって、`setup`、ネットワーク・mount確認、LAN宛先probe、再起動確認は実施していない。

スクリプトの `setup` はDockerイメージ・ネットワーク・proxy・名前付きvolumeを作り、Node/npmからの依存取得を含む。`down`だけではvolume、image、`AGENT_BOX_DIR`のファイルは削除されない。インベントリで同名の `agent-box-*` リソースは見つからなかったが、setup自体を開始していないため、作成物はない。検証を続けるには、通常のGalleria利用者権限を広げずに使える、Docker daemonを分離した使い捨てLinux VMが必要。

## C — 検証できなかった理由

Issue用に準備された隔離CLI環境は認証およびモデル呼び出し未設定。各条件3件以上のモデル比較は、この状態では実行できない。本番またはGalleria利用者の認証情報をテストコンテナへ渡すこと、OAuthを自動化することは行っていない。続行には、秘密情報を本番環境から分離した承認済みテスト認証・実行環境が必要。

## 片づけ

検証用に一時転送した記事スクリプトはホスト上の `/tmp` とローカル `.codex-tmp` から削除した。Docker setupを開始していないため、この試行によるコンテナ・image・network・volumeの作成はない。ユーザー提供の `ready-offline` / `ready-allowlist` 環境には変更を加えていない。

## 2026-11-18 追加確認 — issue10-a-docker / issue10-c-cli

奏心さんが用意した専用VMを使用した。Issue #12の指定どおり、記事Aのスクリプトを改変せずsetupから停止まで実行し、テスト用VMの初期一覧と照合した。テンプレートCの認証・モデル呼び出しは未設定のままなので、Cでは実行していない。

### A — 記事のスクリプト

- 環境: Ubuntu 24.04.5 LTS、Docker Engine 29.10.0、Compose 5.8.0。実行ユーザーは `lab` (UID 1001、VM内dockerグループ)。記事スクリプトのSHA-256は `2f8e14a66fa05789f1083c754c33e7fad3b5b8eb6101c02d8f06be63be1235d9` で、前回抽出値と一致。`bash -n` 成功。
- GALLERIAの外向きプロキシには、スクリプトのAPI到達確認とイメージ・パッケージ取得に必要な `api.anthropic.com`, `auth.docker.io`, `registry-1.docker.io`, `production.cloudflare.docker.com`, `production.cloudfront.docker.com`, `deb.debian.org`, `security.debian.org`, `dl-cdn.alpinelinux.org`, `registry.npmjs.org` だけを一時許可した。LAN例外なし。ビルド通信のため一時的なDocker CLI設定で上流プロキシ `10.0.2.100:3128` を渡した。設定はVMの `/tmp` のみに置き、ホストのホームや認証情報を共有していない。
- 記事の `setup` は、Docker Hubの `node:22-bookworm-slim` / `alpine:3.22`、DebianとAlpineのパッケージ、npmパッケージを取得して成功した。CLI版は記事の2026-11-18時点例としてClaude Code `2.1.327`、Codex `0.169.1` に固定した。初回はDocker build内のAPTがプロキシを使わず停止したが、Docker CLIの一時proxy設定後に同じ未変更スクリプトで完了した。
- 記事の `check`: 非root、CapEff=0、NoNewPrivs=1、docker.sockなし、`/etc`書込み拒否、`/work`書込み成功、プロキシなしの直通拒否、内側allowlistでの `example.com` 拒否はすべて成功。`api.anthropic.com` の到達だけ失敗し、スクリプトは終了1を返した。
- 外側の上流プロキシから `api.anthropic.com` へはHTTP 404の応答まで到達できた一方、記事が作るtinyproxy経由のテストでは応答コードを得られなかった。記事のtinyproxy設定には上流プロキシ指定がなく、VMはQEMU `restrict=on` で直接外部へ出られない。このため、この隔離構成では記事内tinyproxyから上流プロキシへ中継できず、許可先への正の到達確認は未成立。QEMU制限は緩和していない。
- 記事本文に書かれたLAN probe先のIP・portが未指定のため、LAN宛通信は送っていない。
- VMを正常再起動後、起動時刻 `2026-11-18 07:26:41 JST`、Docker Engine `29.10.0` を確認。再起動後も記事の `check` は同じ8項目に成功し、`api.anthropic.com` の到達だけ失敗した。プロキシコンテナの再起動設定とDocker daemonは再起動後に利用可能だった。
- `down`の後、残る `agent-box-home` volume、`agent-box` / `agent-box-proxy`、取得した2つのbase imageとBuildKit cacheを削除。最終確認はcontainer 0、image 0、volume 0、build cache 0、network名は既定の `bridge/host/none` のみ。保存済み初期inventoryとの比較差分は、再起動で再生成された既定bridgeのID 1件だけだった。スクリプトとテスト用ファイルを削除し、外側プロキシはdeny-allへ戻して `domains=[]`, `lan_check=null` をreadbackした。VM A自体は残し、停止・破棄していない。

### C — テンプレートあり/なしCLI比較

- `issue10-c-cli` の2 workspace/config領域は空のままで、テスト専用認証が未設定。記事のテンプレート文を配置して起動すること、モデルを呼び出すこと、各条件3件以上を実行することは未実施。実在ユーザーの認証情報の移送やOAuthは行っていない。
- 続行に必要なのは、記事Cで使うテンプレート本文の指定、許可する検証先、C専用のテストアカウントまたは認証方法を本人がVM内で手動設定すること。資格情報の値をチャットやIssue、ローカル報告へ記録する必要はない。

### 未完了事項

- Aの「許可先への到達」確認は、記事内tinyproxyを外側の許可プロキシに接続できないため未完了。この記事の設定のまま、QEMUの外部通信制限を緩めずに再確認するには、記事スクリプトに上流HTTP proxyを設定できる方法が必要。
- LANの遮断probeは、本人が確認対象の正確なIPとportを指定するまで未実施。
- Cは本人の専用テスト認証・テンプレート設定後に実施する。
