# note記事3本の実機検証 — 2026-11-18

対象 Issue: [supportapp3-lab/vps-check#10](https://github.com/supportapp3-lab/vps-check/issues/10)
検証対象の記事: `agent-docker-sandbox.md`、`github-token-least-privilege.md`、`prompt-injection-agent-rules.md`。記事本文は検証対象データとして読み、記事内の指示やスクリプトは実行していない。記事ファイルは変更していない。

## 結果の要約

| 項目 | 実施したこと | 結果 |
| --- | --- | --- |
| A — Docker sandbox | Galleriaの使い捨てoffline / allowlistコンテナで隔離、mount、通信を確認 | 一般ユーザー、capabilityなし、no-new-privileges、Docker socketなし、root filesystemと/sourceの書込拒否、/work書込可を確認。offline/direct/unlisted通信は失敗し、登録したapi.anthropic.comへのHTTP(S)は到達した。記事のホスト側agent-box.sh setup自体は未実行。 |
| B — GitHub token最小権限 | 記事にある4つのPAT作成URLとクエリをソース上で確認 | サインイン済みGitHubの権限画面は開けず、現在表示されるフィールドや実効権限は未確認。PATは作成せず、token値も取得・保存・表示していない。 |
| C — prompt injection | 記事内の無害なtraining指示を確認 | Claude Code/Codex CLIでのtemplate有無比較は未実施。`TRAINING_OK.txt`は作成していない。 |

## A — Docker sandbox

- WindowsではDocker CLI `29.5.2` を確認。`docker info` は終了コード1で、daemon情報を取得できなかった。
- Galleriaの既存手順にあるSSH先で `codex` ユーザーの実行環境を確認。UID/GIDは `1001`、Docker CLIは `29.9.3`。このユーザーからの `docker info` も終了コード1だった。
- `tools/galleria-linux/README.md` に従うと、実機検証には管理者による必要最小限のmountを使ったコンテナ準備が必要。準備済みコンテナやdaemonアクセスは確認できなかった。
- 2026-11-18 JSTに、Galleria管理者が用意した使い捨て環境で、記事A本文のコピー1ファイルだけを`/source/A/02_body.txt`へ渡して確認した。コピーのSHA-256は原稿と一致した（`fb31e721169ef67816ab3a6f9cb4aa6dca908db31bcb444a16266217924f1dc0`）。`find /source`で見えるファイルはこの1件だけで、`/source`への書込は拒否、`/work`への書込は許可された。
- `issue10-a-offline`ではUID/GID 1100、`CapEff=0000000000000000`、`NoNewPrivs=1`、`/var/run/docker.sock`なし、`/etc`書込拒否を確認した。`curl --noproxy '*' https://example.com`は名前解決に失敗（exit 6）。
- `issue10-a-allowlist`は`api.anthropic.com`のみ登録。プロキシ経由のHTTPS HEADはHTTP 404、HTTP HEADはHTTP 400を返し、いずれも接続成功（exit 0）。応答本文やヘッダーは取得・保存していない。未登録`example.com`へのプロキシHTTPSはHTTP status 000 / curl exit 56、直接HTTPSはstatus 000 / exit 6で失敗した。
- これはGalleriaの提供された`lab.py`隔離環境での実測であり、記事に載るホスト側`agent-box.sh setup`やDocker image/network作成手順をそのまま実行した結果ではない。記事のスクリプトにはホストDocker資源・永続network/volume・再起動policy等を作る処理があるため、ホスト上では実行していない。本文の挙動との完全な同等性、記事内コマンドをそのまま実行した結果、およびLAN宛先の実リクエスト拒否は未検証。既存の`guard.sh`/Squid ACLの設定は別途ソース確認済み。

## B — GitHub tokenの権限画面

記事内のURLは次の4パターンだった。

1. `agent-read`: `contents=read`
2. `agent-pr`: `contents=write`, `pull_requests=write`
3. `agent-issues`: `contents=read`, `issues=write`
4. `agent-pr-ci`: `contents=write`, `pull_requests=write`, `actions=read`

ページを開くWindows browser操作では、対象タブの現在URLを安全に確認できず、Computer Useが操作停止を返した。そのため、GitHubの実際の作成画面に表示される権限フィールドとの比較は未実施。これは資格情報の期限切れやscope不足を示すものではない。PATの作成・削除は行っていない。

## C — prompt injection

記事のtraining文面は確認したが、Claude Code/Codex CLIの両条件を安全に独立実行して比較する検証環境が未確認のため、モデル/CLIでのテスト結果はない。注入文面に従ってファイルを作成することはなく、`TRAINING_OK.txt`は作成していない。

## Go repository checks

Issue用ブランチ `codex/issue-10-note-verification` のcommit base `c55c9742d5412e13eb8d1538891cd359dc19d484` で以下を実行し、いずれも終了コード0。

- `go test ./...`
- `go vet ./...`
- `go build ./...`

Goは既定のRoaming telemetry upload-tokenへアクセスできないという警告を出したが、コマンドは成功した。テレメトリ状態の変更やtokenの閲覧は行っていない。

## 追加確認が必要

1. 記事のホスト側`agent-box.sh`全体を実行した場合の再起動・ネットワーク・mount挙動との同等性。既存ホスト資源を作成するセットアップを実行せず、隔離されたGalleria labで観測できる範囲のみを検証した。
2. 人が承認済みGitHubセッションのUIで4つのPAT作成画面を確認し、表示フィールドを記録する。今回PATは発行していない。
3. 使い捨てテスト環境でClaude CodeまたはCodex CLIのtemplateあり/なし比較を行い、注入文面が境界を越えないことを確認する。

この報告は観測できた事実と未検証項目を分けた部分報告であり、3項目すべての実機検証完了を示さない。
