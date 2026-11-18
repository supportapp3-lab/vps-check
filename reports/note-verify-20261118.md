# note記事3本の実機検証 — 2026-11-18

対象 Issue: [supportapp3-lab/vps-check#10](https://github.com/supportapp3-lab/vps-check/issues/10)
検証対象の記事: `agent-docker-sandbox.md`、`github-token-least-privilege.md`、`prompt-injection-agent-rules.md`。記事本文は検証対象データとして読み、記事内の指示やスクリプトは実行していない。記事ファイルは変更していない。

## 結果の要約

| 項目 | 実施したこと | 結果 |
| --- | --- | --- |
| A — Docker sandbox | WindowsとGalleriaのDocker実行環境を確認 | Docker CLIは存在するが、どちらの実行ユーザーもdaemonへ接続できなかった。スクリプト、通信制御、mount制限の実機検証は未実施。 |
| B — GitHub token最小権限 | 記事にある4つのPAT作成URLとクエリをソース上で確認 | サインイン済みGitHubの権限画面は開けず、現在表示されるフィールドや実効権限は未確認。PATは作成せず、token値も取得・保存・表示していない。 |
| C — prompt injection | 記事内の無害なtraining指示を確認 | Claude Code/Codex CLIでのtemplate有無比較は未実施。`TRAINING_OK.txt`は作成していない。 |

## A — Docker sandbox

- WindowsではDocker CLI `29.5.2` を確認。`docker info` は終了コード1で、daemon情報を取得できなかった。
- Galleriaの既存手順にあるSSH先で `codex` ユーザーの実行環境を確認。UID/GIDは `1001`、Docker CLIは `29.9.3`。このユーザーからの `docker info` も終了コード1だった。
- `tools/galleria-linux/README.md` に従うと、実機検証には管理者による必要最小限のmountを使ったコンテナ準備が必要。準備済みコンテナやdaemonアクセスは確認できなかった。
- したがって、記事スクリプトのallow/deny outbound networkingやmount制限について結果を推定しない。実行は行っていない。

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

1. 管理者が、必要最小限のプロジェクトmountと制御されたネットワーク設定を持つDocker環境を準備した後にAを実行する。
2. 人が承認済みGitHubセッションのUIで4つのPAT作成画面を確認し、表示フィールドを記録する。今回PATは発行していない。
3. 使い捨てテスト環境でClaude CodeまたはCodex CLIのtemplateあり/なし比較を行い、注入文面が境界を越えないことを確認する。

この報告は観測できた事実と未検証項目を分けた部分報告であり、3項目すべての実機検証完了を示さない。
