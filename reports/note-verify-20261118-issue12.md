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
