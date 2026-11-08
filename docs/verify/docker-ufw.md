# Docker公開ポートとUFWの実機検証（Issue #8・途中経過）

2026-11-08 18:32–18:37 JST、検証専用の使い捨てさくらのVPSで実施した。
接続先はSSH alias `sakura-test` を使用した。IPアドレス・ログインユーザー名・鍵情報は記載しない。

**外部からの基準到達性を確認できておらず、3項目の検証は未完了。**
VPS内のHTTPは200だが、Windows PCからVPSのグローバルIPv4宛てTCP 8080は3回ともタイムアウトした。
この結果をUFWによる遮断やDockerのUFW回避の成否として扱わない。
さくら側パケットフィルターのTCP 8080設定確認を依頼し、コンテナを削除してFirewallを復元した。
パケットフィルターが実際の原因かは未確認である。

## 環境

| 項目 | 実測値 |
| --- | --- |
| VPS OS | Ubuntu 24.04 LTS (Noble Numbat) |
| カーネル | `6.8.0-36-generic` |
| Docker Engine / CLI | `29.9.3` / `29.9.3` |
| Docker Firewall backend | `iptables`（新規導入のデフォルト。`daemon.json`なし、`DOCKER-USER`とDockerのDNATルールを実測） |
| iptables実装 | `iptables v1.8.10 (nf_tables)` |
| UFW | `0.36.2` |
| nginx | `1.30.6` |
| イメージ | `nginx:stable-alpine` |
| 取得時のdigest / image ID | `sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311` |
| 外部クライアント | 利用者のWindows PC上のPython。HTTPプロキシを使わずVPSのIPv4へ直接接続 |
| 開始前 | Docker未導入、8080のlistenerなし、UFW inactive、IPv4/IPv6 iptablesルールなし（組込みpolicyはACCEPT） |

`nf_tables` はiptablesコマンドの実装を示す。Docker自身のnftables backendを使ったという意味ではない。
今回の測定対象はIPv4のみで、IPv6からの外部到達は試していない。

## 事前保存とDocker導入

SSHホスト鍵は利用者がVPSコンソールのfingerprintと照合し、クライアントからは
`StrictHostKeyChecking=yes`、`ForwardAgent=no`で接続した。
専用公開鍵を使用し、秘密鍵をVPSへ転送していない。

変更前に、rootのみアクセスできるVPS内の`/var/lib/vps-check-issue8/`へ次を保存した。
これらの生の復元用データはリポジトリやローカルログに転記していない。

```sh
iptables-save > /var/lib/vps-check-issue8/iptables.before
ip6tables-save > /var/lib/vps-check-issue8/ip6tables.before
tar -cpf /var/lib/vps-check-issue8/ufw.before.tar -C / etc/ufw etc/default/ufw
ufw status
sysctl -n net.ipv4.ip_forward
sysctl -n net.ipv6.conf.all.forwarding
```

```text
Status: inactive
SSH_PORT=22
DOCKER_PREEXISTING=no
```

空の`iptables-save`/`ip6tables-save`は、それぞれ0バイトだった。
そのままでは後で新しいDockerルールを除去する復元にならないため、導入前に停止し、
`iptables -t <table> -S`で確認した元の組込みACCEPT policyを明示した復元形式を作成した。
元の0バイトのデータも別途保持した。対象tableは`filter`、`nat`、`mangle`、`raw`、`security`。
この補正時点ではUFW変更・Docker導入は行っていない。

接続断に備え、root所有の復元スクリプトを用意し、20分後の一回限りのsystemd rollback timerを起動した。
完了時はtimerを停止し、手動で同じ復元処理を実行した。

Dockerは[公式Ubuntu向けapt手順](https://docs.docker.com/engine/install/ubuntu/)に従って導入した。
既存SSH許可を消す`ufw reset`は行わず、OpenSSH許可を先に追加した。

```sh
ufw allow OpenSSH
ufw default deny incoming
ufw --force enable
apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release; echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker version --format 'Client={{.Client.Version}} Server={{.Server.Version}}'
iptables --version
ufw --version
iptables -S DOCKER-USER
docker pull nginx:stable-alpine
```

aptの進捗行は省略。関連する実出力は以下。

```text
Rules updated
Rules updated (v6)
Default incoming policy changed to 'deny'
Firewall is active and enabled on system startup
Client=29.9.3 Server=29.9.3
iptables v1.8.10 (nf_tables)
ufw 0.36.2
-N DOCKER-USER
Digest: sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311
```

## 1. UFW deny incomingとDockerの全interface公開

取得したimage IDを`image.id`から読み、同じイメージを指定した。
専用コンテナだけに固定の確認文字列を置いた。

```sh
docker run -d --name vps-check-issue8 --label vps-check.issue=8 \
  -p 8080:80 "$(cat /var/lib/vps-check-issue8/image.id)"
docker exec vps-check-issue8 sh -c "printf 'vps-check-issue8\n' > /usr/share/nginx/html/index.html"
docker exec vps-check-issue8 nginx -v
docker port vps-check-issue8
curl -fsS --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 http://127.0.0.1:8080/
ufw status verbose
```

```text
nginx version: nginx/1.30.6
80/tcp -> 0.0.0.0:8080
80/tcp -> [::]:8080
vps-check-issue8
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)
```

Windows PC側では次のPython処理で接続した。`<VPS_IP>`は実行時にSSH設定からメモリ上に取得し、
この記録では伏せている。各接続は新規接続で、timeoutは5秒、試行間隔は1秒。

```python
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open("http://<VPS_IP>:8080/", timeout=5) as response:
    body = response.read(4096)
    # HTTP statusと body == b"vps-check-issue8\n" を確認する
```

```text
CLIENT=Windows PC; destination=<VPS_IP>:8080
1: HTTPなし / URLError / 5.012秒
2: HTTPなし / URLError / 5.013秒
3: HTTPなし / URLError / 5.014秒
```

この後、VPS内から再度ローカル応答を確認し、Docker転送カウンターを読んだ。
以下の`<CONTAINER_IP>`はDockerが割り当てたアドレスの伏字。

```sh
iptables -t nat -nvxL DOCKER --line-numbers
iptables -nvxL FORWARD --line-numbers
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 5 http://127.0.0.1:8080/
```

```text
DOCKER DNAT: packets=0 bytes=0 tcp dpt:8080 to:<CONTAINER_IP>:80
FORWARD -> DOCKER-USER: packets=0 bytes=0
FORWARD -> DOCKER-FORWARD: packets=0 bytes=0
LOCAL_HTTP_STATUS=200
```

カウンター行は実測した列を抜粋して表記した。外部パケットがDocker転送処理へ届いた証拠は得られていない。
VPS内のnginxと公開設定が動作することは確認したが、外部到達性がないためUFW回避の実機判定は保留。
さくら側のTCP 8080フィルター設定確認・許可の反映後に再測定する。

## 2. `127.0.0.1:8080:80`公開

未実施。全interface公開で外部から到達する基準を確認できていない。
その前提がない状態のtimeoutをlocalhost限定の効果と判定しない。

## 3. DOCKER-USERのconntrack DROP

未実施。同じ外部クライアントの到達を先に確認する必要がある。
予定するルールはIPv4の検証元・入口interface・元の宛先・TCP 8080・新規方向に限定し、
`--ctorigdstport 8080`を使う。SSHや他の既存通信を対象にしない。
外部接続成功→DROP後の遮断とcounter増加→ルール削除後の再到達、の順で確認する。

## 後片付けと復元の実測

所有labelが一致する専用コンテナを削除し、今回pullしたnginxイメージを削除した。
今回新規導入したDocker/socket/containerdを停止・無効化し、新しく作成された`docker0`を削除した。
UFW設定とIPv4/IPv6 iptables、IPv4/IPv6 forwarding値を開始前へ戻した。
namespaceを追加する検証は行っていない。

復元スクリプトはtable順序・コメント・生成時刻を除いてiptablesの保存値を照合した。
各table内のルール順序は保持して比較し、UFW設定ファイル群はSHA-256の一覧が一致した。

```text
IPTABLES_RESTORED=yes
IP6TABLES_RESTORED=yes
UFW_CONFIG_RESTORED=yes
Status: inactive
DOCKER_SERVICE=inactive
CONTAINERD_SERVICE=inactive
PORT_8080_LISTENER=absent
CLEANUP_ERRORS=0
IPV4_FORWARDING_RESTORED=yes
IPV6_FORWARDING_RESTORED=yes
SSH_PORT=22
ROLLBACK_TIMER=inactive
CLEANUP_MARKER=complete
```

Docker関連パッケージと公式apt sourceは導入済みのまま残っている。
SSH認証設定および利用者が追加した一時sudo設定は、継続検証のため維持している。
一時sudo設定は検証終了時に削除する予定。root専用復元データはVPSの削除まで保持する。
VPS自体の削除は利用者が行う。記事公開・PRマージは行っていない。

## 現在の判定

| 項目 | 状態 | 判定根拠 |
| --- | --- | --- |
| 1. Docker公開ポートはUFWを回避するか | 未判定 | VPS内HTTP 200、外部は3回timeout、Docker転送counter 0 |
| 2. localhost限定で外部到達を防げるか | 未実施 | 外部到達の基準が成立していない |
| 3. DOCKER-USERのconntrack DROPで防げるか | 未実施 | 同上 |
| 後片付け | 今回分は完了 | コンテナ/image削除、service停止、8080 listenerなし、元のFirewallとUFW設定を照合 |

参考: [DockerとUFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw)、
[DOCKER-USERと元の宛先portの照合](https://docs.docker.com/engine/network/firewall-iptables/#match-the-original-ip-and-ports-for-requests)。
公式説明と今回の未完了の実機検証結果を区別する。

記録作成時のrepository必須チェックは`go test ./...`、`go vet ./...`、`go build ./...`がすべて成功。
これらはCLIの回帰チェックであり、未実施の外部到達性検証を補うものではない。
