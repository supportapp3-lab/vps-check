# Docker公開ポートとUFWの実機検証（Issue #8）

2026-11-08、検証専用の使い捨てさくらのVPSで実施した。
初回は18:32–18:37 JST、外部フィルター許可後の3項目の測定・復元確認は19:12–19:15 JST。
接続先はSSH alias `sakura-test` を使用した。IPアドレス・ログインユーザー名・鍵情報は記載しない。

**この環境では3項目を実測できた。** 同じWindows PCからのIPv4接続で、
UFW deny incomingでもDockerの全interface公開はHTTP 200、localhost限定は外部timeout、
DOCKER-USERのconntrack DROPも外部timeoutとなった。DROPのcounter増加と削除後のHTTP 200回復も確認した。

初回は外部から3回timeoutとなったため結論を保留して復元した。
本人がさくら側パケットフィルターのTCP 8080未許可を確認し、許可設定の保存完了を連絡した後に再開した。
VPS内だけの応答や、外部フィルター未許可時のtimeoutを成功判定に使っていない。

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

カウンター行は実測した列を抜粋して表記した。ここまでは初回の結果であり、成否を保留した。

### 外部フィルター許可後の再測定

本人からTCP 8080許可の保存完了を受けて、元のFirewall/UFW設定が維持されていることを確認し、
同じdigestのイメージを再取得して、同じ公開コマンドと本文を使用した。
UFWは引き続きactive、deny incoming、許可項目はOpenSSHだけである。

```text
80/tcp -> 0.0.0.0:8080
80/tcp -> [::]:8080
VPS内: vps-check-issue8
Windows外部1: HTTP 200 / marker一致 / 0.076秒
Windows外部2: HTTP 200 / marker一致 / 0.054秒
Windows外部3: HTTP 200 / marker一致 / 0.076秒
```

外部到達が3回成立したため、この環境のIPv4ではDockerの公開ポートがUFWの受信拒否を回避することを確認した。
他のDocker backendやprovider設定まで一般化しない。

## 2. `127.0.0.1:8080:80`公開

前項の外部HTTP 200成立後、所有labelを確認して専用コンテナだけを削除し、同じimage IDでbindだけを変更した。

```sh
docker rm -f vps-check-issue8
docker run -d --name vps-check-issue8 --label vps-check.issue=8 \
  -p 127.0.0.1:8080:80 "$(cat /var/lib/vps-check-issue8/image.id)"
docker exec vps-check-issue8 sh -c "printf 'vps-check-issue8\n' > /usr/share/nginx/html/index.html"
docker port vps-check-issue8
curl -fsS --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 http://127.0.0.1:8080/
```

```text
80/tcp -> 127.0.0.1:8080
vps-check-issue8
Windows外部1: HTTPなし / URLError / 5.008秒
Windows外部2: HTTPなし / URLError / 5.010秒
Windows外部3: HTTPなし / URLError / 5.016秒
```

同じ外部クライアント・UFW・provider設定のまま、localhost応答を維持して外部到達を防げた。
この後、全interface公開に戻すと再び外部3回ともHTTP 200となった（次項の基準測定）。

## 3. DOCKER-USERのconntrack DROP

前項のコンテナを削除して`-p 8080:80`に戻し、同じ固定本文を置いた。

```text
DROP前の外部1: HTTP 200 / marker一致 / 0.054秒
DROP前の外部2: HTTP 200 / marker一致 / 0.049秒
DROP前の外部3: HTTP 200 / marker一致 / 0.050秒
```

SSHセッション情報からメモリ上で検証PCの送信元IPv4とVPSの宛先IPv4を取得し、
その経路のinterface（`ens3`）を確認した。以下はIPを伏せた実行コマンドである。
変数への具体値はログ・repositoryに転記していない。

```sh
rule=(-i "$iface" -s "$client" -p tcp -m conntrack \
  --ctdir ORIGINAL --ctstate NEW --ctorigdst "$server" --ctorigdstport 8080 \
  -m comment --comment vps-check-issue8 -j DROP)
# 同一ruleが既にないことを確認してから挿入
iptables -w 5 -C DOCKER-USER "${rule[@]}" 2>/dev/null
iptables -w 5 -I DOCKER-USER 1 "${rule[@]}"
iptables -S DOCKER-USER
curl -fsS --max-time 5 http://127.0.0.1:8080/
```

上の`-C`はruleがないため終了1となることをguardで確認し、挿入を継続した。
ルールの一致対象は、この検証PCから対象VPSの8080へ入るIPv4 TCPの新規接続だけ。
SSHの22番と既存接続は含まない。DNAT後の宛先port80との誤照合を避け、元の宛先8080を使う。

```text
-N DOCKER-USER
-A DOCKER-USER -s <CLIENT_IP>/32 -i ens3 -p tcp -m conntrack --ctstate NEW --ctorigdst <VPS_IP> --ctorigdstport 8080 --ctdir ORIGINAL -m comment --comment vps-check-issue8 -j DROP
VPS内: vps-check-issue8
DROP後の外部1: HTTPなし / URLError / 5.005秒
DROP後の外部2: HTTPなし / URLError / 5.014秒
DROP後の外部3: HTTPなし / URLError / 5.014秒
```

外部試行後にcounterを確認した。

```sh
iptables -nvxL DOCKER-USER --line-numbers
```

```text
Chain DOCKER-USER (1 references)
num pkts bytes target prot opt in   out source      destination
1   9    468   DROP   6    --  ens3 *   <CLIENT_IP> 0.0.0.0/0  ctstate NEW ctorigdst <VPS_IP> ctorigdstport 8080 ctdir ORIGINAL /* vps-check-issue8 */
```

9は遮断されたパケット数であり、HTTPリクエスト数ではない。接続試行は3回でTCP再送を含む。
同じrule引数配列をroot専用ファイルへ保存しておき、削除時はその配列を読み戻してexact ruleを指定した。

```sh
mapfile -t rule < /var/lib/vps-check-issue8/drop.args
iptables -w 5 -D DOCKER-USER "${rule[@]}"
iptables -S DOCKER-USER
```

```text
-N DOCKER-USER
TEST_DROP_RULE_REMOVED=yes
削除後の外部1: HTTP 200 / marker一致 / 0.055秒
削除後の外部2: HTTP 200 / marker一致 / 0.050秒
削除後の外部3: HTTP 200 / marker一致 / 0.050秒
```

到達成功→対象ruleでのcounter増加と遮断→削除後の到達回復が成立し、この環境でconntrack DROPの効果を確認した。

## 後片付けと復元の実測

所有labelが一致する専用コンテナを削除し、今回pullしたnginxイメージを削除した。
今回新規導入したDocker/socket/containerdを停止・無効化し、新しく作成された`docker0`を削除した。
UFW設定とIPv4/IPv6 iptables、IPv4/IPv6 forwarding値を開始前へ戻した。
namespaceを追加する検証は行っていない。

復元スクリプトはtable順序・コメント・生成時刻・chainの可変packet/byte counterを除いてiptablesの保存値を照合した。
各table内のルール順序は保持して比較し、UFW設定ファイル群はSHA-256の一覧が一致した。
再開前のguardがpacket counterだけの変化も設定変更として停止したため、読取診断でルールとUFWの一致を確認し、
counterだけを比較対象から除いた。実際のルール変更を無視する緩和は行っていない。

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
TEMPORARY_PASSWORDLESS_SUDO_REMOVED=yes
SSH_AUTHENTICATION=ok
PASSWORDLESS_SUDO_UNAVAILABLE=yes
```

Docker関連パッケージと公式apt sourceは導入済みのまま残っている。
SSH認証設定は維持し、今回の一時sudo設定は、内容が本人の作成したruleと一致することを確認して削除した。
新しいSSHセッションで鍵認証成功と、passwordless sudoが利用できなくなったことを確認した。
root専用復元データはVPSの削除まで保持する。
VPS自体の削除は利用者が行う。記事公開・PRマージは行っていない。
さくら側のTCP 8080許可も利用者による管理であり、VPSを残す場合は検証用許可を戻す必要がある。

## 現在の判定

| 項目 | 状態 | 判定根拠 |
| --- | --- | --- |
| 1. Docker公開ポートはUFWを回避するか | この環境では確認 | UFW active/deny incoming/OpenSSHのみ許可でも外部3回HTTP 200・本文一致 |
| 2. localhost限定で外部到達を防げるか | この環境では確認 | localhost応答維持、外部3回timeout。全interfaceに戻すと外部HTTP 200 |
| 3. DOCKER-USERのconntrack DROPで防げるか | この環境では確認 | 外部成功→DROPでtimeout・9packet/468byte→exact rule削除で外部成功 |
| 後片付け | 完了 | コンテナ/image削除、service停止、8080 listenerなし、元のFirewall/UFW/forwardingを照合。一時sudo削除とSSH維持を再確認 |

参考: [DockerとUFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw)、
[DOCKER-USERと元の宛先portの照合](https://docs.docker.com/engine/network/firewall-iptables/#match-the-original-ip-and-ports-for-requests)。
この一構成の実測であり、他のDocker/kernel/provider/backendやIPv6まで保証するものではない。

記録作成時のrepository必須チェックは`go test ./...`、`go vet ./...`、`go build ./...`がすべて成功。
これらはCLIの回帰チェックであり、外部到達性については上記の別の実測によって確認した。
