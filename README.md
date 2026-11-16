# dev-tools-jp

ブラウザだけで動く小さな無料Webツール集（日本語）です。

公開URL: https://supportapp3-lab.github.io/dev-tools-jp/

## 方針

- 静的サイトのみ（ビルドなしの素の HTML / CSS / JS）
- 入力内容はすべてブラウザ内で処理し、外部へ送信・保存しません
- 広告・アクセス解析タグは入れません

## 構成

- `/` … トップページ（ツール一覧）
- `/tools/<名前>/index.html` … 各ツールのページ

## ローカルで確認

```sh
python3 -m http.server
# http://localhost:8000/ を開く
```

## Compose設定チェッカー

`/tools/compose-check/` に設定全体を貼り付けてチェックします。値は貼り付け後にマスクされ、入力欄の編集をロックします。修正は元ファイルで行い全体を貼り直してください。入力と元の値はタブ内のメモリのみで扱い、送信・保存・外部ライブラリは使いません。

一般的な `services` のブロック形式、1行の配列/マップ、ports/volumesの短縮/長形式を簡易解析します。YAMLパーサーや実効設定の診断ではなく、アンカー・変数・複数ファイルの展開はしません。未確認の書式・参照先を案内し、検出ゼロでも安全とは限りません。詳細はページの注意点に記載しています。

Node標準機能だけで期待値テストを実行できます（通信不要、ダミー入力のみ）。

```sh
node tools/compose-check/test.js
node tools/agent-config-check/test.js
node tools/sshd-check/test.js
```

## JWTデコード＆安全チェック

`/tools/jwt-check/` ではJWTのヘッダーとペイロードをブラウザ内でデコードし、署名は表示せず長さだけを示します。署名検証や発行元の確認は行いません。入力を送信・保存せず、危ない例と通常の例は架空のダミー値です。

```sh
node tools/jwt-check/test.js
```

## nginx設定セキュリティチェッカー

`/tools/nginx-check/` は `http` / `server` / `location` の一部ディレクティブをブラウザ内で簡易確認します。入力は送信・保存されず、結果には設定値やパスを表示しません。nginxの構文検証・実効設定の診断・`include`先の読込みは行わず、検出ゼロでも安全を保証しません。確認項目と制約はページ内に記載しています。

```sh
node tools/nginx-check/test.js
```
