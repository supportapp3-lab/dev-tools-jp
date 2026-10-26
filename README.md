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
