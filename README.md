# node_auth_passkey_1

 Version: 0.9.1

 Author  : 

 date    : 2026/11/07
 
 update  :

***

node.js , Passkey authrize SQLite example

* SQLite DB
* windows11 , Windows hello
* express
* node22
* Linux

***
* start
```
npm install
npm run start      # http://localhost:3000
```

***
## 使い方
- 下段の「新規登録」でユーザー名を入力 → Windows Hello(顔/指紋/PIN)で Passkey 作成
- 上段の「Windwos hello でログイン」おす
- ログアウト後、「Windows Hello でログイン」

## リリース準備
- HTTPS 必須。環境変数を設定:
    RP_ID=example.com ORIGIN=https://example.com SESSION_SECRET=長いランダム文字列 npm start
- RP_ID はドメインと一致させる(後から変更すると既存 Passkey は使えなくなります)
- セッションストアは本番では connect-sqlite3 等へ変更推奨(既定はメモリ)


***
### version
* V_0_9_1: new

***
### blog

https://zenn.dev/knaka0209/scraps/713e2a9cd12fd9

