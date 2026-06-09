# Ken-Apps — 開発メモ（Claude 向け知見）

トランジスタ社の業務用アプリ集。Google Apps Script (GAS) 製の小規模 Web アプリを
個人/社内向けに作っていく。最初のアプリは **TRANPASS**（暗号化パスワード管理）。

## ユーザーについて
- 日本語でやり取りする。
- **非技術者**。専門用語（PR、デプロイ、ブランチ等）は都度かみ砕いて説明する。
- 「まず構成を考えて、意図どおりになるまで確認してから開発」を好む。
  → いきなり実装せず、設計案を提示し `AskUserQuestion` で要点（セキュリティ方針など）を確認してから着手する。

## 進め方の型（このリポジトリの定番ワークフロー）
1. 設計案を提示 → 重要な分岐（アクセス範囲・暗号方式など）を質問で確定。
2. 指定ブランチで実装し、明確なメッセージでコミット＆プッシュ。
3. **PR はユーザーが明示的に頼んだときだけ作成**する。
4. 成果物は **ダウンロード用 ZIP** にして `SendUserFile` で渡す（GAS は ZIP 直接取込み不可なので、解凍して手貼り or clasp の手順を README に書く）。
5. ビルド成果物（`*.zip`）は `.gitignore` 済み。コミットしない。

## GAS アプリの設計で効いた知見（重要）
- **サーバー側 JS は 1 ファイル（`Code.gs`）に統合する。**
  - 理由: 手作業コピペでファイルを貼り忘れると `ReferenceError: xxx is not defined` が起きる。
    実際に `Crypto.gs` の貼り忘れで発生した。GAS は全 `.gs` が同一グローバルスコープなので統合で防げる。
- HTML は `HtmlService.createTemplateFromFile('Index')` 等で**名前参照**（拡張子なし `Index`/`Style`/`Script`）。
  `<?!= include('Style') ?>` でインライン展開する構成が扱いやすい。
- **Web アプリのデプロイ**: `appsscript.json` で `executeAs: USER_DEPLOYING` / `access: MYSELF`（自分専用が最も安全）。
- **コード修正後は再デプロイが必要**: 「デプロイを管理」→ ✏️ → バージョン「新バージョン」→「デプロイ」。
  URL は変わらない。ユーザーに毎回この手順を案内する。
- エラー対応時は、**画面に出る赤いメッセージの文言を聞く**のが最短（添付画像が届かないこともある）。
  クライアントの `withFailureHandler` で `err.message` をそのまま表示しておくと診断が速い。

## 暗号まわりの知見（TRANPASS）
- GAS にネイティブ AES は無い。**純 JS の AES-256（Chris Veness 系）を自前実装**し、
  CTR モード + **HMAC-SHA256（GAS ネイティブ `Utilities.computeHmacSha256Signature`）= Encrypt-then-MAC**。
- SHA-256 / HMAC / base64 は `Utilities`（ネイティブ）を使う。PIN は salt + ストレッチ（×2000）でハッシュ。
- **バイトの符号変換に注意**: GAS の `Byte[]` は -128..127。内部処理は 0..255 で行い、
  `Utilities` 受け渡し直前に signed へ変換するヘルパ（`toUnsigned`/`toSignedBytes`）を用意。
- マスターキー（32B）は Script Properties に保管し初回自動生成。**削除＝復号不能**なので警告を README に明記。
- **必ず検証する**: 実装した AES は ①NIST(FIPS-197) AES-256 既知応答 ②CTR ラウンドトリップ
  ③Node 標準 `aes-256-ctr` との一致、で Node 上でローカル検証してからコミットした。
  GAS 側にも `runSelfTest`（同等テスト）を同梱して現地確認できるようにした。

## UI/UX の知見
- モバイル前提（iPhone/PC/Mac）。ダークテーマ、タッチターゲット大きめ。
- ログインは**毎回シャッフルする数字グリッド**から PIN 桁を選ぶ覗き見対策。digits は **0〜9（10キー, 5×2）**。
- 破壊的/誤操作しやすい操作（編集ボタン等）は**小さく・控えめ・端に寄せる**。
  ユーザーから「編集ボタンが広すぎる」と指摘 → 全幅をやめ右寄せの小型アウトラインに変更して好評。
- 機微情報（パスワード/CVV）は伏字＋👁トグル、コピー後 60 秒で自動クリア。

## TRANPASS のファイル構成（参考）
```
src/Code.gs        サーバー全部（認証/CRUD/AES/セルフテスト）
src/Index.html     画面
src/Style.html     CSS
src/Script.html    クライアントJS
src/appsscript.json マニフェスト（scope: drive, script.storage / access: MYSELF）
```
