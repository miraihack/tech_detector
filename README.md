# Tech Detector

Webサイトで使用されている技術スタックとセキュリティ構成を包括的に検出・分析するブラウザ拡張機能（Chrome / Firefox 対応、Manifest V3）。

JSフレームワーク、CMS、CDN、アナリティクスなど **65種以上の技術** を6つの検出手法で識別し、TLS/証明書・セキュリティヘッダー・DNS・メール認証・Cookie・ページ診断・VirusTotal連携まで、サイトのセキュリティ状態を一画面で確認できます。

---

## 主な機能

### 技術検出（65種 / 12カテゴリ）

| カテゴリ | 検出対象例 |
|---------|-----------|
| JS フレームワーク | React, Vue.js, Angular, Svelte, Next.js, Nuxt, Gatsby, Remix, Ember.js, Backbone.js, Alpine.js, htmx |
| JS ライブラリ | jQuery, Lodash, Axios, Moment.js, Three.js, D3.js |
| CSS フレームワーク | Tailwind CSS, Bootstrap, Bulma, Foundation, Materialize |
| CMS / EC | WordPress, Shopify, Wix, Squarespace, Webflow, Drupal, Ghost |
| Web サーバー | nginx, Apache, IIS, LiteSpeed |
| サーバー OS | Windows Server, Ubuntu, Debian, CentOS, Red Hat, FreeBSD, Unix |
| アナリティクス | Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Segment, Mixpanel |
| CDN | Cloudflare, Fastly, CloudFront, Akamai, jsDelivr |
| フォント | Google Fonts, Adobe Fonts, Font Awesome |
| ホスティング | Vercel, Netlify, Heroku, GitHub Pages |
| ビルドツール | Webpack, Vite, Parcel |
| セキュリティ | reCAPTCHA, hCaptcha, Service Worker |

### 6つの検出手法

| 手法 | 説明 | 例 |
|------|------|-----|
| **JS グローバル変数** | `window` 直下のオブジェクトを探査し、バージョンも抽出 | `jQuery.fn.jquery` → `3.7.1` |
| **DOM セレクタ** | CSSセレクタでフレームワーク固有の属性を検出 | `[data-reactroot]`, `[ng-version]` |
| **Script src** | `<script>` タグの `src` を正規表現でマッチ | `react.min.js`, `_next/static` |
| **Meta タグ** | `<meta name="generator">` 等の内容を解析 | `WordPress 6.2` |
| **HTTP ヘッダー** | レスポンスヘッダーからサーバー情報を取得 | `server: nginx`, `x-powered-by: Express` |
| **HTML ソース** | HTML先頭50KBを正規表現でスキャン | `wp-content`, `tailwindcss` |

### セキュリティ分析

#### 暗号化 / TLS
- HTTPS 使用状況・SSL Labs グレード
- TLS バージョン（1.2 / 1.3）
- 暗号スイート・鍵長
- HTTP バージョン（HTTP/1.1, HTTP/2, HTTP/3）
- HSTS 設定状況

#### 耐量子計算機暗号（PQC）— Firefox 専用

> ⚠️ この機能は **Firefox 109 以降専用** です。Chrome / Chromium では表示されません。

- 鍵交換アルゴリズムの PQC 対応状況（ハイブリッド構成 / Pure PQC / 現行暗号）
- 検出例: `ハイブリッド構成（X25519MLKEM768）`、`Pure PQC（MLKEM768）`
- 証明書署名アルゴリズムの PQC 対応状況（ML-DSA / SLH-DSA / Falcon 等）
- 総合評価（PQC対応 / 完全対応 / 未対応）
- 検出方法: Firefox `webRequest.getSecurityInfo()` による実際のネゴシエーション結果

#### 証明書情報
- 発行元 CA・Subject DN
- 鍵アルゴリズム・署名アルゴリズム
- 有効期間・残り日数・失効警告
- Subject Alternative Names（SANs）

#### セキュリティヘッダー
- Content-Security-Policy（CSP）
- X-Content-Type-Options / X-Frame-Options / X-XSS-Protection
- Referrer-Policy / Permissions-Policy
- Cross-Origin-Opener-Policy（COOP）/ Cross-Origin-Resource-Policy（CORP）

#### 情報漏洩チェック
- Server / X-Powered-By ヘッダーの露出
- CORS 設定（`Access-Control-Allow-Origin: *` の検出）

#### Cookie セキュリティ
- Secure / HttpOnly / SameSite フラグの設定状況

#### メール認証
- SPF / DMARC / DKIM の設定状況
- DKIM は主要セレクタ（google, selector1, selector2, k1 等）を自動探査

#### DNS セキュリティ
- DNSSEC 有効性
- CAA（認証局制限）レコード
- BIMI（ブランドインジケーター）

#### DNS 情報
- IP アドレス解決・逆引き（PTR）
- ネームサーバー（NS）一覧
- MX レコード

#### ページ診断
- Mixed Content 検出（HTTPS上のHTTPリソース）
- 外部スクリプトのドメイン数
- SRI（Subresource Integrity）未設定の検出
- インラインイベントハンドラの検出
- HTTP上のパスワード入力欄
- サードパーティ iframe
- HTTP送信フォームの検出
- `target="_blank"` の `noopener` 未設定

#### 公開情報
- `security.txt` の設置状況
- `robots.txt` の機密パス露出（`/admin`, `/.env`, `/.git` 等）

#### VirusTotal 連携
- VirusTotal API v3 による URL 安全性チェック
- 判定表示（安全 / 疑わしい / 危険）
- 検出エンジン別の内訳（悪意 / 疑わしい / 安全 / 未検出）
- 評価スコア・最終分析日
- 無料 API キーで利用可能（設定ページから登録）

### UI

- ブラウザウィンドウ中央にポップアップウィンドウとして表示
- 2カラムレイアウト（左：技術検出・証明書・DNS等 / 右：セキュリティヘッダー・Cookie等）
- カテゴリ別グループ化・アイコン表示・バージョン表示
- パス / フェイル / ニュートラルの3段階ステータスインジケーター

---

## インストール

### Chrome / Chromium 系ブラウザ

1. このリポジトリをクローンまたはダウンロード
   ```
   git clone <repository-url>
   ```
2. `chrome://extensions` を開く
3. 右上の **デベロッパーモード** を有効化
4. **「パッケージ化されていない拡張機能を読み込む」** をクリック
5. `tech-detector/` ディレクトリを選択

### Firefox

1. このリポジトリをクローンまたはダウンロード
2. `about:debugging#/runtime/this-firefox` を開く
3. **「一時的なアドオンを読み込む」** をクリック
4. `tech-detector/manifest.json` を選択

> Firefox では一時的なアドオンとしての読み込みのため、ブラウザ再起動時に再読み込みが必要です。

### VirusTotal API キーの設定（任意）

1. [VirusTotal](https://www.virustotal.com/gui/join) に無料アカウント登録
2. プロフィールページから API キーを取得
3. 拡張機能の設定ページ（アイコン右クリック →「オプション」）で API キーを入力・保存

---

## 使い方

1. 任意の Web サイトにアクセス
2. ツールバーの Tech Detector アイコンをクリック
3. ブラウザウィンドウ中央にポップアップが開き、自動的に解析が開始
4. 技術検出結果とセキュリティ分析結果が2カラムで表示

---

## 技術詳細

### アーキテクチャ

```
background.js (Service Worker)
  ├── アイコンクリック → ポップアップウィンドウを中央に生成
  ├── HTTP レスポンスヘッダーからの技術検出
  ├── content script のプログラム的インジェクション
  ├── tabDetections{} によるタブごとの検出結果管理
  └── メッセージルーティング・バッジ更新

content.js (ISOLATED world)
  ├── technologies.json をロードして検出エンジン初期化
  ├── DOM・meta・script src・HTML（先頭50KB）からの検出
  ├── content-main.js からの JS 検出結果を postMessage で受信
  └── 全検出結果を merge して background.js へ送信

content-main.js (MAIN world)
  ├── ページの JS コンテキストにアクセス（window 直下のグローバル変数）
  ├── 500ms 遅延後に JS プローブ実行（フレームワーク初期化待ち）
  └── 結果を window.postMessage で content.js へ返送

detect.js (検出ロジックモジュール)
  ├── TechDetector オブジェクトとして検出関数をエクスポート
  └── content.js と background.js の両方から利用

popup/ (ポップアップ UI)
  ├── popup.js: 全チェックを Promise.all で並列実行・結果レンダリング
  ├── popup.html: 2カラムレイアウト
  └── popup.css: スタイル定義

options.html / options.js (設定ページ)
  └── VirusTotal API キーの管理
```

### メッセージング

| メッセージタイプ | 方向 | 用途 |
|----------------|------|------|
| `RUN_DETECTION` | popup.js → background.js | 検出実行リクエスト |
| `DETECTION_RESULT` | content.js → background.js | 検出結果送信 |
| `GET_DETECTIONS` | popup.js → background.js | キャッシュ済み結果取得 |
| `GET_TLS_INFO` | popup.js → background.js | Firefox TLS ネゴシエーション情報取得（Firefox専用） |
| `TECH_DETECTOR_JS_PROBE` | content-main.js → content.js | JS グローバル変数の探査結果（window.postMessage） |

### 検出フロー

```
アイコンクリック
  → background.js がポップアップウィンドウを生成（tabId・tabUrl をパラメータ渡し）
  → popup.js が RUN_DETECTION メッセージを送信
  → background.js が HEAD リクエストでヘッダー検出
  → content script をプログラム的にインジェクション
  → content.js が DOM / meta / script / HTML を解析
  → content-main.js が JS グローバル変数を探査（500ms 遅延）
  → 結果を merge → popup.js へ返却
  → 同時に暗号化・ヘッダー・Cookie・DNS 等のチェックを並列実行
  → 2カラムでレンダリング
```

### 外部 API

| API | 用途 | タイムアウト |
|-----|------|------------|
| [SSL Labs API](https://www.ssllabs.com/ssltest/) | TLS グレード・暗号スイート・証明書情報 | 4秒 |
| [Google Public DNS API](https://dns.google/) | DNS レコード照会（A / NS / MX / TXT / CAA / PTR） | — |
| [VirusTotal API v3](https://www.virustotal.com/) | URL 安全性チェック（要 API キー） | 8秒 |

### ファイル構成

```
tech-detector/
├── manifest.json           # 拡張機能マニフェスト（Manifest V3）
├── background.js           # Service Worker
├── content.js              # コンテンツスクリプト（ISOLATED world）
├── content-main.js         # コンテンツスクリプト（MAIN world）
├── detect.js               # 検出エンジン
├── technologies.json       # 技術定義データベース（65件）
├── options.html            # 設定ページ
├── options.js              # 設定ロジック
├── CLAUDE.md               # 開発ガイド
├── lib/
│   └── browser-polyfill.js # Firefox 互換ポリフィル
├── icons/
│   ├── icon-16.png         # 拡張機能アイコン（16 / 32 / 48 / 128px）
│   ├── icon-32.png
│   ├── icon-48.png
│   ├── icon-128.png
│   ├── icon.svg
│   └── techs/              # 技術アイコン（SVG、65件）
└── popup/
    ├── popup.html           # ポップアップ UI
    ├── popup.js             # ポップアップロジック
    └── popup.css            # スタイルシート
```

### 権限

| 権限 | 用途 |
|------|------|
| `scripting` | コンテンツスクリプトのプログラム的インジェクション |
| `cookies` | Cookie セキュリティ分析 |
| `storage` | VirusTotal API キーの永続化 |
| `webRequest` | HTTP レスポンスヘッダーの傍受 |
| `webRequestBlocking` | Firefox: TLS ネゴシエーション情報の取得（`getSecurityInfo()`） |
| `<all_urls>` (host) | 全サイトへのアクセス（ヘッダー取得・スクリプト注入） |

### ブラウザ互換性

| ブラウザ | サポート状況 |
|---------|------------|
| Chrome / Chromium | Manifest V3 完全対応 |
| Firefox | 109.0 以上、`browser-polyfill.js` による互換レイヤー。**耐量子計算機暗号（PQC）検出はFirefox専用** |

全スクリプトで `const api = typeof browser !== 'undefined' ? browser : chrome;` パターンを使用し、Chrome / Firefox 両方の API に対応しています。

### 技術的特徴

- **ビルドツール不要** — Webpack / Vite 等のバンドラーやパッケージマネージャーを使用せず、純粋な JavaScript / HTML / CSS のみで構成
- **並列実行** — 全チェックを `Promise.all` で同時実行し、高速に結果を表示
- **タイムアウト制御** — 外部 API には個別のタイムアウトを設定（4〜8秒）
- **マルチメソッド検出** — 同一技術を複数手法で検出した場合は自動マージ
- **グレースフルデグラデーション** — 制限ページ（`chrome://`、`about://` 等）でもエラーなく動作

---

## 技術定義の追加方法

`technologies.json` にエントリを追加します。

```json
{
  "name": "技術名",
  "category": "js-framework",
  "icon": "filename.svg",
  "js": { "GlobalVar": "version.path" },
  "dom": "[data-attribute]",
  "scripts": "regex-pattern\\.js",
  "meta": { "generator": "regex-pattern" },
  "headers": { "x-powered-by": "regex-pattern" },
  "html": "regex-pattern"
}
```

| フィールド | 説明 |
|-----------|------|
| `js` | グローバル変数プローブ（キー: 変数名、値: バージョンパス） |
| `dom` | CSS セレクタ |
| `scripts` | `<script src>` にマッチする正規表現 |
| `meta` | meta タグ（キー: name 属性、値: content 正規表現） |
| `headers` | HTTP ヘッダー（キー: ヘッダー名、値: 正規表現） |
| `html` | HTML 先頭50KB にマッチする正規表現 |

アイコンは `icons/techs/` に SVG ファイルとして配置してください。

### カテゴリ一覧

`js-framework`, `js-library`, `css-framework`, `cms`, `server`, `os`, `analytics`, `cdn`, `font`, `hosting`, `build`, `security`

---

## ライセンス

MIT
