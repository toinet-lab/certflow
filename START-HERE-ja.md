# はじめ方ガイド（GitHub・ライセンス・Cowork がはじめての方へ）

このプロジェクト一式を、GitHub もライセンスも Cowork も使ったことがない前提で、
最初から動かすための手順書です。上から順にやれば動きます。

---

## 0. 全体像（何を・どの順で）

作るもの：`certflow` という「証明書の有効期限を一覧するツール」。まずは
**読み取り専用（Phase 0）**。安全に始められて、実務にもすぐ役立ちます。

流れはこの3層です。

1. **置き場所**＝GitHub（コードを公開・保存する場所）
2. **安全網**＝ガードレール CI（変更のたびに自動でセキュリティ・著作権を検査）
3. **自動化＋承認**＝Cowork（あなたの承認を挟みながら開発を回す）

---

## 1. 用語の最小知識（これだけ分かれば十分）

- **Git**：変更履歴を記録する仕組み（お使いの PC に入れるソフト）。
- **GitHub**：Git のプロジェクトを置くクラウド上のサービス。
- **リポジトリ（repo）**：1つのプロジェクトの入れ物（このフォルダ全体）。
- **コミット（commit）**：変更に「ここまでの区切り」として記録を付ける操作。
- **ブランチ（branch）**：作業用の枝。本流は `main`。枝で作業して後で本流に合流。
- **プルリクエスト（PR）**：枝の変更を `main` に取り込む前の「レビュー依頼」。
  ここが**承認の関所**になります。
- **CI**：PR やコミストのたびに GitHub が自動で走らせる検査（＝ガードレール）。

イメージ：`main`（本番の本流）を直接いじらず、**枝で直す→PR で見せる→
CI が検査→あなたが承認して合流**、という流れです。

---

## 2. ライセンスとは / なぜ MIT

ソフトを公開するとき「他人が何をしてよいか」を決めるのがライセンスです。
無指定だと逆に**誰も安心して使えません**。主な選択肢：

- **MIT**：一番シンプル。「著作権表示さえ残せば、自由に使ってよい」。今回はこれ。
- **Apache-2.0**：MIT に近い許容的ライセンス＋特許条項。より企業向けで手厚い。
- **GPL / AGPL（コピーレフト）**：「使うなら派生物もソース公開せよ」と強制する型。
  → **あなたのツールに混ざると、無料公開＋有償サポートの形と相性が悪い**ので、
  混入を CI（ScanOSS）で弾きます。

同梱の `LICENSE` は MIT です。`YOUR NAME` をあなたの名前に置き換えてください。

---

## 3. 準備（アカウントとソフト）

1. **GitHub アカウント**を作成（https://github.com）。ユーザー名を決めます。
2. **Git** を導入。
   - Windows：https://git-scm.com からインストーラ、または「GitHub Desktop」
     （GUI で分かりやすい：https://desktop.github.com）。
   - Mac：`git` は多くの場合入っています。無ければ `xcode-select --install`。
3. **Go**（このツールのビルドに必要）：https://go.dev/dl/ から 1.22 以降。

> コマンド操作が不安なら、まず **GitHub Desktop** を入れると、コミットや
> push をボタン操作でできます。以下はコマンド版の説明ですが、GitHub Desktop
> でも同じことができます。

---

## 4. 自分用に名前を差し替える

このひな型はモジュール名が `github.com/toinet-lab/certflow` になっています。
`toinet-lab` をあなたの GitHub ユーザー名に置き換えます（フォルダ内で一括置換）。

Mac / Linux：
```sh
grep -rl 'toinet-lab' . | xargs sed -i 's/toinet-lab/あなたのユーザー名/g'
```
Windows（PowerShell）:
```powershell
Get-ChildItem -Recurse -File | ForEach-Object {
  (Get-Content $_.FullName) -replace 'toinet-lab','あなたのユーザー名' | Set-Content $_.FullName
}
```
`LICENSE` の `YOUR NAME`、`.github/CODEOWNERS` の `@toinet-lab` も自分の名前／
ユーザー名にしておきます。

---

## 5. GitHub にリポジトリを作って上げる

1. GitHub 右上「＋」→ **New repository**。
   - Repository name：`certflow`
   - **Public**（無料公開）を選択
   - 「Add a README」などの初期ファイルは**付けない**（こちらで用意済みのため）
   - **Create repository**
2. 表示されるコマンドのうち「push an existing repository」を使います。
   このフォルダで：
   ```sh
   git init
   git add .
   git commit -s -m "Initial commit: certflow Phase 0"
   git branch -M main
   git remote add origin https://github.com/あなたのユーザー名/certflow.git
   git push -u origin main
   ```
   （`-s` は署名付きコミット。CONTRIBUTING の DCO 用です。）

これで GitHub 上にコードとファイルが並びます。`.github/workflows` があるので、
**push した瞬間に CI（ガードレール）が自動で走ります**。

---

## 6. 安全設定（最初に1回だけ）

GitHub のリポジトリ画面 → **Settings** で以下をオンにします。

1. **ブランチ保護**（Settings → Branches → Add branch ruleset か Add rule）
   - 対象：`main`
   - 「Require a pull request before merging」＝ main に直接コミット禁止
   - 「Require status checks to pass」→ `build & test` や `license & snippet
     scan` などを必須に（＝CI が緑でないとマージ不可）
   → これで「承認とレビューを経てからだけ合流」が仕組みとして固定されます。
2. **シークレット検査**（Settings → Code security）
   - 「Secret scanning」と「Push protection」をオン（鍵やトークンの誤コミット防止）
   - 「Private vulnerability reporting」をオン（脆弱性の非公開報告を受けられる）

---

## 7. CI（ガードレール）の見方

PR やコミット画面の下、または上部 **Actions** タブで結果が見えます。

- 緑のチェック＝合格。赤い×＝要確認。
- 走る検査：ビルド＆テスト、CodeQL（脆弱性の静的解析）、**ScanOSS
  （コピーレフト混入を検出したら PR を止める）**、Trivy、govulncheck、
  gitleaks、SBOM 生成。
- **ライセンス検査が赤**になったら、チェックを外すのではなく、指摘された
  コードを取り除く／書き直すのが正解です（それがこの仕組みの目的です）。

最初は赤が出ても慌てないでください。多くは「報告のみ（止めない）」設定です。
止める設定は「ビルド／テスト」と「コピーレフト検査」だけにしてあります。

---

## 8. ツールを使ってみる

```sh
go build -o certflow .
./certflow example.com example.org:443
# 一覧ファイルで、21日を切ったら警告表示、JSON 出力
cp hosts.example.txt hosts.txt   # 中身を自分の環境に書き換え
./certflow -file hosts.txt -warn 21 -json
```
`-fail-under 14` を付けると「14日以内に切れる証明書があれば終了コード2」を返すので、
cron や監視から呼ぶのに使えます（読み取り専用なので安全です）。

---

## 9. Cowork の始め方

Cowork は、Claude に複数ステップの作業を任せ、要所であなたの承認を挟める機能です。
Pro / Max / Team / Enterprise プランで使え、**デスクトップ版が最も高機能**
（ローカルのファイルを扱える）です。Web・モバイルはベータで、外出先からの
確認・軌道修正に向きます。

1. Claude を開き、メッセージ入力欄で **「Cowork」** を選ぶ（通常のチャットに
   戻すときは「Chat」）。
2. **標準指示文を登録**：`docs/cowork-global-instructions-ja.md` の
   「コピーする本文」を、**Settings → Cowork → Global instructions** に貼り付け。
   これで毎回のセッションに承認ルールとガードレールが効きます。
3. **モードを選ぶ**（入力欄のモード切替）
   - **Manual（手動承認）**：既定。公開・本番・マージなど不可逆な操作は必ず承認。
   - **Auto（自動承認）**：内部の調査・下書き・要約など、やり直せる作業だけに使う。
   - **Skip**：使わない。
4. 判断が要る場面では、**スマホに確認が飛び**、進行中の作業を途中で軌道修正できます。

> メニューの正確な名称はベータのため変わることがあります。最新は
> support.claude.com（Cowork のヘルプ）で確認してください。

**Cowork にやらせないこと**：本番の証明書更新そのものをスケジュール実行させない
でください。Cowork の予約実行は PC が起動している必要があり、スリープ中は動きません。
本番の更新は将来 systemd タイマーや GitHub Actions など確実な仕組みに持たせ、
Cowork は「開発を回す側」に徹させます。

---

## 10. 毎日の回し方（このループを回すだけ）

1. 要望・不具合が **Issue** で届く（テンプレートで整理される）
2. Cowork がトリアージ（ラベル・重複・要約）し、**対応案（計画）を提示**
3. あなたが計画を**承認**
4. 実装は背景エージェントにブランチ＋PR で作らせる
5. **ガードレール CI が緑**になる（赤なら直す）
6. あなたが **PR をレビューして承認・マージ**
7. 区切りがついたら **リリース**（ここも承認）

承認は「計画→着手」「PR→マージ」「リリース」の節目に絞ると、確認が形骸化せず、
大事な場面に集中できます。

---

## 11. 最初の1週間チェックリスト

- [ ] GitHub アカウント・Git・Go を用意
- [ ] `toinet-lab` と `YOUR NAME` を自分用に置換
- [ ] `certflow` リポジトリを Public で作成し push
- [ ] main のブランチ保護＋シークレット検査をオン
- [ ] CI が動くことを Actions タブで確認
- [ ] `certflow` をビルドして手元の数ホストで試す
- [ ] Cowork に標準指示文を登録し、Manual モードで小さな作業を1つ依頼
- [ ] Issue を1件作り、Cowork にトリアージ→計画提示→承認の流れを試す

ここまでできたら、あとは Phase 1（発行）に進む前に、しばらく Phase 0 を
運用して手応えを掴むのがおすすめです。
