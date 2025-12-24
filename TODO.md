# TODO - 次回再開時のタスク

## ✅ 完了済み

- [x] LangGraph マルチエージェント構成
- [x] Operator中心のハブ・スポーク構成
- [x] Docker化（python:3.11-slim）
- [x] Flask Webアプリ + Tailwind UI
- [x] グラフ可視化（PNG/Mermaid）
- [x] NVD API 実装・動作確認
- [x] MITRE CVE API 実装・動作確認
- [x] GitHub Search API 実装・動作確認
- [x] Exploit リトライループ（最大5回）
- [x] 不要ファイル削除・リファクタリング

## 🔲 未完了・改善点

### 高優先度

1. **ExploitDB 実装**
   - 現在はプレースホルダー
   - 公開APIがないため、GitLabミラー or スクレイピングを検討
   - https://gitlab.com/exploit-database/exploitdb

2. **Exploit 実行の実装**
   - 現在はシミュレーション（ランダム成功/失敗）
   - 実際のスクリプト実行ロジックを追加
   - サンドボックス環境での実行を検討

3. **LLM統合**
   - 現在はルールベースの判定
   - OpenAI/Claude APIを使ってOperatorの判断をLLMで行う
   - CVE分析の要約をLLMで生成

### 中優先度

4. **エラーハンドリング強化**
   - APIレート制限時のリトライ
   - タイムアウト処理の改善

5. **PoC検索の精度向上**
   - CVE-IDからGitHub検索クエリを最適化
   - スター数・更新日でフィルタリング

6. **レポート形式の改善**
   - PDF出力
   - JSON/SARIF形式でのエクスポート

### 低優先度

7. **UIの改善**
   - リアルタイム進捗表示（WebSocket）
   - 過去スキャン履歴の保存

8. **テストの追加**
   - ユニットテスト
   - API モック

9. **本番環境対応**
   - Gunicorn/uWSGI
   - ログ出力の改善
   - ヘルスチェックエンドポイント

## 🔧 起動方法

```bash
# Docker起動
docker build -t ai-redteam .
docker run -d --rm --name ai-redteam -p 8080:8080 ai-redteam

# アクセス
open http://localhost:8080

# テスト実行
curl -X POST http://localhost:8080/api/run \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "log4j", "dry_run": true}'
```

## 📝 メモ

- NVD APIはキーなしでも動作するがレート制限あり
- GitHub APIは認証なしで60リクエスト/時間
- MITRE APIはCVE-ID形式での検索が最適
