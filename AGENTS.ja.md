# AGENTS.md — このリポジトリで作業する AI エージェント向けルール

このリポジトリはセキュリティツールを構築しています。開発するエージェントにも同じ規律が適用されます。

## シークレット処理

- **`key.txt` や `secrets.enc` を直接読まないでください**。テスト fixture は例外ですが、その場合でも store package API 経由に限定します。
- **シークレット値を print、log、commit しないでください**。テスト出力も含みます。
- store をデバッグするときは、raw `Get()` ではなく store 自身の `List()` (マスク済み) を使うか、マスク済み形式に対して assert してください。
- `e2e_test.py` は、MCP 出力に平文が現れないことを意図的に assert しています。この性質を維持してください。
- `verify_redeem.py` は hash、`/proc/<pid>/environ`、`/proc/<pid>/cmdline` に対して assert します。値を確認するために値を出力しないでください。この性質を維持してください。
- ディスク上の blob を調べる必要がある場合は、bytes として読み、armor marker や平文が含まれないことだけを確認してください。復号済みデータを dump してはいけません。

## セキュリティ不変条件

1. `secrets.enc` は平文の key material を決して含んではいけません。age で暗号化します。
2. `key.txt` は `0600`、store dir は `0700` でなければなりません。
3. すべての MCP tool result と resource はマスク済みでなければなりません。tool result に平文を出してはいけません。
4. `put` は `value_file` パスを受け取り、それを読み、読み取り後に削除しなければなりません。
5. マスキング規則は `internal/mask` にあります。entropy/prefix/URL segmentation のテストを green に保ってください。
6. **redemption は fail-closed です** (`internal/redeem`、docs/THREAT-MODEL.md)。未知のセッション、期限切れセッション、そのセッションで発行されていないキー名、値の欠落または空値、不正な予約プレフィックス、`argv` 内のトークン、audit log の書き込み失敗。いずれの場合もコマンドを起動しません。トークンをそのまま転送するフォールバックも、平文を転送するフォールバックも存在せず、エラーメッセージに値を含めてはいけません。
7. redemption は `argv` に値を置かず、値も引数リスト全体もログに残しません (`<store>/audit.log` はキー名のみを記録します)。
8. **結合済みトークンは必ず強制されます。** `--allow-host` / `--allow-path` / `--allow-header` 付きで発行したトークンは、`keysmith run --target` が記録された結合をすべて満たす場合にのみ解決できます (host 一致、path prefix、header の存在)。`--target` の欠落、不一致の宛先、https 以外 (loopback の http を除く)、クエリ文字列付きの宛先はすべて拒否します。結合の検査は audit 書き込み前、子プロセス起動前に実行し、結合を緩める・落とす再発行は `ErrBindingConflict` で失敗させなければなりません。

## ワークフロー

- コミット前に `go test ./...` を実行してください。すべての package が pass する必要があります。
- `go vet ./...` を実行してください。warning がない状態にします。
- `internal/mcp` または `internal/store` を変更した後は `python3 e2e_test.py` を実行してください。protocol round-trip が green のままである必要があります。
- `internal/redeem`、または `token`/`run` コマンドを変更した後は `python3 verify_redeem.py` を実行してください。fail-closed の end-to-end チェックを green に保つ必要があります。
- Go SDK (github.com/modelcontextprotocol/go-sdk) は、未解決の OSV advisory がないバージョンを使ってください。更新は意図的に行います。
