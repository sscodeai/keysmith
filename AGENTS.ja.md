# AGENTS.md — このリポジトリで作業する AI エージェント向けルール

このリポジトリはセキュリティツールを構築しています。開発するエージェントにも同じ規律が適用されます。

## シークレット処理

- **`key.txt` や `secrets.enc` を直接読まないでください**。テスト fixture は例外ですが、その場合でも store package API 経由に限定します。
- **シークレット値を print、log、commit しないでください**。テスト出力も含みます。
- store をデバッグするときは、raw `Get()` ではなく store 自身の `List()` (マスク済み) を使うか、マスク済み形式に対して assert してください。
- `e2e_test.py` は、MCP 出力に平文が現れないことを意図的に assert しています。この性質を維持してください。
- ディスク上の blob を調べる必要がある場合は、bytes として読み、armor marker や平文が含まれないことだけを確認してください。復号済みデータを dump してはいけません。

## セキュリティ不変条件

1. `secrets.enc` は平文の key material を決して含んではいけません。age で暗号化します。
2. `key.txt` は `0600`、store dir は `0700` でなければなりません。
3. すべての MCP tool result と resource はマスク済みでなければなりません。tool result に平文を出してはいけません。
4. `put` は `value_file` パスを受け取り、それを読み、読み取り後に削除しなければなりません。
5. マスキング規則は `internal/mask` にあります。entropy/prefix/URL segmentation のテストを green に保ってください。

## ワークフロー

- コミット前に `go test ./...` を実行してください。すべての package が pass する必要があります。
- `go vet ./...` を実行してください。warning がない状態にします。
- `internal/mcp` または `internal/store` を変更した後は `python3 e2e_test.py` を実行してください。protocol round-trip が green のままである必要があります。
- Go SDK (github.com/modelcontextprotocol/go-sdk) は、未解決の OSV advisory がないバージョンを使ってください。更新は意図的に行います。
