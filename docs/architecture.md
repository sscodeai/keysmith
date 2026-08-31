# keysmith Architecture

```mermaid
flowchart TB
    subgraph Agent["AI Agent (Claude Code / Cursor / ...)"]
        A[LLM]
        SK[Built-in SKILL.md<br/>rules: never cat .env<br/>values via value_file]
    end

    subgraph MCP["keysmith (Go, single binary)"]
        T[tools<br/>list/get/put/rotate/delete]
        R[resources<br/>secret://secrets masked view]
        M["internal/mcp<br/>MCP Server (stdio)"]
    end

    subgraph Store["internal/store (age encrypted)"]
        K[key.txt<br/>0600 private key]
        E[secrets.enc<br/>armor ciphertext]
    end

    subgraph Mask["internal/mask"]
        MR[masking rules<br/>prefix/entropy/URL segmentation]
    end

    A -->|"pass handles, not plaintext"| SK
    SK -->|"MCP protocol calls"| M
    M --> T
    M --> R
    T -->|"Set/Get/Rotate"| Store
    R -->|"List masked view"| Store
    Store -->|"decrypt in memory"| Mask
    Mask -->|"masked output"| T
    Mask -->|"masked output"| R

    style K fill:#f66,stroke:#900
    style E fill:#ff9,stroke:#990
    style T fill:#9cf,stroke:#069
    style R fill:#9cf,stroke:#069
```

## Layers

| Layer | Component | Responsibility |
|---|---|---|
| Agent layer | LLM + SKILL.md | behavior rules: no raw reads, handle passing |
| MCP layer | internal/mcp | protocol server: tools + resources |
| Storage layer | internal/store | age encrypted residency, atomic writes, 0600 |
| Masking layer | internal/mask | prefix/entropy/URL-segment masking rules |
