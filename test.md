```mermaid
erDiagram
    Users {
        String user_id PK "Primary key"
        String user_name "Username"
        String tenant_id "Tenant identifier"
        String hashed_password "Password hash"
    }

    Assistants {
        String assistant_id PK "Primary key"
        String user_id FK "Foreign key to Users.user_id"
        String assistant_name "Assistant name"
        String created_at "Timestamp"
    }

    ChatSessions {
        String session_id PK "Primary key"
        String assistant_id FK "Foreign key to Assistants.assistant_id"
        String user_id FK "Foreign key to Users.user_id"
        String created_at "Timestamp"
    }

    ChatMessages {
        String message_id PK "Primary key"
        String chat_session_id FK "Foreign key to ChatSessions.session_id"
        String sender "Message sender (user/assistant)"
        String content "Message content"
        String timestamp "Message timestamp"
    }

    Users ||--o{ Assistants : "has"
    Users ||--o{ ChatSessions : "has"
    Assistants ||--o{ ChatSessions : "has"
    ChatSessions ||--o{ ChatMessages : "contains"
