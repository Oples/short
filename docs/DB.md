<dbdiagrams.io>

```
Table aka {
  id int [pk, increment]
  created_at datetime // new Date()
  expire_at datetime // NULL or 2 years
  user text // uuid
  in text  // aka s.enokai.net/{in}
  out text // to https://www.amazon.it/dp/0000000001
  key text // https://crates.io/crates/argon2
}
```

```sql
CREATE TABLE IF NOT EXISTS Aka (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT,
  expire_at TEXT,
  user TEXT,
  "in" TEXT UNIQUE,
  out TEXT,
  "key" TEXT
)
```
