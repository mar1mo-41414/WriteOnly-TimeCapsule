# WriteOnly-TimeCapsule

[日本語 README →](README.md)

> [!CAUTION]
> **This is a toy for adding a little fun to everyday life. Do NOT use it for real work.**
>
> It is not meant for protecting secrets that truly matter, business data, or anything you cannot afford to lose.
> The cryptography itself is delegated to well-established libraries ([age](https://age-encryption.org/), [drand](https://drand.love/)),
> but this tool is an unaudited hobby project whose threat model is simply "don't accidentally peek at the contents".
> The author accepts no responsibility for any data loss or leakage.

A software **time capsule you can write to, but cannot look into until you open it**.

Drop in diary entries, photos or letters to your future self with `vault add` whenever you like.
Not even you can tell what, how many, or how much you have put in.
When you finally "open" it, everything comes out and the capsule is destroyed for good.

- Adding only needs the public key. There is **no** command to list contents, count items or show free space
- The container has a fixed size from the start; its apparent size never changes
- Opening can destroy the capsule and the key (it can never be opened again)
- Split the key so that, e.g., any 2 of 3 people can open it together
- Add a time lock: "nobody, not even me, can open this before 20XX-XX-XX"
- Single binary for macOS / Linux

## Download

Grab the binary for your platform from [Releases](../../releases), rename it to `vault` and put it on your PATH.

| File | Platform |
| --- | --- |
| `vault-darwin-arm64` | Apple Silicon Mac |
| `vault-darwin-amd64` | Intel Mac |
| `vault-linux-amd64` | Linux (x86_64) |
| `vault-linux-arm64` | Linux (ARM64, e.g. Raspberry Pi) |

```bash
chmod +x vault-darwin-arm64 && mv vault-darwin-arm64 /usr/local/bin/vault
```

> [!NOTE]
> On macOS, a binary downloaded with a browser may be blocked by Gatekeeper.
> Run `xattr -d com.apple.quarantine /usr/local/bin/vault` in that case.

To build from source you need Go: `make` (host) / `make dist` (all platforms).

## Usage

### Basics: create → add → open

```bash
vault init --size 500M                 # creates vault.dat / vault.dat.pub / vault-secret.key
                                       # move vault-secret.key to a USB stick and remove it from this machine
vault add diary.txt photo.jpg          # only prints "added"
vault add --delete-original letter.txt # remove the original after adding
vault status                           # existence and apparent size only
vault open --key /Volumes/USB/vault-secret.key --and-destroy-key   # everything comes out, capsule + key destroyed (asks first)
```

### Split the key ("any 2 of 3")

```bash
vault init --size 500M --shares 3 --threshold 2 --key-out keys/capsule.key
vault split --key vault-secret.key --shares 3 --threshold 2 --delete-original   # split an existing key
vault open --key capsule.share1-of-3.key --key capsule.share3-of-3.key --and-destroy-key
```

A single share reveals nothing about the key. Each share is one ~90-character line, so you can even hand it over on paper (typos are detected).

### Time lock ("not before year X")

```bash
# cannot be opened before 2036-03-20; a 2-of-3 split key is kept as the escape hatch
vault init --size 500M --timelock 2036-03-20 --shares 3 --threshold 2 --key-out escape/capsule.key
vault status                 # → openable after 2036-03-20 00:00:00 (3460 days left)
vault open --and-destroy-key # after the date, no key needed (Internet access required)
vault timelock --key vault-secret.key --until +10y   # add a time lock to an existing capsule
```

Dates: `2036-03-20`, `"2036-03-20 09:00"`, `+10y`, `+6mo`, `+30d`, ...

Changing the clock or patching the program does not help: the key needed to open it simply does not exist anywhere until that date.
Whoever holds the escape-hatch key (secret key or enough shares) can still open it at any time.

The CLI messages are in Japanese.

## Caveats

- **Lose the key and the capsule can never be opened.** The same goes for losing too many shares
- The time lock relies on the external [drand](https://drand.love/) network. If drand no longer exists on that date, only the escape hatch can open the capsule — always keep one
- Destroying only affects files on the machine where you open it, not copies or backups
- There is intentionally no command to look inside (`list`, `peek`, ...)

Technical details are in [docs/ARCHITECTURE-EN.md](docs/ARCHITECTURE-EN.md).

## License

[MIT](LICENSE)
