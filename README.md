# cipd

A clean-room Debian Linux daemon that speaks **EtherNet/IP** (TCP 44818), **CSPv4** (TCP 2222,
legacy fallback) and **DF1** (serial/USB) to Allen-Bradley PLCs, and exposes a single
**CIP/PCCC router** to local clients over a Unix-domain-socket JSON API (with REST/OPC-UA as thin
adapters over the same router).

It is a ground-up reimplementation of the transport + routing behavior documented in
[`ARCHITECTURE.md`](ARCHITECTURE.md), written **from the public ODVA EtherNet/IP / CIP and
Allen-Bradley DF1 (1770-6.5.16) specifications** — no code or data is derived from any vendor
binary.

## Layout

```
ARCHITECTURE.md      protocol map + driver↔engine interface spec (the reference)
src/
  cip.rs             encapsulation header, CPF, CIP Message Router, EPATH, Unconnected_Send
  pccc.rs            PCCC blocks, SLC/PLC-5 typed read/write, PCCC-in-CIP
  df1.rs             DF1 framing (DLE stuff), BCC/CRC-16, ACK/NAK/ENQ link state machine
  enip.rs            EtherNet/IP session (RegisterSession SM, SendRRData)
  csp.rs             CSPv4 fallback (documented scaffold)
  router.rs          device registry, lazy connect, route table, transaction nonces
  api.rs             Unix-socket newline-JSON API
  config.rs/main.rs  config + bootstrap
cipd.example.json    sample configuration
packaging/cipd.service  systemd unit
```

## Build & run

```sh
cargo build --release
sudo install -Dm755 target/release/cipd /usr/local/bin/cipd
sudo install -Dm644 cipd.example.json /etc/cipd/config.json   # then edit
sudo install -Dm644 packaging/cipd.service /etc/systemd/system/cipd.service
sudo systemctl enable --now cipd
```

Or run in the foreground: `cipd ./cipd.example.json` (set `RUST_LOG=cipd=debug` for traces).

## API (newline-delimited JSON over the Unix socket)

```sh
# list configured devices
echo '{"op":"list_devices"}' | socat - UNIX-CONNECT:/run/cipd/cipd.sock

# MicroLogix/SLC logical read — no raw file_type numbers needed
echo '{"op":"ml_read","device":"slc_serial","address":"N7:0","count":10}' \
  | socat - UNIX-CONNECT:/run/cipd/cipd.sock
echo '{"op":"ml_read","device":"slc_serial","address":"T4:0.ACC"}' \
  | socat - UNIX-CONNECT:/run/cipd/cipd.sock
# ...and write (values encoded per file type: F->f32, N->i16, L->i32)
echo '{"op":"ml_write","device":"slc_serial","address":"F8:2","values":[3.14]}' \
  | socat - UNIX-CONNECT:/run/cipd/cipd.sock

# low-level form (explicit file_type) is still available:
echo '{"op":"slc_read","device":"slc_serial","size":2,"file":7,"file_type":137,"element":0,"sub_element":0}' \
  | socat - UNIX-CONNECT:/run/cipd/cipd.sock

# raw CIP: Get_Attributes_All (0x01) of Identity object (class 0x01 inst 1) on a Logix
echo '{"op":"raw_cip","device":"logix1","service":1,"path":"20012401","data":""}' \
  | socat - UNIX-CONNECT:/run/cipd/cipd.sock
```

Responses: `{"status":"ok","data":{...}}` or `{"status":"error","message":"..."}`.

## Implemented vs. TODO

**Implemented (unit-tested encoders):** encapsulation header, CPF/SendRRData, CIP MR
request/reply, EPATH + port-segment routing, Unconnected_Send, PCCC blocks + SLC typed R/W,
**MicroLogix/SLC logical address parser** (`N7:0`, `B3:0`, `F8:2`, `T4:0.ACC`, `I:0`, `O:0`,
`N7:0/4`, extended `>=255` addressing) with typed value decode/encode,
PCCC-in-CIP, DF1 BCC/CRC-16 + full-duplex framing/de-framing + link retry SM, EtherNet/IP session
lifecycle, lazy-reconnect device router, Unix-socket API.

**TODO / validate against hardware or captures:**
- CSPv4 header byte layout (`csp.rs`) — legacy; confirm before enabling.
- Connected messaging (ForwardOpen / Class-1 I/O, `SendUnitData`) — only UCMM/unconnected now.
- DF1 half-duplex master/slave polling (the `ab_mastr`/`ab_slave` variants).
- Logix symbolic tag addressing (ANSI extended symbol segments) and CIP fragmentation.
- REST and OPC-UA adapters (add alongside `api.rs`, calling the same `Router`).
- Lock Rockwell-specific byte math (UCMM tick-timeout scaling, PCCC-in-CIP requestor-id,
  route-path padding) against Wireshark captures.

## Status

`cargo build` has **not** been run in the authoring environment (no Rust toolchain on the analysis
host). Treat this as a reviewed, self-consistent foundation: run `cargo build` / `cargo test` and
expect to resolve minor issues. Validate wire output with `pycomm3`/`cpppo` and the Wireshark
ENIP/CIP dissector before connecting to production equipment.
```
