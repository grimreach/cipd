# RSLinx Classic comms core — protocol map & driver-to-engine interface specification

**Status:** reverse-engineering notes + clean-room target spec
**Scope:** EtherNet/IP (TCP 44818) + CSPv4 (TCP 2222) + DF1 serial/USB transports feeding a
unified CIP/PCCC router, for a Debian Linux daemon (`cipd`).

> **Provenance / clean-room boundary.**
> The *observations* below (class names, method signatures, the driver/engine split, state
> machines, Win32 API usage) were recovered with a decompiler from the shipped RSLinx Classic
> binaries (`ENGINE.DLL`, `ABTCP.DRV`, `AB_DF1.DRV`) for **interoperability analysis only**.
> The *wire formats* are the publicly published ODVA EtherNet/IP + CIP specifications and the
> Allen-Bradley **DF1 Protocol and Command Set** (pub. 1770-6.5.16) / PCCC command set.
> The daemon in `src/` is written **clean-room from those public specifications** — no code or
> data is copied from the decompilation. Keep that separation: implementers of `src/` should
> work from the public specs and this document's format tables, not from vendor binaries.

---

## 1. Binaries examined (observed)

All 32-bit x86, MSVC9 (VS2008) / MFC90 / ATL, each with a matching PDB reference, so symbol
names were recovered.

| Binary | Role | Key evidence |
|---|---|---|
| `ENGINE.DLL` (9197 funcs, `engine.pdb`) | Full CIP/PCCC stack, packet model, transaction router, device & route tables | `CProtocolPCCC`, `CProtocolASA`, `CPacketPCCC`, `CPacketASA`, `CDevice`, `CComm`, virtual-backplane classes |
| `ABTCP.DRV` (5040 funcs, `abtcp.pdb`) | Thin plug-in: TCP sockets + EtherNet/IP **and** CSPv4 encapsulation; delegates CIP to ENGINE | imports `ENGINE.DLL::Engine_RegisterDriver`, `CComm::Connect`, `CProtocolASA::OnConnectionData`, `CCIPDataTable::Write`; `WSOCK32::connect` |
| `AB_DF1.DRV` (`ab_df1.pdb`) | Thin plug-in: Win32 serial/USB DF1 framing; delegates PCCC to ENGINE; also hosts USB DH+/DH485 devices + modem dial-out | Win32 `SetCommState`/`WaitCommEvent`; shares `CPacketPCCC`/`CDecb`; `CDeviceABU2DHP`, `CDeviceABMicro800USB`, `CDeviceABUIC` |
| `ab_mastr.drv`, `ab_slave.drv` | DF1 half-duplex polling master / slave variants | (same class family) |

**Key architectural finding:** RSLinx already has a clean internal seam — a *driver ↔ engine*
API. Drivers implement only a physical transport (sockets, serial); the engine owns the CIP/PCCC
semantics, packet model, transaction matching and routing. **The port should reproduce that seam,
not the DLL boundaries.**

---

## 2. Layered architecture (target)

```
            ┌──────────────────────────────────────────────┐
  clients → │  Northbound API  (Unix socket JSON | REST | OPC-UA)   │  api.rs
            ├──────────────────────────────────────────────┤
            │  Unified CIP/PCCC Router                      │  router.rs
            │   • device registry   • route table (EPATH)   │
            │   • transaction manager (context/TNS match,   │
            │     timeout, retry, cancel, unsolicited)      │
            ├───────────────┬───────────────┬──────────────┤
  transports│  EtherNet/IP  │   CSPv4       │   DF1         │  enip.rs / csp.rs / df1.rs
            │  TCP 44818    │   TCP 2222    │  serial/USB   │
            └───────────────┴───────────────┴──────────────┘
                     carry →  CIP Message Router  +  PCCC blocks   (cip.rs / pccc.rs)
```

The packet model (`CPacket → CPacketASA | CPacketPCCC`, carried in a `CDecb` control block) is
**shared by every transport** in RSLinx. We mirror that: `cip.rs` and `pccc.rs` are transport-
independent; a transport's only job is to deliver/receive those byte blocks.

---

## 3. Driver ↔ Engine interface (the seam to reproduce)

Observed ENGINE exports used by `ABTCP.DRV` (southbound driver API) and the shared packet/device
vtables. These define the trait surface in `router.rs`.

| Observed symbol (ENGINE.DLL) | Meaning | Daemon equivalent |
|---|---|---|
| `Engine_RegisterDriver` | a transport registers itself with the router | `Router::register_device()` |
| `Srv_RegisterServerSubsystem` | northbound server (OPC/DDE/DTM) registers | `api.rs` adapters |
| `Unsol_RegisterTargetForSource` / `…Unregister` | subscribe to unsolicited/incoming msgs | `Router` unsolicited dispatch |
| `CComm::Connect(_LinxCommTarget*)` / `Disconnect` | open/close a device channel | `Transport::connect/close` |
| `CProtocolASA::OnConnectionData` | inbound CIP data from a driver → router | `Router::on_rx()` |
| `CProtocolASA::DoEncapsulatedUCMMRequest` / `DoEncapsulatedConnectionData` | UCMM / connected CIP dispatch | `cip` UCMM path |
| `CCIPDataTable::Write` | data-table write entry point | API `raw_cip` / typed write |
| `CDevice::GetHostNameBySession`, `SetStation`, `GetMappedNodeRoute → ROUTE` | device identity & route lookup | `Device` + `Route` |
| `CComm::DH5_TypedRead/Write`, `DH500_TypedRead/Write`, `SetupPCCCTransaction` | PLC-5 / SLC typed read/write | `pccc` builders |
| `CPacketASA::MakeUnconnectedSend`, `SetASAUnconnectedTimeout`, `ScaleTimeoutAs8Bits` | build CIP Unconnected_Send + tick timeout | `cip::unconnected_send` |
| `CPacketPCCC::GetPCCC → PCCCHDR*`, `GetSTS/GetTNS`, `MakeReply` | PCCC header accessors | `pccc::PcccRequest/Reply` |
| virtual-backplane: `C1756BackplanePort`, `CFlexLogixBackplanePort`, `CXLogixBackplanePort`, `ASA_GetVirtualBackplaneObject`, `VLink_AddNode/RegisterPLC2Address` | multi-hop CIP routing through chassis/DH+/DF1 | `route.rs` EPATH port segments |

---

## 4. EtherNet/IP encapsulation (TCP 44818)

### 4.1 Encapsulation header — 24 bytes, little-endian

| Off | Size | Field |
|----|----|----|
| 0 | u16 | `command` |
| 2 | u16 | `length` (bytes after header) |
| 4 | u32 | `session_handle` |
| 8 | u32 | `status` (0 = success) |
| 12 | 8 | `sender_context` (echoed in reply — used for request/reply matching) |
| 20 | u32 | `options` |

Commands used: `0x0000` NOP, `0x0004` ListServices, `0x0063` ListIdentity, `0x0064`
ListInterfaces, `0x0065` RegisterSession, `0x0066` UnRegisterSession, `0x006F` SendRRData
(unconnected/UCMM), `0x0070` SendUnitData (connected Class-1/3).

- **RegisterSession** data = `protocol_version u16 (=1)`, `options u16 (=0)`. Reply carries the
  assigned `session_handle`.
- **SendRRData** data = `interface_handle u32 (=0 for CIP)`, `timeout u16`, then CPF (below).

### 4.2 Common Packet Format (CPF)

`item_count u16`, then each item `{ type_id u16, length u16, data[length] }`.

| type_id | Item |
|---|---|
| 0x0000 | Null address (UCMM / unconnected) |
| 0x00A1 | Connected address (`connection_id u32`) |
| 0x00B1 | Connected data (`sequence u16` + CIP) |
| 0x00B2 | Unconnected data (CIP Message Router request/reply) |
| 0x8000 / 0x8001 | sockaddr info O→T / T→O |

UCMM request = Null-address item (len 0) + Unconnected-data item (0x00B2) holding the CIP MR
request.

### 4.3 CIP Message Router

Request: `service u8`, `path_size u8 (words)`, `EPATH`, `request_data`.
Reply: `reply_service u8 (= service|0x80)`, `0x00`, `general_status u8`,
`additional_status_size u8 (words)`, `additional_status[]`, `reply_data`.

EPATH logical segments (little-endian value for 16-bit): class `0x20 xx` / `0x21 00 xxxx`,
instance `0x24 xx` / `0x25 00 xxxx`, attribute `0x30 xx`, member `0x28 xx`.

### 4.4 Unconnected_Send (multi-hop routing)

Service `0x52` on Connection Manager (class `0x06`, instance 1):

```
priority_ticks u8 | timeout_ticks u8 | message_request_size u16 |
<embedded MR request> | [pad u8 if size odd] |
route_path_size u8 (words) | reserved u8(0) | <route path EPATH port segments>
```

Route path = ordered hops as **port segments**: `0x01, link` for backplane port 1 (link = slot);
larger ports/link addresses use the extended port-segment forms. This is RSLinx's
"virtual backplane" rendered on the wire.

### 4.5 Session state machine (per device/socket)

```
DISCONNECTED ─TCP connect(44818)→ TCP_OPEN
TCP_OPEN ─RegisterSession(0x65)→ REGISTERING
REGISTERING ─status=0, store session_handle→ ACTIVE
            └status≠0 ("refused to establish a session")→ CSPv4 fallback
ACTIVE ─SendRRData/SendUnitData, match reply by sender_context
ACTIVE ─idle→ keepalive (SO_KEEPALIVE); inactivity close
ACTIVE ─UnRegisterSession(0x66) | peer close→ CLOSING → DISCONNECTED
any ─error 10053/10054/timeout→ "connection lost" → auto-reconnect
```

Observed socket options: `SO_KEEPALIVE`, `SO_LINGER`, `SO_OOBINLINE`, explicit send/recv buffer
sizing; one worker thread per connection; SNMP used to read the interface system-ID during browse.

---

## 5. CSPv4 (legacy "AB Ethernet", TCP 2222)

Pre-EtherNet/IP transport for PLC-5E / SLC-5/05. The driver uses it as an **automatic fallback**
(observed: *"Device refused an EtherNet/IP connection, retry using CSPv4"* and the reverse). It
carries the same **PCCC** command blocks inside a fixed CSP header, with its own session open.
For a modern daemon this is **optional/legacy**; exact CSP field offsets should be confirmed from
the DF1/CSP reference or a packet capture before enabling it (`csp.rs` is a documented scaffold).

---

## 6. CIP/PCCC router (ENGINE core)

### 6.1 PCCC command block (`struct PCCCHDR`)

Embedded application message (inside DF1 data, CSP data, or PCCC-in-CIP):

```
DST u8 | SRC u8 |            ← link addressing (DF1/DH+); omitted inside PCCC-in-CIP
CMD u8 | STS u8 | TNS u16 | FNC u8 | <command data>
```

- `TNS` = transaction nonce, matches reply to request (`CPacketPCCC::GetTNS/SetTNS`).
- Reply: `CMD(|0x40)`, `STS`, `TNS`, `[EXT_STS u8 if STS==0xF0]`, `<data>`.
- Common ops (`CComm` typed read/write): CMD `0x0F` with FNC `0xA2` (SLC protected typed read),
  `0xAA` (SLC protected typed write); PLC-5 typed read/write equivalents.
- Diagnostics handled locally by `CPCCCTarget` (loopback/status/counters/node-table) — the daemon
  answers these for its own virtual node.

### 6.2 PCCC-in-CIP

Registry `…\RSLinx\Protocols\PCCC in CIP`. CIP service `0x4B` on the PCCC object
(class `0x67`, instance 1):

```
requestor_id_len u8 (=7) | CIP_vendor u16 | CIP_serial u32 | <PCCC block (CMD..data)>
```

Built by `CDevice::MakeEncapsulatedUCMMRequest` / `CProtocolASA::DoEncapsulatedUCMMRequest`.
This is how the daemon talks PCCC to SLC/PLC-5 **over EtherNet/IP**.

### 6.3 Routing / device model

`CDevice` holds station + route; `GetMappedNodeRoute → ROUTE`. The virtual backplane
(`C1756BackplanePort`, `CFlexLogixBackplanePort`, `CXLogixBackplanePort`) and bridge ports
(`CPCCCBridgePort<CKA|CKE|CKP5>`, `CKEDF1Channel`) express chassis → DH+/DF1 → station hops as the
Unconnected_Send route path (§4.4).

---

## 7. DF1 serial / USB (AB_DF1.DRV)

Transport: Win32 overlapped serial (`CreateFile` COM port, `SetCommState`, `SetCommTimeouts`,
`SetupComm`, `PurgeComm`, `WaitCommEvent`, `SetCommMask`, `EscapeCommFunction`). On Linux this is
`termios` + async read; USB devices (`1784-U2DHP` USB↔DH+, `Micro800` USB, `UIC` DH485) appear as
`/dev/ttyACM*` (CDC-ACM) and speak the **same DF1** — no kernel driver.

Config (observed registry `…\RSLinx\Drivers\AB_DF1`): `SerialDevice` (`COM%d`), `BaudRate`,
`Parity`, `Station`, `ACKTimeout`, `MaxDF1Retries`. Error check = **BCC or CRC**; link =
**Full or Half Duplex**.

### 7.1 Full-duplex framing (DF1, 1770-6.5.16)

```
message : DLE STX <payload, DLE-stuffed> DLE ETX <check>
          check = BCC (1 byte)  or  CRC-16 (2 bytes, low then high)
control : DLE ACK (10 06) | DLE NAK (10 15) | DLE ENQ (10 05)
stuffing: any 0x10 in payload is doubled → 0x10 0x10
BCC     : two's complement of the 8-bit sum of payload bytes
CRC-16  : poly 0xA001 (reflected), init 0, computed over payload + ETX
```

Payload = `DST, SRC` then the PCCC block (§6.1).

### 7.2 Link state machine (full-duplex)

```
IDLE ─have msg→ TX (send frame, start ACKTimeout)
TX ─DLE ACK→ IDLE (await reply frame)
TX ─DLE NAK / bad→ retransmit (≤ MaxDF1Retries) else FAIL
TX ─timeout→ DLE ENQ (query last ACK/NAK); retries exhausted→ FAIL
RX ─DLE STX…good check→ DLE ACK, deliver payload to router
RX ─bad check→ DLE NAK
```

Half-duplex adds master polling (`DLE ENQ` + station, `DLE SOH` addressing) → the
`ab_mastr`/`ab_slave` split.

---

## 8. Module map (daemon)

| Spec section | Module | Responsibility |
|---|---|---|
| §4 §4.3 §4.4 | `src/cip.rs` | encapsulation header, CPF, CIP MR, EPATH, Unconnected_Send, status names |
| §6.1 §6.2 | `src/pccc.rs` | PCCC block, TNS, SLC/PLC-5 typed r/w, PCCC-in-CIP wrap |
| §7 | `src/df1.rs` | DLE framing, BCC/CRC-16, ACK/NAK/ENQ link SM, serial I/O |
| §4.5 | `src/enip.rs` | TCP 44818, RegisterSession SM, SendRRData/UnitData |
| §5 | `src/csp.rs` | TCP 2222 CSPv4 fallback (scaffold) |
| §6.3 §3 | `src/router.rs` | device registry, route table, transaction manager |
| §2 | `src/api.rs` | Unix-socket JSON API (+ REST/OPC-UA adapter points) |
| — | `src/config.rs`, `src/main.rs`, `src/error.rs` | config, bootstrap, errors |

---

## 9. Validation strategy

Develop against the public specs; validate before touching hardware with open stacks
(`pycomm3`, `cpppo`, OpenENER) and Wireshark's ENIP/CIP dissector. Lock Rockwell-specific byte
math (UCMM timeout tick scaling, PCCC-in-CIP requestor-id, route-path padding, CSP header) against
captures. Unit-test `cip`/`pccc`/`df1` encoders with known-good frames.
