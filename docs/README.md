# open-cisco-zta Documentation

Welcome to the internal technical documentation for **open-cisco-zta**, an open-source, high-performance client for **Cisco Secure Access ZTNA (Zero Trust Network Access)** written in **Rust**.

This documentation provides an in-depth reference for architects, developers, security engineers, and advanced users who want to understand the system design, protocol invariants, and operational details of the project.

---

## 📚 Documentation Index

| Document | Description |
| :--- | :--- |
| **[Architecture & Technical Principles](architecture.md)** | Comprehensive breakdown of system architecture, control plane, data plane multiplexing, cryptography, networking, and posture engine. |
| **[Key Features & Capabilities](features.md)** | Detailed overview of all features, including transparent TUN mode, userspace SOCKS5h proxy, and OS posture spoofing. |
| **[CLI Reference](cli-reference.md)** | Full command-line reference for all subcommands (`enroll`, `run`, `status`, `sync`), flags, arguments, and environment variables. |
| **[Configuration & State Persistence](configuration.md)** | Layout of configuration directories across Linux and Windows, file formats, and JSON schemas. |
| **[Enrollment & Authentication Deep-Dive](enrollment.md)** | Step-by-step lifecycle of client enrollment: RFC 9449 DPoP, browser SSO cookie capture, Cisco Umbrella device registration, and custom ACME certificate issuance. |

---

## 🧭 Project Highlights & Invariants

- **Clean-Room Implementation:** Implemented from scratch without proprietary Cisco binaries, drivers, or kernel daemons.
- **Strict Protocol Compliance:** Enforces Cisco-specific protocol extensions (RFC 9449 DPoP composite headers, custom ACME `ZtnaUriList` and `ztna-jwt` challenges, RFC 9298 MASQUE `CONNECT-UDP` encapsulation).
- **Userspace Networking:** Provides transparent system-wide tunneling via Linux/Windows TUN and a userspace TCP/IP stack (`netstack-smoltcp`), as well as an unprivileged SOCKS5h proxy on both Linux and Windows.
- **Privacy & Isolation:** Corporate DNS traffic is handled via synthetic Fake-IPs (`198.18.0.0/15`) with zero leakage of corporate domain queries to upstream resolvers. Non-corporate traffic is completely untouched.
