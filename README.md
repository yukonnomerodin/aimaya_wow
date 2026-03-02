# Aimaya: Connecting Eras 🌌

![Midnight Header](https://raw.githubusercontent.com/yukonnomerodin/aimaya_wow/main/aimaya1.jpg) 

**Aimaya** is a high-performance C# gateway designed to bridge the gap between modern **World of Warcraft (Retail 12.0.1, Build 66102)** and legacy server cores like **AzerothCore**.

---


# 🧊 Project Frozen (Architectural Transition)

This repository is preserved as a research artifact and architectural checkpoint for the practical study of protocol and server architecture through the following integration model:

**Retail Client → custom Proxy/Gateway → AzerothCore**

The integration layer was implemented and analyzed more deeply than initially anticipated, allowing accelerated extraction of architectural conclusions.

The project established a real protocol-level integration environment in which the following aspects were explored:

* Retail client network protocol
* Session cryptographic channel
* Transport gateway model
* Adaptation of a legacy server core to modern client requirements

The phase was partially implemented and thoroughly analyzed. The research produced key insights into scalability boundaries and structural limitations that arise when building on inherited cores such as AzerothCore and TrinityCore.

As a result, a strategic decision was made to transition toward the development of a proprietary modern server core, designed from the ground up with emphasis on:

* deterministic state management
* controlled cryptographic boundaries
* transparent observability
* long-term architectural scalability

Aimaya_wow remains a frozen architectural baseline and engineering reference point for the next stage of development.

---

The project is not discontinued — it has been transitioned into a separate development branch within the repository and continues to evolve under a new architectural direction.

---

## 🚀 Key Features

* **Modern Auth Pipeline**: Fully implemented **SRP6** authentication and **TLS** encrypted sessions.
* **Retail World Encryption**: Stable **AES-GCM world channel** negotiation and encrypted session bootstrap.
* **Protocol Translation**: Seamlessly translates modern **Protobuf** messages into legacy-compatible instructions.
* **Dynamic RealmList**: Generates **Zlib-compressed JSON** realm lists required by modern Battle.net SDK clients.
* **Intelligent Handoff**: Implements `RealmJoinRequest` to issue valid session tickets for World server transitions.
* **Deferred Frame Synchronization**: Deterministic post-handshake frame flushing for retail compatibility.
* **Database Integration**: Powered by **Dapper** for fast and reliable data management.

---

## 🛠️ Tech Stack

* **Language**: C# / .NET 8.0
* **Database**: MySQL (via MySqlConnector)
* **ORM**: Dapper
* **Network**: System.IO.Pipelines for high-throughput socket handling
* **Serialization**: Protobuf & Zlib
* **Encryption**: SRP6, TLS, AES-GCM

---

## 📊 Project Status

| Component | Status | Description |
| :--- | :--- | :--- |
| **AuthGateway** | ✅ Online | Login, RealmList, Ticket issuance, and encrypted world bootstrap fully functional. |
| **WorldGateway** | 🚀 Milestone M1 Complete | Retail client reaches Character Selection via encrypted world channel. Opcode translation layer under active expansion. |
| **Database Support**| ✅ Online | AzerothCore auth database integration operational. |

---

## 🧠 Milestone M1 – Retail World Bootstrap

The bridge now successfully:

- Completes encrypted world handshake (AES-GCM)
- Enters secure world mode
- Performs deterministic post-ACK frame synchronization
- Achieves stable session state transition
- Reaches Character Enumeration stage
- Displays retail Character Selection screen

This confirms full compatibility of the retail client authentication and world bootstrap pipeline through Aimaya.

---

## 🛠️ Ongoing Development (M2+)

- Character Creation pipeline support  
- World entry & spawn initialization  
- Movement synchronization layer  
- Opcode mapping expansion  
- Entity & gameplay state translation  

---

## ❤️ Credits & Acknowledgments

Aimaya stands on the shoulders of giants. We express our deepest gratitude to the legendary communities and contributors who built the foundation of modern emulation:

* **[TrinityCore](https://www.trinitycore.org/)** — For establishing the gold standard of open-source server emulation and protocol research.
* **[AzerothCore](https://www.azerothcore.org/)** — For the incredible modularity and community-driven excellence that powers our backend.

*Respect to all developers who keep the magic of Azeroth alive.*

---

## 🌐 Links & Community

* **Official Website**: [aimaya.pro](https://aimaya.pro)
* **Discord Support**: [Join our community](https://discord.gg/TxHGh3dP4g)
* **Documentation**: Available in the `/docs` folder (Local only).

---

## 👤 Author

Developed with ⚔️ **yukoNw** and 💻 by **Kuma**.

---

### ⚖️ Disclaimer
This project is for educational and research purposes only. "World of Warcraft" and "Battle.net" are trademarks of Blizzard Entertainment. Aimaya is not affiliated with or endorsed by Blizzard Entertainment.
