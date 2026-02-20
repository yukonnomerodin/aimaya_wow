# Aimaya: Connecting Eras 🌌

![Midnight Header](https://raw.githubusercontent.com/yukonnomerodin/aimaya_wow/main/aimaya1.jpg) 

**Aimaya** is a high-performance C# gateway designed to bridge the gap between modern **World of Warcraft (Retail 12.0.1, Build 66017)** and legacy server cores like **AzerothCore**.

---

## 🚀 Key Features

* **Modern Auth Pipeline**: Fully implemented **SRP6** authentication and **TLS** encrypted sessions.
* **Protocol Translation**: Seamlessly translates modern **Protobuf** messages into legacy-compatible instructions.
* **Dynamic RealmList**: Generates **Zlib-compressed JSON** realm lists required by modern Battle.net SDK clients.
* **Intelligent Handoff**: Implements `RealmJoinRequest` to issue valid session tickets for World server transitions.
* **Database Integration**: Powered by **Dapper** for fast and reliable data management.

---

## 🛠️ Tech Stack

* **Language**: C# / .NET 8.0
* **Database**: MySQL (via MySqlConnector)
* **ORM**: Dapper
* **Network**: System.IO.Pipelines for high-throughput socket handling
* **Serialization**: Protobuf & Zlib

---

## 📊 Project Status

| Component | Status | Description |
| :--- | :--- | :--- |
| **AuthGateway** | ✅ Online | Login, RealmList, and Ticket issuance are fully functional. |
| **WorldGateway** | 🛠️ In Progress | Working on packet translation and session proxying. |
| **Database Support**| ✅ Online | Basic AzerothCore auth database integration. |

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

Developed with ⚔️**yukoNw** and 💻 by **Kuma**.

---

### ⚖️ Disclaimer
This project is for educational and research purposes only. "World of Warcraft" and "Battle.net" are trademarks of Blizzard Entertainment. Aimaya is not affiliated with or endorsed by Blizzard Entertainment.
