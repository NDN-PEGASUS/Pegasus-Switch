# Pegasus-Switch

> Cooperate with [Pegasus-Server](https://github.com/NDN-PEGASUS/Pegasus-Server) to build a high-speed cross-platform NDN forwarding system architecture.

---

## 📌 Overview

This repository is part of the [**Pegasus**](https://github.com/NDN-PEGASUS) project, a cross-plane forwarding acceleration architecture for Named Data Networking (NDN). Pegasus-Switch is a high-speed NDN forwarder based on the Tofino2 programmable switch. In collaboration with [Pegasus-Server](https://github.com/NDN-PEGASUS/Pegasus-Server), it can further accelerate NDN traffic forwarding.

---

## 📁 Directory Structure
```
Pegasus-Switch/
├── pclndncpv2/       # Control plane of Pegasus-Switch
├── pclndndpv2/       # Data plane of Pegasus-Switch
└── README.md
```

## 🚀 Quick Setup

Clone the repository [Pegasus-Switch](https://github.com/NDN-PEGASUS/Pegasus-Switch) to a Tofino2 programmable switch.

First, copy `pclndn.xml` and `types.xml` to `path/to/your/SDE/install/share/cli/xml`

Based on the optimal parsable name format obtained in the [Pegasus-Traffic](https://github.com/NDN-PEGASUS/Pegasus-Traffic), modify the parser implementation in the data plane (`pclndndpv2.p4`).

To compile and install the data plane:
```shell
cd Pegasus-Switch/pclndndpv2/
./build.sh
./install.sh
```

To compile and start the control plane:
```shell
cd Pegasus-Switch/pclndncpv2/
./start_pegasus.sh
```

By control plane, offloading the bitmap for external servers and the MAC table for backend servers: 
```shell
pclndn
port add
bitmap add
group add key area 0

# Ports connected to backend servers
# Please modify according to your testbed topology
mac add server 0 dmac 0c:42:a1:3a:67:68 port 3/0 
mac add server 0 dmac 0c:42:a1:3a:67:69 port 4/0
```

If you want to stop the Pegasus switch: 
```shell
./stop_pcl_switchd.sh
```