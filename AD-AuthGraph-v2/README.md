# AD-AuthGraph-v2

AD-AuthGraph-v2 is an enterprise-scale Active Directory authorization graph generation framework designed to collect, model, and visualize authorization relationships from large Microsoft Active Directory environments.

This version significantly extends the original AD-AuthGraph by introducing an enterprise Active Directory benchmark generator, a high-performance authorization state collector, and improvements throughout the graph generation pipeline.

---

## Features

- Enterprise-scale Active Directory benchmark generation
- High-performance Active Directory authorization state collection
- Authorization graph generation
- Graph refinement
- Native C graph analysis engine
- Interactive graph visualization
- Compatible with large Active Directory environments

---

## Components

### Active Directory Generator

Creates large benchmark Active Directory environments consisting of users, groups, computers, organizational units, memberships and enterprise-like structures.

---

### Authorization State Collector

Collects authorization data directly from Active Directory including:

- Users
- Groups
- Computers
- Organizational Units
- Memberships
- Service Principal Names (SPNs)
- Delegation
- Access Control Lists (ACLs)
- Security Descriptors

The collector outputs a JSON authorization state compatible with the remainder of the pipeline.

---

### Graph Builder

Transforms collected authorization state into graph nodes and relationships.

---

### Graph Refiner

Optimizes and normalizes the generated graph.

---

### Analyzer

Native C implementation for efficient graph analysis.

---

### Visualizer

Interactive visualization of generated authorization graphs.

---

# Directory Structure

```
AD-AuthGraph-v2/
│
├── README.md
├── LICENSE
├── requirements.txt
├── main.py
│
├── source/
│   ├── Program.cs
│   ├── analyzer.c
│   ├── graph_builder.py
│   ├── refiner.py
│   └── visualizer.py
│
├── generators/
│   └── Generate-EnterpriseAD_nodes.ps1
│
├── collectors/
│   └── Collect-ADAuthorization.ps1
│
└── sample_output/
    └── state_5.json
```

---

# Requirements

- Windows Server
- Active Directory Domain Services
- .NET 8
- Python 3.x
- Microsoft Visual C++ (for analyzer compilation)

---

# Workflow

1. Generate benchmark Active Directory
2. Collect authorization state
3. Build authorization graph
4. Refine graph
5. Analyze graph
6. Visualize graph

---

# Scalability

AD-AuthGraph-v2 is designed for enterprise Active Directory environments.

The collector implements:

- LDAP paging
- Streaming JSON output
- Bounded memory usage
- Incremental processing
- Checkpoint/resume support
- Efficient SID/GUID caching

allowing significantly larger Active Directory environments to be processed than the original PowerShell implementation.

---

# Research Motivation

Modern enterprise Active Directory deployments often contain hundreds of thousands of security principals and authorization relationships. Traditional collection pipelines become increasingly slow and memory intensive as directory size grows.

AD-AuthGraph-v2 addresses these challenges by providing a scalable authorization-state collection and graph generation pipeline while maintaining compatibility with existing downstream processing.

---

# License

GNU General Public License (GPLv3)