"""
graph_builder.py - Authorization Graph Builder

Builds a directed graph from Active Directory authorization state JSON.
Models directory-level authority relationships as nodes and edges.

Author: Siddharth Ray Chaudhuri
Date: 2026-02-10
Purpose: Authorization Graph Modeling Project
"""

import json
import networkx as nx
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

EXTENDED_RIGHTS_MAP = {
    "00299570-246d-11d0-a768-00aa006e0529": "ResetPassword",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "User-Force-Change-Password",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}


class AuthorizationGraph:
    """
    Builds and manages an authorization graph from AD state data.
    
    The graph models:
    - Nodes: Identities (Users, Groups, Computers, SPNs)
    - Edges: Trust relationships (memberships, permissions, delegation)
    """
    
    def __init__(self):
        """Initialize empty authorization graph"""
        self.G = nx.DiGraph()
        self.metadata = {}
        self.statistics = {
            'nodes': 0,
            'edges': 0,
            'users': 0,
            'groups': 0,
            'computers': 0,
            'spns': 0
        }
        
        # Edge contract definitions (formal specification)
        self.edge_contracts = {
            'member_of': {
                'description': 'Identity is member of group',
                'conditional': False,
                'mediation': 'direct',
                'enforcement': 'AD directory state',
                'authority_granted': 'Inherits group permissions'
            },
            'local_admin_on': {
                'description': 'Group has local admin rights on computer',
                'conditional': True,
                'mediation': 'local',
                'enforcement': 'LSASS on target computer',
                'authority_granted': 'Local administrator privileges'
            },
            'has_permission_on': {
                'description': 'Identity has ACL permission on target',
                'conditional': False,
                'mediation': 'direct',
                'enforcement': 'AD DS on operations',
                'authority_granted': 'Specific ACL right (varies)'
            },
            'has_spn': {
                'description': 'Identity has Service Principal Name',
                'conditional': False,
                'mediation': 'direct',
                'enforcement': 'Kerberos KDC',
                'authority_granted': 'Service identity',
                'note': 'Enables Kerberoasting (credential obtainability)'
            },
            'trusted_for_delegation': {
                'description': 'Can request TGT on behalf of target',
                'conditional': True,
                'mediation': 'kdc',
                'enforcement': 'KDC during ticket issuance',
                'authority_granted': 'Can impersonate target',
                'conditions': ['target_authenticates', 'forwardable_ticket', 'not_protected_user']
            }
        }
    
    def load_from_json(self, filepath: str) -> bool:
        """
        Load AD authorization state from JSON file and build graph.
        
        Args:
            filepath: Path to JSON file from PowerShell collector
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"[*] Loading authorization state from: {filepath}")
            
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
            
            # Store metadata
            self.metadata = data.get('metadata', {})
            print(f"    Domain: {self.metadata.get('domain', 'Unknown')}")
            print(f"    Collection Date: {self.metadata.get('collection_date', 'Unknown')}")
            
            # Build graph components
            self._add_user_nodes(data.get('users', []))
            self._add_group_nodes(data.get('groups', []))
            self._add_computer_nodes(data.get('computers', []))
            self._add_spn_nodes(data.get('spns', []))
            
            self._add_membership_edges(data.get('group_memberships', []))
            self._add_spn_edges(data.get('spns', []))
            self._add_delegation_edges(data.get('delegation', []))
            self._add_acl_edges(data.get('acl_permissions', []))
            
            # Update statistics
            self.statistics['nodes'] = self.G.number_of_nodes()
            self.statistics['edges'] = self.G.number_of_edges()
            
            print(f"[+] Graph built successfully")
            print(f"    Nodes: {self.statistics['nodes']}")
            print(f"    Edges: {self.statistics['edges']}")
            
            return True
            
        except FileNotFoundError:
            print(f"[-] Error: File not found: {filepath}")
            return False
        except json.JSONDecodeError as e:
            print(f"[-] Error: Invalid JSON format: {e}")
            return False
        except Exception as e:
            print(f"[-] Error loading data: {e}")
            return False
    
    def _add_user_nodes(self, users: List[Dict]) -> None:
        """Add user nodes to graph"""
        for user in users:
            node_id = f"User:{user['sam_account_name']}"
            self.G.add_node(
                node_id,
                node_type='user',
                sam=user['sam_account_name'],
                dn=user['distinguished_name'],
                sid=user['sid'],
                enabled=user['enabled'],
                description=user.get('description', ''),
                has_delegation=user.get('has_delegation', False)
            )
            self.statistics['users'] += 1
    
    def _add_group_nodes(self, groups: List[Dict]) -> None:
        """Add group nodes to graph"""
        for group in groups:
            node_id = f"Group:{group['sam_account_name']}"
            self.G.add_node(
                node_id,
                node_type='group',
                sam=group['sam_account_name'],
                dn=group['distinguished_name'],
                sid=group['sid'],
                description=group.get('description', ''),
                group_category=group.get('group_category', ''),
                group_scope=group.get('group_scope', '')
            )
            self.statistics['groups'] += 1
    
    def _add_computer_nodes(self, computers: List[Dict]) -> None:
        """Add computer nodes to graph"""
        for computer in computers:
            node_id = f"Computer:{computer['sam_account_name']}"
            self.G.add_node(
                node_id,
                node_type='computer',
                sam=computer['sam_account_name'],
                dn=computer['distinguished_name'],
                sid=computer['sid'],
                enabled=computer['enabled'],
                os=computer.get('operating_system', ''),
                trusted_for_delegation=computer.get('trusted_for_delegation', False)
            )
            self.statistics['computers'] += 1
    
    def _add_spn_nodes(self, spns: List[Dict]) -> None:
        """Add SPN nodes to graph"""
        # Create unique SPN nodes (SPNs can be shared)
        spn_set = set()
        for spn_entry in spns:
            spn_value = spn_entry['spn']
            if spn_value not in spn_set:
                node_id = f"SPN:{spn_value}"
                self.G.add_node(
                    node_id,
                    node_type='spn',
                    spn=spn_value
                )
                spn_set.add(spn_value)
                self.statistics['spns'] += 1
    
    def _add_membership_edges(self, memberships: List[Dict]) -> None:
        """Add group membership edges"""
        for membership in memberships:
            member_type = membership['member_type']
            member_sam = membership['member_sam']
            group_sam = membership['group_sam']
            is_direct = membership['direct_membership']
            
            # Construct node IDs
            if member_type == 'user':
                source = f"User:{member_sam}"
            elif member_type == 'computer':
                source = f"Computer:{member_sam}"
            elif member_type == 'group':
                source = f"Group:{member_sam}"
            else:
                continue  # Skip unknown types
            
            target = f"Group:{group_sam}"        
            
            # Only add edge if both nodes exist
            if self.G.has_node(source) and self.G.has_node(target):
                self.G.add_edge(
                    source,
                    target,
                    edge_type='member_of',
                    direct_membership=is_direct,
                    conditional=False,
                    mediation='direct'
                )
    
    def _add_spn_edges(self, spns: List[Dict]) -> None:
        """Add SPN edges (identity -> SPN)"""
        for spn_entry in spns:
            identity_type = spn_entry['identity_type']
            identity_sam = spn_entry['identity_sam']
            spn_value = spn_entry['spn']
            
            # Construct source node ID
            if identity_type == 'user':
                source = f"User:{identity_sam}"
            elif identity_type == 'computer':
                source = f"Computer:{identity_sam}"
            else:
                continue
            
            target = f"SPN:{spn_value}"
            
            # Add edge if both nodes exist
            if self.G.has_node(source) and self.G.has_node(target):
                self.G.add_edge(
                    source,
                    target,
                    edge_type='has_spn',
                    conditional=False,
                    mediation='direct',
                    enabled=spn_entry.get('enabled', True)
                )
    
    def _add_delegation_edges(self, delegations: List[Dict]) -> None:
        """Add delegation edges (conditional authority)"""
        for deleg in delegations:
            identity_type = deleg['identity_type']
            identity_sam = deleg['identity_sam']
            delegation_type = deleg['delegation_type']
            allowed_targets = deleg.get('allowed_targets', [])
            
            # Construct source node ID
            if identity_type == 'user':
                source = f"User:{identity_sam}"
            elif identity_type == 'computer':
                source = f"Computer:{identity_sam}"
            else:
                continue
            
            if not self.G.has_node(source):
                continue
            
            if delegation_type == 'unconstrained':
                # Unconstrained delegation - can impersonate anyone
                target = "Identity:*"
                # Create wildcard node if it doesn't exist
                if not self.G.has_node(target):
                    self.G.add_node(target, node_type='wildcard', description='Any identity')
                
                self.G.add_edge(
                    source,
                    target,
                    edge_type='trusted_for_delegation',
                    delegation_type='unconstrained',
                    conditional=True,
                    conditions=['target_authenticates', 'forwardable_ticket'],
                    mediation='kdc'
                )
            
            elif delegation_type in ['constrained', 'constrained_with_protocol_transition']:
                # Constrained delegation - specific targets
                if allowed_targets:
                    for target_spn in allowed_targets:
                        target = f"SPN:{target_spn}"
                        # Create SPN node if it doesn't exist
                        if not self.G.has_node(target):
                            self.G.add_node(target, node_type='spn', spn=target_spn)
                        
                        self.G.add_edge(
                            source,
                            target,
                            edge_type='constrained_delegation',
                            delegation_type=delegation_type,
                            conditional=True,
                            conditions=['specific_service_only'],
                            mediation='kdc'
                        )
    
    def _add_acl_edges(self, acl_permissions: List[Dict]) -> None:
        """Add ACL permission edges"""
        # Pre-build SAM lookup sets from already-loaded nodes so we can
        # resolve trustees in DOMAIN\username format (produced by the
        # PowerShell collector) as well as the legacy type:sam format.
        user_sams     = {d.get('sam', '') for n, d in self.G.nodes(data=True) if d.get('node_type') == 'user'}
        group_sams    = {d.get('sam', '') for n, d in self.G.nodes(data=True) if d.get('node_type') == 'group'}
        computer_sams = {d.get('sam', '') for n, d in self.G.nodes(data=True) if d.get('node_type') == 'computer'}

        for acl in acl_permissions:
            target_type = acl['target_type']
            target_sam = acl['target_sam']
            trustee_identity = acl['trustee_identity']
            permission = acl['permission']
            
            object_type_guid = acl.get('object_type_guid')

            # ── Resolve trustee to a graph node ID ──────────────────────────
            # Format 1 (legacy): "type:sam"  e.g. "user:mdsiraj"
            # Format 2 (PS collector): "DOMAIN\username" e.g. "BLUES\mdsiraj"
            source = None

            if ':' in trustee_identity:
                parts = trustee_identity.split(':', 1)
                trustee_type = parts[0].lower()
                trustee_sam  = parts[1]
                if trustee_type == 'user':
                    source = f"User:{trustee_sam}"
                elif trustee_type == 'group':
                    source = f"Group:{trustee_sam}"
                elif trustee_type == 'computer':
                    source = f"Computer:{trustee_sam}"

            else:
                # DOMAIN\\username or DOMAIN\username format from PS collector
                # Use rsplit on backslash to get the SAM account name
                parts_bs = trustee_identity.replace('/', '\\').rsplit('\\', 1)
                sam = parts_bs[-1] if len(parts_bs) > 1 else ''
                if sam and sam in user_sams:
                    source = f'User:{sam}'
                elif sam and sam in group_sams:
                    source = f'Group:{sam}'
                elif sam and sam in computer_sams:
                    source = f'Computer:{sam}'
            if source is None:
                continue  # Skip system principals (NT AUTHORITY\, Everyone, etc.)
            
            
            # Construct target node ID
            if target_type == 'user':
                target = f"User:{target_sam}"
            elif target_type == 'group':
                target = f"Group:{target_sam}"
            else:
                continue
            
            # Add edge if both nodes exist and not self-referential
            if self.G.has_node(source) and self.G.has_node(target) and source != target:
                # Simplify permission name for edge type
                resolved_right = None
                if 'GenericAll' in permission:
                    edge_type = 'has_GenericAll_on'
                elif 'WriteDacl' in permission:
                    edge_type = 'has_WriteDACL_on'
                elif 'WriteOwner' in permission:
                    edge_type = 'has_WriteOwner_on'
                elif 'GenericWrite' in permission:
                    edge_type = 'has_GenericWrite_on'
                elif 'WriteProperty' in permission:
                    edge_type = 'has_WriteProperty_on'
                elif 'ExtendedRight' in permission:
                    edge_type = 'has_ExtendedRight_on'
                    resolved_right = EXTENDED_RIGHTS_MAP.get(object_type_guid)
                else:
                    edge_type = 'has_permission_on'
                
                self.G.add_edge(
                    source,
                    target,
                    edge_type=edge_type,
                    permission=permission,
                    extended_right=resolved_right if 'ExtendedRight' in permission else None,
                    conditional=False,
                    mediation='direct',
                    access_control_type=acl.get('access_control_type', 'Allow')
                )
    
    def get_graph(self) -> nx.DiGraph:
        """Return the NetworkX graph object"""
        return self.G
    
    def get_statistics(self) -> Dict:
        """Return graph statistics"""
        return self.statistics
    
    def get_metadata(self) -> Dict:
        """Return collection metadata"""
        return self.metadata
    
    def get_node(self, node_id: str) -> Optional[Dict]:
        """Get node attributes by ID"""
        if self.G.has_node(node_id):
            return dict(self.G.nodes[node_id])
        return None
    
    def get_edges_from(self, node_id: str) -> List[Tuple[str, str, Dict]]:
        """Get all outgoing edges from a node"""
        if self.G.has_node(node_id):
            return [(u, v, self.G[u][v]) for u, v in self.G.edges(node_id)]
        return []
    
    def get_edges_to(self, node_id: str) -> List[Tuple[str, str, Dict]]:
        """Get all incoming edges to a node"""
        if self.G.has_node(node_id):
            return [(u, v, self.G[u][v]) for u, v in self.G.in_edges(node_id)]
        return []
    
    def export_graph_data(self, output_file: str = "graph_data.json") -> bool:
        """
        Export graph in JSON format for external analysis.
        
        Args:
            output_file: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            graph_data = {
                'metadata': self.metadata,
                'statistics': self.statistics,
                'nodes': [],
                'edges': []
            }
            
            # Export nodes
            for node_id in self.G.nodes():
                node_data = {'id': node_id}
                node_data.update(self.G.nodes[node_id])
                graph_data['nodes'].append(node_data)
            
            # Export edges
            for u, v in self.G.edges():
                edge_data = {
                    'source': u,
                    'target': v
                }
                edge_data.update(self.G[u][v])
                graph_data['edges'].append(edge_data)
            
            with open(output_file, 'w', encoding='utf-8-sig') as f:
                json.dump(graph_data, f, indent=2)
            
            print(f"[+] Graph data exported to: {output_file}")
            return True
            
        except Exception as e:
            print(f"[-] Error exporting graph data: {e}")
            return False


def main():
    """Test the graph builder"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python graph_builder.py <json_file>")
        print("Example: python graph_builder.py blues_state0_clean.json")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    print("=== Authorization Graph Builder ===\n")
    
    # Create graph
    graph = AuthorizationGraph()
    
    # Load data
    if not graph.load_from_json(json_file):
        sys.exit(1)
    
    # Print statistics
    print("\n=== Graph Statistics ===")
    stats = graph.get_statistics()
    for key, value in stats.items():
        print(f"{key.capitalize()}: {value}")
    
    # Export graph data
    output_file = json_file.replace('.json', '_graph.json')
    graph.export_graph_data(output_file)
    
    print("\n[✓] Graph building complete!")
    print("Next step: python analyzer.py")


if __name__ == "__main__":
    main()