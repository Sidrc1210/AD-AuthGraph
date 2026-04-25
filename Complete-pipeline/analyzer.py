"""
analyzer.py - Authorization Graph Analyzer (Refactored)

Analyzes authorization graphs by directly consuming exported graph JSON.
No redundant graph reconstruction - works on pre-built graphs only.

Author: Siddharth Ray Chaudhuri
Date: 2026-02-10 (Refactored: 2026-02-10)
Purpose: Authorization Graph Modeling Project
"""

import networkx as nx
from typing import Dict, List, Tuple, Set, Optional, Union
from collections import defaultdict
from pathlib import Path
import json


class AuthorizationAnalyzer:
    """
    Analyzes authorization graphs to identify privilege escalation paths,
    security risks, and compliance issues.
    
    Consumes pre-built graph JSON directly - no redundant reconstruction.
    """
    
    def __init__(self, graph_source: Union[nx.DiGraph, str, Path]):
        """
        Initialize analyzer with a graph source.
        
        Args:
            graph_source: One of:
                - NetworkX DiGraph object (pre-built)
                - Path to graph JSON file (exported by graph_builder.py)
                - String path to graph JSON file
        
        Raises:
            ValueError: If graph source is invalid
            FileNotFoundError: If graph JSON file not found
        """
        self.G = None
        self.metadata = {}
        self._source_type = None
        
        # Cache for expensive computations
        self._da_paths_cache = None
        self._reachability_cache = {}
        
        # Load graph based on source type
        if isinstance(graph_source, nx.DiGraph):
            # Direct graph object
            self.G = graph_source
            self._source_type = 'graph_object'
            print("[+] Analyzer initialized with pre-built graph")
            
        elif isinstance(graph_source, (str, Path)):
            # Graph JSON file path
            graph_path = Path(graph_source)
            if not graph_path.exists():
                raise FileNotFoundError(f"Graph file not found: {graph_path}")
            
            if not self._load_graph_from_json(str(graph_path)):
                raise ValueError(f"Failed to load graph from: {graph_path}")
            
            self._source_type = 'graph_json'
            
        else:
            raise ValueError(
                f"Invalid graph source type: {type(graph_source)}. "
                f"Expected nx.DiGraph, str, or Path"
            )
        
        # Validate graph
        if self.G is None or not isinstance(self.G, nx.DiGraph):
            raise ValueError("Failed to initialize graph")
        
        print(f"[+] Graph loaded: {self.G.number_of_nodes()} nodes, {self.G.number_of_edges()} edges")
    
    def _load_graph_from_json(self, filepath: str) -> bool:
        """
        Load graph structure directly from exported graph JSON.
        
        This method reconstructs the NetworkX graph from the JSON format
        produced by GraphBuilder.export_graph_data().
        
        Args:
            filepath: Path to graph JSON file (*_graph.json)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"[*] Loading graph from: {filepath}")
            
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                graph_data = json.load(f)
            
            # Extract metadata
            self.metadata = graph_data.get('metadata', {})
            
            # Validate structure
            if 'nodes' not in graph_data or 'edges' not in graph_data:
                print("[-] Error: Invalid graph JSON format (missing nodes or edges)")
                return False
            
            # Create empty directed graph
            self.G = nx.DiGraph()
            
            # Add nodes with attributes
            for node_data in graph_data['nodes']:
                node_id = node_data.pop('id')  # Remove 'id' from attributes
                self.G.add_node(node_id, **node_data)
            
            # Add edges with attributes
            for edge_data in graph_data['edges']:
                source = edge_data.pop('source')
                target = edge_data.pop('target')
                self.G.add_edge(source, target, **edge_data)
            
            print(f"    [+] Loaded {len(graph_data['nodes'])} nodes")
            print(f"    [+] Loaded {len(graph_data['edges'])} edges")
            
            if self.metadata:
                print(f"    Domain: {self.metadata.get('domain', 'Unknown')}")
                print(f"    Collection Date: {self.metadata.get('collection_date', 'Unknown')}")
            
            return True
            
        except FileNotFoundError:
            print(f"[-] Error: File not found: {filepath}")
            return False
        except json.JSONDecodeError as e:
            print(f"[-] Error: Invalid JSON format: {e}")
            return False
        except Exception as e:
            print(f"[-] Error loading graph: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def find_domain_admin_paths(self, use_cache: bool = True) -> Dict[str, List[List[str]]]:
        """
        Find all identities that have paths to Domain Admins.
        
        Args:
            use_cache: Use cached results if available
            
        Returns:
            Dictionary mapping identity -> list of paths to Domain Admins
        """
        if use_cache and self._da_paths_cache is not None:
            return self._da_paths_cache
        
        da_node = "Group:Domain Admins"
        
        # Check if Domain Admins exists
        if not self.G.has_node(da_node):
            print("[!] Warning: Domain Admins group not found in graph")
            return {}
        
        paths_to_da = {}
        
        # Find all paths to Domain Admins
        for node in self.G.nodes():
            # Only check user and computer nodes (identities that can escalate)
            node_type = self.G.nodes[node].get('node_type', '')
            if node_type not in ['user', 'computer']:
                continue
            
            try:
                # Find all simple paths (no cycles)
                paths = list(nx.all_simple_paths(
                    self.G, 
                    source=node, 
                    target=da_node, 
                    cutoff=10  # Max path length
                ))
                
                if paths:
                    paths_to_da[node] = paths
                    
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue
        
        # Cache results
        self._da_paths_cache = paths_to_da
        
        return paths_to_da
    
    def find_authority_paths(self, source: str, target: str, max_length: int = 10) -> List[List[str]]:
        """
        Find all paths from source identity to target authority.
        
        Args:
            source: Source node ID
            target: Target node ID
            max_length: Maximum path length to search
            
        Returns:
            List of paths (each path is a list of node IDs)
        """
        if not self.G.has_node(source):
            print(f"[!] Warning: Source node not found: {source}")
            return []
        
        if not self.G.has_node(target):
            print(f"[!] Warning: Target node not found: {target}")
            return []
        
        try:
            paths = list(nx.all_simple_paths(self.G, source, target, cutoff=max_length))
            return paths
        except nx.NetworkXNoPath:
            return []
        except Exception as e:
            print(f"[!] Error finding paths: {e}")
            return []
    
    def get_transitive_authority(self, identity: str) -> Set[str]:
        """
        Get all authorities (groups) reachable from an identity.
        
        Args:
            identity: Identity node ID
            
        Returns:
            Set of reachable group node IDs
        """
        if identity in self._reachability_cache:
            return self._reachability_cache[identity]
        
        if not self.G.has_node(identity):
            return set()
        
        # Get all reachable nodes
        reachable = nx.descendants(self.G, identity)
        
        # Filter to only groups (authorities)
        authorities = {
            node for node in reachable 
            if self.G.nodes[node].get('node_type') == 'group'
        }
        
        # Cache result
        self._reachability_cache[identity] = authorities
        
        return authorities
    
    def identify_kerberoastable_paths(self) -> Dict[str, Dict]:
        """
        Find identities with SPNs that have paths to high privilege.
        
        Returns:
            Dictionary mapping identity -> {spns, paths_to_da, risk_level}
        """
        kerberoastable = {}
        
        # Find all identities with SPNs
        for node in self.G.nodes():
            node_data = self.G.nodes[node]
            node_type = node_data.get('node_type', '')
            
            # Only users and computers can be Kerberoasted
            if node_type not in ['user', 'computer']:
                continue
            
            # Check if has SPN
            has_spn = False
            spn_list = []
            
            for neighbor in self.G.neighbors(node):
                edge_data = self.G[node][neighbor]
                if edge_data.get('edge_type') == 'has_spn':
                    has_spn = True
                    spn_value = self.G.nodes[neighbor].get('spn', '')
                    if spn_value:
                        spn_list.append(spn_value)
            
            if has_spn:
                # Check if has path to Domain Admins
                da_paths = self.find_authority_paths(node, "Group:Domain Admins")
                
                # Determine risk level
                if da_paths:
                    risk_level = "CRITICAL"
                else:
                    # Check for other high-value groups
                    authorities = self.get_transitive_authority(node)
                    high_value = any('admin' in g.lower() for g in authorities)
                    risk_level = "HIGH" if high_value else "MEDIUM"
                
                kerberoastable[node] = {
                    'spns': spn_list,
                    'spn_count': len(spn_list),
                    'paths_to_da': len(da_paths),
                    'shortest_path_length': min(len(p) for p in da_paths) if da_paths else None,
                    'authorities': list(self.get_transitive_authority(node)),
                    'risk_level': risk_level,
                    'enabled': node_data.get('enabled', True)
                }
        
        return kerberoastable
    
    def _find_da_paths_via_membership_only(self, source: str) -> List[List[str]]:
        """
        Find paths to Domain Admins using ONLY membership/delegation edges.
        ACL permission edges are excluded so that identify_acl_abuse_paths can
        correctly determine whether a source already has legitimate DA access
        independently of any ACL abuse opportunity.
        """
        da_node = "Group:Domain Admins"
        if not self.G.has_node(source) or not self.G.has_node(da_node):
            return []

        # Build a subgraph containing only non-ACL edges
        acl_prefixes = (
            'has_GenericAll_on', 'has_WriteDACL_on', 'has_WriteOwner_on',
            'has_GenericWrite_on', 'has_WriteProperty_on', 'has_ExtendedRight_on',
            'has_permission_on', 'has_GenericWrite_on',
        )
        membership_edges = [
            (u, v) for u, v, d in self.G.edges(data=True)
            if d.get('edge_type', '') not in acl_prefixes
        ]
        subgraph = self.G.edge_subgraph(membership_edges)

        if not subgraph.has_node(source) or not subgraph.has_node(da_node):
            return []

        try:
            return list(nx.all_simple_paths(subgraph, source, da_node, cutoff=10))
        except Exception:
            return []

    def identify_acl_abuse_paths(self) -> Dict[str, List[Dict]]:
        """
        Find ACL permission chains that lead to privilege escalation.

        Detects all dangerous ACL edge types produced by graph_builder, including
        has_ExtendedRight_on which covers ResetPassword and ForceChangePassword.
        Also checks the raw 'permission' attribute on each edge for additional
        dangerous rights that may be embedded in compound permission strings.
        
        Returns:
            Dictionary mapping target identity -> list of abuse paths
        """
        acl_abuse = defaultdict(list)

        # Edge type prefixes produced by graph_builder._add_acl_edges()
        # has_ExtendedRight_on covers ResetPassword / ForceChangePassword in AD
        dangerous_edge_types = [
            'has_GenericAll_on',
            'has_WriteDACL_on',
            'has_WriteOwner_on',
            'has_GenericWrite_on',
            'has_WriteProperty_on',
            'has_ExtendedRight_on',   # covers ResetPassword, ForceChangePassword
            'has_permission_on',
        ]

        # Strings to match inside the raw 'permission' attribute on an edge
        # (the full permission string from the PowerShell collector)
        dangerous_raw_perms = [
            'GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite',
            'WriteProperty', 'ExtendedRight', 'ResetPassword', 'ForceChangePassword',
        ]

        # Find all ACL permission edges
        for u, v, data in self.G.edges(data=True):
            edge_type = data.get('edge_type', '')

            # Match on edge_type (primary check) OR on raw permission string (fallback)
            raw_perm = data.get('permission', '') or data.get('full_permission', '')
            is_dangerous = (
                edge_type in dangerous_edge_types
                or any(p in raw_perm for p in dangerous_raw_perms)
            )

            if not is_dangerous:
                continue

            # NEW: Resolve specific permission name if available
            resolved_permission = data.get("extended_right") or edge_type

            # Get source and target node types
            source_type = self.G.nodes[u].get('node_type', '')
            target_type = self.G.nodes[v].get('node_type', '')

            # Check if target has a path to Domain Admins (i.e. is high-value)
            target_da_paths = self.find_authority_paths(v, "Group:Domain Admins", max_length=10)

            # Check if source already has LEGITIMATE (non-ACL) DA access.
            source_da_paths = self._find_da_paths_via_membership_only(u)

            # Case 1: Source gains NEW access to DA through target
            if target_da_paths and not source_da_paths:
                target_authorities = self.get_transitive_authority(v)
                source_authorities = self.get_transitive_authority(u)
                new_authorities = target_authorities - source_authorities

                risk_level = 'CRITICAL' if 'Group:Domain Admins' in target_authorities else 'HIGH'

                shortest_target_path = min(target_da_paths, key=len)
                abuse_chain_length = len(shortest_target_path) + 1

                abuse_path = {
                    'source': u,
                    'source_type': source_type,
                    'target': v,
                    'target_type': target_type,
                    'permission': resolved_permission,  # Updated
                    'full_permission': data.get('permission', ''),
                    'authorities_gained': list(new_authorities),
                    'risk_level': risk_level,
                    'abuse_chain': [u] + shortest_target_path,
                    'chain_length': abuse_chain_length,
                    'explanation': (
                        f"{u} can use {resolved_permission} on {v} to gain access to "  # Updated
                        f"Domain Admins via: {' -> '.join([u] + shortest_target_path)}"
                    )
                }
                acl_abuse[v].append(abuse_path)

            # Case 2: Both can reach DA, but source gets a SHORTER path via target
            elif target_da_paths and source_da_paths:
                shortest_target = min(target_da_paths, key=len)
                shortest_source = min(source_da_paths, key=len)

                path_via_target = len(shortest_target) + 1
                path_direct = len(shortest_source)

                if path_via_target < path_direct:
                    target_authorities = self.get_transitive_authority(v)
                    source_authorities = self.get_transitive_authority(u)

                    abuse_path = {
                        'source': u,
                        'source_type': source_type,
                        'target': v,
                        'target_type': target_type,
                        'permission': resolved_permission,  # Updated
                        'full_permission': data.get('permission', ''),
                        'authorities_gained': list(target_authorities - source_authorities),
                        'risk_level': 'MEDIUM',
                        'abuse_chain': [u] + shortest_target,
                        'chain_length': path_via_target,
                        'explanation': (
                            f"{u} can use {resolved_permission} on {v} for shorter path to DA "  # Updated
                            f"({path_via_target} vs {path_direct} hops)"
                        )
                    }
                    acl_abuse[v].append(abuse_path)

        return dict(acl_abuse)
    
    def identify_delegation_risks(self) -> List[Dict]:
        """
        Find delegation configurations that pose security risks.
        
        Returns:
            List of delegation risk findings
        """
        risks = []
        
        for u, v, data in self.G.edges(data=True):
            edge_type = data.get('edge_type', '')
            
            if 'delegation' in edge_type.lower():
                delegation_type = data.get('delegation_type', '')
                
                # Check if source has high privilege
                source_authorities = self.get_transitive_authority(u)
                has_high_privilege = any(
                    'admin' in auth.lower() 
                    for auth in source_authorities
                )
                
                risk = {
                    'source': u,
                    'target': v,
                    'delegation_type': delegation_type,
                    'edge_type': edge_type,
                    'conditional': data.get('conditional', False),
                    'conditions': data.get('conditions', []),
                    'has_high_privilege': has_high_privilege,
                    'risk_level': 'CRITICAL' if delegation_type == 'unconstrained' and has_high_privilege else 'MEDIUM'
                }
                
                risks.append(risk)
        
        return risks
    
    def analyze_edge_criticality(self, source: str, target: str) -> Dict:
        """
        Analyze the impact of removing a specific edge.
        
        Args:
            source: Source node ID
            target: Target node ID
            
        Returns:
            Dictionary with criticality analysis
        """
        if not self.G.has_edge(source, target):
            return {'error': 'Edge does not exist'}
        
        # Get baseline DA paths
        baseline_da_paths = self.find_domain_admin_paths(use_cache=False)
        baseline_count = len(baseline_da_paths)
        
        # Temporarily remove edge
        edge_data = self.G[source][target].copy()
        self.G.remove_edge(source, target)
        
        # Clear cache and recalculate
        self._da_paths_cache = None
        self._reachability_cache = {}
        new_da_paths = self.find_domain_admin_paths(use_cache=False)
        new_count = len(new_da_paths)
        
        # Restore edge
        self.G.add_edge(source, target, **edge_data)
        
        # Clear cache again
        self._da_paths_cache = None
        self._reachability_cache = {}
        
        # Identify affected identities
        affected_identities = set(baseline_da_paths.keys()) - set(new_da_paths.keys())
        
        return {
            'edge': (source, target),
            'edge_type': edge_data.get('edge_type', 'unknown'),
            'baseline_da_paths': baseline_count,
            'after_removal_da_paths': new_count,
            'paths_broken': baseline_count - new_count,
            'affected_identities': list(affected_identities),
            'criticality': 'HIGH' if (baseline_count - new_count) > 0 else 'LOW'
        }
    
    def find_shortest_escalation_path(self, source: str) -> Optional[List[str]]:
        """
        Find the shortest privilege escalation path from source to Domain Admins.
        
        Args:
            source: Source identity node ID
            
        Returns:
            Shortest path as list of node IDs, or None if no path exists
        """
        try:
            path = nx.shortest_path(self.G, source, "Group:Domain Admins")
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    
    def get_privilege_distribution(self) -> Dict[str, int]:
        """
        Get distribution of how many identities have access to each group.
        
        Returns:
            Dictionary mapping group -> count of identities with access
        """
        distribution = {}
        
        # Get all group nodes
        groups = [n for n, d in self.G.nodes(data=True) if d.get('node_type') == 'group']
        
        for group in groups:
            # Count how many identities can reach this group
            count = 0
            for node in self.G.nodes():
                node_type = self.G.nodes[node].get('node_type', '')
                if node_type in ['user', 'computer']:
                    if group in self.get_transitive_authority(node) or node == group:
                        count += 1
            
            distribution[group] = count
        
        return distribution
    
    def compare_states(self, other_analyzer: 'AuthorizationAnalyzer') -> Dict:
        """
        Compare this authorization state with another (for evolution analysis).
        
        Args:
            other_analyzer: Another AuthorizationAnalyzer instance
            
        Returns:
            Dictionary with comparison results
        """
        # Get DA paths for both states
        current_da = self.find_domain_admin_paths()
        other_da = other_analyzer.find_domain_admin_paths()
        
        # Identify changes
        new_identities = set(current_da.keys()) - set(other_da.keys())
        removed_identities = set(other_da.keys()) - set(current_da.keys())
        
        # Count edge changes
        current_edges = set(self.G.edges())
        other_edges = set(other_analyzer.G.edges())
        new_edges = current_edges - other_edges
        removed_edges = other_edges - current_edges
        
        # Identify new risks
        current_kerb = self.identify_kerberoastable_paths()
        other_kerb = other_analyzer.identify_kerberoastable_paths()
        new_kerb_risks = set(current_kerb.keys()) - set(other_kerb.keys())
        
        return {
            'current_state': {
                'da_paths': len(current_da),
                'total_edges': len(current_edges),
                'kerberoastable': len(current_kerb)
            },
            'previous_state': {
                'da_paths': len(other_da),
                'total_edges': len(other_edges),
                'kerberoastable': len(other_kerb)
            },
            'changes': {
                'new_da_paths': list(new_identities),
                'removed_da_paths': list(removed_identities),
                'new_edges': len(new_edges),
                'removed_edges': len(removed_edges),
                'new_kerberoastable': list(new_kerb_risks)
            },
            'delta': {
                'da_paths': len(current_da) - len(other_da),
                'edges': len(current_edges) - len(other_edges),
                'kerberoastable': len(current_kerb) - len(other_kerb)
            }
        }
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate comprehensive authorization analysis report.
        
        Args:
            output_file: Optional file to save report (JSON format)
            
        Returns:
            Report as formatted string
        """
        # Gather all analysis data
        da_paths = self.find_domain_admin_paths()
        kerb_paths = self.identify_kerberoastable_paths()
        acl_abuse = self.identify_acl_abuse_paths()
        delegation_risks = self.identify_delegation_risks()
        privilege_dist = self.get_privilege_distribution()
        
        # Build report
        report_data = {
            'metadata': self.metadata,
            'summary': {
                'total_identities': sum(1 for n, d in self.G.nodes(data=True) 
                                       if d.get('node_type') in ['user', 'computer']),
                'identities_with_da_paths': len(da_paths),
                'total_da_paths': sum(len(paths) for paths in da_paths.values()),
                'kerberoastable_identities': len(kerb_paths),
                'acl_abuse_targets': len(acl_abuse),
                'delegation_risks': len(delegation_risks)
            },
            'domain_admin_paths': {
                identity: {
                    'path_count': len(paths),
                    'shortest_path_length': min(len(p) for p in paths),
                    'paths': paths
                }
                for identity, paths in da_paths.items()
            },
            'kerberoastable_analysis': kerb_paths,
            'acl_abuse_chains': acl_abuse,
            'delegation_risks': delegation_risks,
            'privilege_distribution': privilege_dist
        }
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8-sig') as f:
                    json.dump(report_data, f, indent=2)
                print(f"[+] Report saved to: {output_file}")
            except Exception as e:
                print(f"[-] Error saving report: {e}")
        
        # Generate formatted text report
        report_text = self._format_report(report_data)
        
        return report_text
    
    def _format_report(self, report_data: Dict) -> str:
        """Format report data as readable text"""
        lines = []
        
        lines.append("=" * 80)
        lines.append("ACTIVE DIRECTORY AUTHORIZATION ANALYSIS REPORT")
        lines.append("=" * 80)
        
        # Metadata
        metadata = report_data.get('metadata', {})
        lines.append(f"\nDomain: {metadata.get('domain', 'Unknown')}")
        lines.append(f"Collection Date: {metadata.get('collection_date', 'Unknown')}")
        
        # Summary
        lines.append("\n" + "=" * 80)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("=" * 80)
        
        summary = report_data['summary']
        lines.append(f"\nTotal Identities: {summary['total_identities']}")
        lines.append(f"Identities with Domain Admin Paths: {summary['identities_with_da_paths']}")
        lines.append(f"Total Privilege Escalation Paths: {summary['total_da_paths']}")
        lines.append(f"Kerberoastable Identities: {summary['kerberoastable_identities']}")
        lines.append(f"ACL Abuse Targets: {summary['acl_abuse_targets']}")
        lines.append(f"Delegation Risks: {summary['delegation_risks']}")
        
        # Domain Admin Paths
        if report_data['domain_admin_paths']:
            lines.append("\n" + "=" * 80)
            lines.append("DOMAIN ADMIN PRIVILEGE PATHS")
            lines.append("=" * 80)
            
            for identity, data in report_data['domain_admin_paths'].items():
                lines.append(f"\n{identity}")
                lines.append(f"  Path Count: {data['path_count']}")
                lines.append(f"  Shortest Path: {data['shortest_path_length']} hops")
                lines.append(f"  Example Paths:")
                for i, path in enumerate(data['paths'][:2], 1):
                    lines.append(f"    {i}. {' → '.join(path)}")
        
        # Kerberoastable
        if report_data['kerberoastable_analysis']:
            lines.append("\n" + "=" * 80)
            lines.append("KERBEROASTABLE IDENTITY ANALYSIS")
            lines.append("=" * 80)
            
            for identity, data in report_data['kerberoastable_analysis'].items():
                lines.append(f"\n{identity}")
                lines.append(f"  SPNs: {', '.join(data['spns'])}")
                lines.append(f"  Paths to DA: {data['paths_to_da']}")
                lines.append(f"  Risk Level: {data['risk_level']}")
                if data['paths_to_da'] > 0:
                    lines.append(f"  Shortest Path Length: {data['shortest_path_length']} hops")
        
        # ACL Abuse
        if report_data['acl_abuse_chains']:
            lines.append("\n" + "=" * 80)
            lines.append("ACL PERMISSION ABUSE CHAINS")
            lines.append("=" * 80)
            
            for target, chains in report_data['acl_abuse_chains'].items():
                lines.append(f"\nTarget: {target}")
                for chain in chains:
                    lines.append(f"  Source: {chain['source']}")
                    lines.append(f"  Permission: {chain['permission']}")
                    lines.append(f"  Risk Level: {chain['risk_level']}")
                                        
                    # Show full abuse chain
                    if 'abuse_chain' in chain:
                        lines.append(f"  Full Path to DA ({chain['chain_length']} hops):")
                        lines.append(f"    {' → '.join(chain['abuse_chain'])}")

                    lines.append(f"  Authorities Gained: {', '.join(chain['authorities_gained'])}") 
                    # Show explanation
                    if 'explanation' in chain:
                        lines.append(f"  Explanation: {chain['explanation']}")

        # Delegation Risks
        if report_data['delegation_risks']:
            lines.append("\n" + "=" * 80)
            lines.append("DELEGATION CONFIGURATION RISKS")
            lines.append("=" * 80)
            
            for risk in report_data['delegation_risks']:
                lines.append(f"\nSource: {risk['source']}")
                lines.append(f"  Delegation Type: {risk['delegation_type']}")
                lines.append(f"  Target: {risk['target']}")
                lines.append(f"  Risk Level: {risk['risk_level']}")
                if risk['conditional']:
                    lines.append(f"  Conditions: {', '.join(risk['conditions'])}")
        
        lines.append("\n" + "=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    @classmethod
    def from_raw_json(cls, raw_json_path: str) -> 'AuthorizationAnalyzer':
        """Backward compatibility: Create analyzer from raw AD JSON."""
        from graph_builder import AuthorizationGraph
        
        print("[*] Backward compatibility mode: building graph from raw JSON")
        
        # Build graph
        graph_builder = AuthorizationGraph()
        if not graph_builder.load_from_json(raw_json_path):
            raise ValueError(f"Failed to load raw JSON: {raw_json_path}")
        
        # Create analyzer with pre-built graph
        return cls(graph_builder.get_graph())


def main():
    """CLI interface for the analyzer"""
    import sys
    
    # Usage information
    if len(sys.argv) < 2:
        print("=" * 80)
        print("Authorization Graph Analyzer - Usage")
        print("=" * 80)
        print("\nDirect Graph Analysis (Recommended):")
        print("  python analyzer.py <graph_json_file>")
        print("  Example: python analyzer.py blues_state0_clean_graph.json")
        print("\nState Comparison:")
        print("  python analyzer.py <graph_json> --compare <other_graph_json>")
        print("\nBackward Compatibility (uses raw AD JSON):")
        print("  python analyzer.py <raw_json_file> --raw")
        sys.exit(1)
    
    graph_file = sys.argv[1]
    
    print("=" * 80)
    print("Authorization Graph Analyzer")
    print("=" * 80)
    print()
    
    use_raw = '--raw' in sys.argv
    
    try:
        if use_raw:
            analyzer = AuthorizationAnalyzer.from_raw_json(graph_file)
        else:
            analyzer = AuthorizationAnalyzer(graph_file)
    except Exception as e:
        print(f"[-] Error initializing analyzer: {e}")
        sys.exit(1)
    
    if '--compare' in sys.argv:
        try:
            compare_index = sys.argv.index('--compare')
            compare_file = sys.argv[compare_index + 1]
            
            print(f"\n[*] Loading comparison state: {compare_file}")
            
            if use_raw:
                compare_analyzer = AuthorizationAnalyzer.from_raw_json(compare_file)
            else:
                compare_analyzer = AuthorizationAnalyzer(compare_file)
            
            comparison = analyzer.compare_states(compare_analyzer)
            # (Comparison printing logic omitted for brevity)
        except (IndexError, ValueError) as e:
            print(f"[-] Error in comparison mode: {e}")
            sys.exit(1)
    else:
        print("\n[*] Analyzing authorization state...")
        output_file = graph_file.replace('_graph.json', '_analysis.json')
        report = analyzer.generate_report(output_file=output_file)
        print("\n" + report)
    
    print("\n[✓] Analysis complete!")


if __name__ == "__main__":
    main()