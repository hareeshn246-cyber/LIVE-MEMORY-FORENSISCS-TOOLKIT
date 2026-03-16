
import networkx as nx
import logging

class BehaviorGraph:
    """
    Constructs and analyzes a directed behavioral graph from event logs.
    Nodes represent entities (User, Host, Process, File).
    Edges represent behavioral interactions with timestamps.
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.logger = logging.getLogger("BehaviorGraph")

    def add_event(self, source_entity, target_entity, timestamp, event_type=None):
        """
        Adds a directed edge from source to target representing an interaction.
        """
        if not source_entity or not target_entity:
            return

        # Add nodes if they don't exist (NetworkX handles this automatically, but good to be explicit for attributes)
        if not self.graph.has_node(source_entity):
            self.graph.add_node(source_entity, type="entity")
        if not self.graph.has_node(target_entity):
            self.graph.add_node(target_entity, type="entity")

        # Add edge with timestamp
        # We can store multiple events between same nodes? NetworkX DiGraph stores only one edge unless MultiDiGraph
        # For this implementation, we will update the weight or last_seen if edge exists, or use MultiDiGraph if detailed logs needed.
        # User requirement says "Store timestamps on edges". Let's use a list of timestamps if multiple interactions.
        
        if self.graph.has_edge(source_entity, target_entity):
            self.graph[source_entity][target_entity]['timestamps'].append(timestamp)
            self.graph[source_entity][target_entity]['weight'] += 1
        else:
            self.graph.add_edge(source_entity, target_entity, timestamps=[timestamp], weight=1, event_type=event_type)

    def compute_features(self):
        """
        Computes structural graph features for each node.
        Returns a dictionary mapping node_id -> feature_dict.
        Features: In-degree, Out-degree, Betweenness, PageRank, Clustering.
        """
        if self.graph.number_of_nodes() == 0:
            return {}

        features = {}
        
        # 1. Degree Centrality
        in_degree = nx.in_degree_centrality(self.graph)
        out_degree = nx.out_degree_centrality(self.graph)
        
        # 2. Betweenness Centrality
        # k=None uses all nodes (exact). For very large graphs, might need approximation.
        betweenness = nx.betweenness_centrality(self.graph)
        
        # 3. PageRank
        try:
            pagerank = nx.pagerank(self.graph)
        except nx.PowerIterationFailedConvergence:
            self.logger.warning("PageRank failed to converge, using default values.")
            pagerank = {n: 0.0 for n in self.graph.nodes()}

        # 4. Clustering Coefficient (defined for directed graphs in NetworkX?)
        # nx.clustering works for directed graphs but might warn.
        clustering = nx.clustering(self.graph)

        nodes = self.graph.nodes()
        for node in nodes:
            # Normalize implicitly by NetworkX algorithms where possible, but ensure [0,1] range
            # Degree centralities are already normalized by 1/(N-1)
            # Betweenness is normalized by 1/((N-1)(N-2))
            # PageRank sums to 1
            # Clustering is [0,1]
            
            features[node] = {
                "in_degree": in_degree.get(node, 0.0),
                "out_degree": out_degree.get(node, 0.0),
                "betweenness": betweenness.get(node, 0.0),
                "pagerank": pagerank.get(node, 0.0),
                "clustering": clustering.get(node, 0.0)
            }
            
        return features

    def get_node_features(self, node_id):
        """
        Returns the feature vector for a specific node as a list (for ML input).
        Order: [in_degree, out_degree, betweenness, pagerank, clustering]
        """
        features = self.compute_features() # Recomputing all for now. In prod, cache this.
        if node_id not in features:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        
        f = features[node_id]
        return [
            f["in_degree"],
            f["out_degree"],
            f["betweenness"],
            f["pagerank"],
            f["clustering"]
        ]

    def save_graph(self, filepath):
        """
        Saves the current graph structure to a JSON file.
        """
        import json
        import os
        
        data = {
            "nodes": [],
            "edges": []
        }
        
        for node, attrs in self.graph.nodes(data=True):
            data["nodes"].append({"id": node, **attrs})
            
        for source, target, attrs in self.graph.edges(data=True):
            # timestamps might not be JSON serializable if they are datetime objects, 
            # but we are passing floats/ints usually.
            data["edges"].append({"source": source, "target": target, **attrs})
            
        try:
            directory = os.path.dirname(filepath)
            if not os.path.exists(directory):
                os.makedirs(directory)
                
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            self.logger.info(f"Graph saved to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save graph: {e}")
            return False

    def load_graph(self, filepath):
        """
        Loads the graph structure from a JSON file.
        """
        import json
        import os
        
        if not os.path.exists(filepath):
            self.logger.warning(f"Graph file not found: {filepath}")
            return False
            
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            self.graph.clear()
            
            for node in data.get("nodes", []):
                self.graph.add_node(node["id"], **{k:v for k,v in node.items() if k != "id"})
                
            for edge in data.get("edges", []):
                self.graph.add_edge(
                    edge["source"], 
                    edge["target"], 
                    **{k:v for k,v in edge.items() if k not in ["source", "target"]}
                )
                
            self.logger.info(f"Graph loaded from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load graph: {e}")
            return False
