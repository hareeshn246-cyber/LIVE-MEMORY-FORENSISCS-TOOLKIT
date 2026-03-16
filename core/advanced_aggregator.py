"""
Advanced Risk Aggregator
Combines scores from Process, Registry, and Kernel analysis.
"""
import logging

logger = logging.getLogger(__name__)

def calculate_advanced_risk(process_score, registry_score=0, kernel_risk=0):
    """
    Aggregates risk from multiple forensic sources.
    
    Args:
        process_score (float): 0-100 score from standard analysis
        registry_score (float): 0-100 score from registry anomalies
        kernel_risk (float): 0-100 score from kernel findings
        
    Returns:
        dict: Final advanced verdict and score
    """
    # Base weightings
    # Process: 100% (Since Kernel/Registry are removed)
    
    final_score = process_score
    risk_contributors = ["Process Analysis"]
    
    return {
        "advanced_score": min(100.0, final_score),
        "contributors": risk_contributors,
        "is_critical": final_score > 80
    }
