#!/usr/bin/env python3
"""
APT Variant Validation Scoring Script

This script evaluates APT variants (C1-C6) against ground truth samples using three criteria:
1. Logical Coherence (LC) [1-10]: Logical progression of techniques
2. Operational Realism (OR) [1-10]: Real-world feasibility
3. Same Objective (SO) [Yes/No]: Objective alignment with ground truth
"""

import pandas as pd
import re
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

# MITRE ATT&CK Tactic Ordering (Cyber Kill Chain)
TACTIC_ORDER = {
    'reconnaissance': 0,
    'resource-development': 1,
    'initial-access': 2,
    'execution': 3,
    'persistence': 4,
    'privilege-escalation': 5,
    'defense-evasion': 6,
    'credential-access': 7,
    'discovery': 8,
    'lateral-movement': 9,
    'collection': 10,
    'command-and-control': 11,
    'exfiltration': 12,
    'impact': 13
}

# Technique to Tactic Mapping (simplified - common mappings)
TECHNIQUE_TACTIC_MAP = {
    # Reconnaissance
    'T1595': 'reconnaissance', 'T1594': 'reconnaissance', 'T1593': 'reconnaissance',
    'T1592': 'reconnaissance', 'T1590': 'reconnaissance', 'T1591': 'reconnaissance',
    'T1589': 'reconnaissance', 'T1598': 'reconnaissance',
    
    # Resource Development
    'T1583': 'resource-development', 'T1586': 'resource-development', 'T1584': 'resource-development',
    'T1587': 'resource-development', 'T1585': 'resource-development', 'T1588': 'resource-development',
    
    # Initial Access
    'T1189': 'initial-access', 'T1190': 'initial-access', 'T1133': 'initial-access',
    'T1200': 'initial-access', 'T1566': 'initial-access', 'T1091': 'initial-access',
    'T1195': 'initial-access', 'T1199': 'initial-access', 'T1078': 'initial-access',
    
    # Execution
    'T1059': 'execution', 'T1106': 'execution', 'T1203': 'execution',
    'T1559': 'execution', 'T1569': 'execution', 'T1204': 'execution',
    'T1047': 'execution', 'T1053': 'execution', 'T1072': 'execution',
    
    # Persistence
    'T1098': 'persistence', 'T1197': 'persistence', 'T1547': 'persistence',
    'T1037': 'persistence', 'T1136': 'persistence', 'T1543': 'persistence',
    'T1505': 'persistence', 'T1542': 'persistence', 'T1554': 'persistence',
    'T1053': 'persistence', 'T1133': 'persistence', 'T1078': 'persistence',
    
    # Privilege Escalation
    'T1134': 'privilege-escalation', 'T1548': 'privilege-escalation', 'T1547': 'privilege-escalation',
    'T1037': 'privilege-escalation', 'T1543': 'privilege-escalation', 'T1068': 'privilege-escalation',
    'T1574': 'privilege-escalation', 'T1055': 'privilege-escalation', 'T1053': 'privilege-escalation',
    'T1078': 'privilege-escalation',
    
    # Defense Evasion
    'T1548': 'defense-evasion', 'T1134': 'defense-evasion', 'T1197': 'defense-evasion',
    'T1140': 'defense-evasion', 'T1480': 'defense-evasion', 'T1211': 'defense-evasion',
    'T1222': 'defense-evasion', 'T1564': 'defense-evasion', 'T1574': 'defense-evasion',
    'T1562': 'defense-evasion', 'T1070': 'defense-evasion', 'T1202': 'defense-evasion',
    'T1036': 'defense-evasion', 'T1556': 'defense-evasion', 'T1578': 'defense-evasion',
    'T1112': 'defense-evasion', 'T1027': 'defense-evasion', 'T1647': 'defense-evasion',
    'T1055': 'defense-evasion', 'T1542': 'defense-evasion', 'T1620': 'defense-evasion',
    'T1207': 'defense-evasion', 'T1218': 'defense-evasion', 'T1216': 'defense-evasion',
    'T1553': 'defense-evasion', 'T1221': 'defense-evasion', 'T1205': 'defense-evasion',
    'T1127': 'defense-evasion', 'T1535': 'defense-evasion', 'T1078': 'defense-evasion',
    'T1497': 'defense-evasion', 'T1600': 'defense-evasion', 'T1601': 'defense-evasion',
    
    # Credential Access
    'T1110': 'credential-access', 'T1555': 'credential-access', 'T1212': 'credential-access',
    'T1187': 'credential-access', 'T1606': 'credential-access', 'T1056': 'credential-access',
    'T1556': 'credential-access', 'T1111': 'credential-access', 'T1621': 'credential-access',
    'T1040': 'credential-access', 'T1003': 'credential-access', 'T1528': 'credential-access',
    'T1558': 'credential-access', 'T1539': 'credential-access',
    
    # Discovery
    'T1087': 'discovery', 'T1010': 'discovery', 'T1217': 'discovery',
    'T1580': 'discovery', 'T1538': 'discovery', 'T1526': 'discovery',
    'T1482': 'discovery', 'T1083': 'discovery', 'T1615': 'discovery',
    'T1046': 'discovery', 'T1135': 'discovery', 'T1040': 'discovery',
    'T1201': 'discovery', 'T1120': 'discovery', 'T1069': 'discovery',
    'T1057': 'discovery', 'T1012': 'discovery', 'T1018': 'discovery',
    'T1518': 'discovery', 'T1082': 'discovery', 'T1614': 'discovery',
    'T1016': 'discovery', 'T1049': 'discovery', 'T1033': 'discovery',
    'T1007': 'discovery', 'T1124': 'discovery', 'T1497': 'discovery',
    'T1622': 'discovery',
    
    # Lateral Movement
    'T1210': 'lateral-movement', 'T1534': 'lateral-movement', 'T1570': 'lateral-movement',
    'T1563': 'lateral-movement', 'T1021': 'lateral-movement', 'T1091': 'lateral-movement',
    'T1072': 'lateral-movement', 'T1080': 'lateral-movement', 'T1550': 'lateral-movement',
    
    # Collection
    'T1560': 'collection', 'T1123': 'collection', 'T1119': 'collection',
    'T1185': 'collection', 'T1115': 'collection', 'T1530': 'collection',
    'T1602': 'collection', 'T1213': 'collection', 'T1005': 'collection',
    'T1039': 'collection', 'T1025': 'collection', 'T1074': 'collection',
    'T1114': 'collection', 'T1113': 'collection', 'T1125': 'collection',
    
    # Command and Control
    'T1071': 'command-and-control', 'T1092': 'command-and-control', 'T1132': 'command-and-control',
    'T1001': 'command-and-control', 'T1568': 'command-and-control', 'T1573': 'command-and-control',
    'T1008': 'command-and-control', 'T1105': 'command-and-control', 'T1104': 'command-and-control',
    'T1095': 'command-and-control', 'T1571': 'command-and-control', 'T1572': 'command-and-control',
    'T1090': 'command-and-control', 'T1219': 'command-and-control', 'T1205': 'command-and-control',
    'T1102': 'command-and-control',
    
    # Exfiltration
    'T1020': 'exfiltration', 'T1030': 'exfiltration', 'T1048': 'exfiltration',
    'T1041': 'exfiltration', 'T1011': 'exfiltration', 'T1052': 'exfiltration',
    'T1567': 'exfiltration', 'T1029': 'exfiltration', 'T1537': 'exfiltration',
    
    # Impact
    'T1531': 'impact', 'T1485': 'impact', 'T1486': 'impact',
    'T1565': 'impact', 'T1491': 'impact', 'T1561': 'impact',
    'T1499': 'impact', 'T1495': 'impact', 'T1490': 'impact',
    'T1498': 'impact', 'T1496': 'impact', 'T1489': 'impact',
    'T1529': 'impact',
}

# APT Objectives
APT_OBJECTIVES = {
    'APT41': ['espionage', 'financial-gain'],
    'Turla': ['espionage'],
    'MuddyWater': ['espionage', 'disruption', 'ransomware'],
    'APT39': ['espionage', 'credential-theft'],
    'Lazarus_Group': ['financial-gain', 'disruption', 'ransomware'],
    'APT28': ['espionage', 'information-warfare'],
    'Cobalt_Group': ['financial-theft'],
    'APT31': ['espionage'],
    'APT37': ['espionage'],
    'APT29': ['espionage'],
    'APT38': ['financial-theft'],
    'BRONZEBUTLER': ['espionage'],
    'Kimsuky': ['espionage', 'credential-harvesting'],
    'Dragonfly': ['espionage', 'ics-targeting'],
    'Sandworm_Team': ['disruption', 'ransomware', 'ics-disruption'],
    'Aquatic_Panda': ['espionage', 'supply-chain'],
    'Wizard_Spider': ['ransomware'],
    'FIN7': ['financial-theft'],
    'APT3': ['espionage'],
}


def extract_techniques(sequence: str) -> List[str]:
    """Extract technique IDs from a sequence string."""
    if pd.isna(sequence) or sequence == '':
        return []
    
    # Extract all T#### patterns
    techniques = re.findall(r'T\d{4}(?:\.\d{3})?', str(sequence))
    return techniques


def get_tactic_for_technique(technique: str) -> str:
    """Get the tactic for a technique ID."""
    # Strip sub-technique notation
    base_technique = technique.split('.')[0]
    return TECHNIQUE_TACTIC_MAP.get(base_technique, 'unknown')


def evaluate_logical_coherence(sequence: str) -> int:
    """
    Evaluate logical coherence of a technique sequence.
    Returns score 1-10 based on tactic ordering.
    """
    techniques = extract_techniques(sequence)
    if not techniques:
        return 1
    
    # Get tactic sequence
    tactics = [get_tactic_for_technique(t) for t in techniques]
    tactic_order_values = [TACTIC_ORDER.get(t, -1) for t in tactics if t != 'unknown']
    
    if not tactic_order_values:
        return 5  # No known tactics, neutral score
    
    # Calculate ordering violations
    violations = 0
    for i in range(len(tactic_order_values) - 1):
        if tactic_order_values[i] > tactic_order_values[i + 1]:
            # Check if it's a major violation (e.g., going backwards significantly)
            diff = tactic_order_values[i] - tactic_order_values[i + 1]
            if diff > 3:
                violations += 2  # Major violation
            else:
                violations += 1  # Minor violation
    
    # Calculate score based on violations
    max_violations = len(tactic_order_values)
    if violations == 0:
        score = 10
    elif violations <= max_violations * 0.1:
        score = 9
    elif violations <= max_violations * 0.2:
        score = 8
    elif violations <= max_violations * 0.3:
        score = 7
    elif violations <= max_violations * 0.4:
        score = 6
    elif violations <= max_violations * 0.5:
        score = 5
    elif violations <= max_violations * 0.7:
        score = 4
    elif violations <= max_violations * 0.85:
        score = 3
    else:
        score = 2
    
    return max(1, min(10, score))


def evaluate_operational_realism(sequence: str, apt_name: str) -> int:
    """
    Evaluate operational realism of a technique sequence.
    Returns score 1-10 based on technique plausibility and APT context.
    """
    techniques = extract_techniques(sequence)
    if not techniques:
        return 1
    
    # Base score
    score = 7
    
    # Check sequence length (realistic sequences are typically 8-25 techniques)
    seq_length = len(techniques)
    if seq_length < 5:
        score -= 2  # Too short
    elif seq_length > 40:
        score -= 2  # Too long
    elif 8 <= seq_length <= 25:
        score += 1  # Ideal length
    
    # Check for essential tactics presence
    tactics = set(get_tactic_for_technique(t) for t in techniques)
    
    # Most realistic attacks have initial access, execution, and at least one of: persistence, discovery, or c2
    essential_present = 0
    if 'initial-access' in tactics or 'reconnaissance' in tactics:
        essential_present += 1
    if 'execution' in tactics:
        essential_present += 1
    if 'command-and-control' in tactics or 'persistence' in tactics:
        essential_present += 1
    
    if essential_present >= 2:
        score += 1
    elif essential_present == 1:
        score -= 1
    else:
        score -= 2
    
    # Check for unrealistic patterns
    if 'impact' in tactics and 'collection' not in tactics and 'exfiltration' not in tactics:
        # Impact without collection/exfiltration (unless it's a destructive APT)
        if apt_name not in ['Sandworm_Team', 'Wizard_Spider', 'Lazarus_Group']:
            score -= 1
    
    return max(1, min(10, score))


def infer_objective_from_sequence(sequence: str) -> List[str]:
    """Infer the primary objective from a technique sequence."""
    techniques = extract_techniques(sequence)
    tactics = [get_tactic_for_technique(t) for t in techniques]
    tactic_set = set(tactics)
    
    objectives = []
    
    # Espionage indicators
    if 'exfiltration' in tactic_set or 'collection' in tactic_set:
        objectives.append('espionage')
    
    # Financial indicators (less specific, needs context)
    if 'credential-access' in tactic_set and 'lateral-movement' in tactic_set:
        objectives.append('financial-gain')
        objectives.append('credential-theft')
    
    # Ransomware/Disruption indicators
    if 'impact' in tactic_set:
        objectives.append('disruption')
        objectives.append('ransomware')
    
    # Credential harvesting
    if 'credential-access' in tactic_set:
        objectives.append('credential-harvesting')
        objectives.append('credential-theft')
    
    # If no clear objective, assume espionage (most common)
    if not objectives:
        objectives.append('espionage')
    
    return objectives


def evaluate_same_objective(seed_sequence: str, candidate_sequence: str, apt_name: str) -> str:
    """
    Determine if candidate shares same objective as seed.
    Returns 'Yes' or 'No'.
    """
    if pd.isna(candidate_sequence) or candidate_sequence == '':
        return 'No'
    
    # Get objectives for both sequences
    seed_objectives = infer_objective_from_sequence(seed_sequence)
    candidate_objectives = infer_objective_from_sequence(candidate_sequence)
    
    # Get APT's known objectives
    apt_objectives = APT_OBJECTIVES.get(apt_name, ['espionage'])
    
    # Check if there's overlap between seed and candidate objectives
    seed_set = set(seed_objectives)
    candidate_set = set(candidate_objectives)
    apt_set = set(apt_objectives)
    
    # If candidate shares any objective with seed, return Yes
    if seed_set & candidate_set:
        return 'Yes'
    
    # If both align with APT's known objectives, return Yes
    if (seed_set & apt_set) and (candidate_set & apt_set):
        return 'Yes'
    
    # Otherwise, check if objectives are compatible
    # E.g., espionage and credential-theft are compatible
    compatible_groups = [
        {'espionage', 'credential-theft', 'credential-harvesting'},
        {'financial-gain', 'financial-theft', 'credential-theft'},
        {'disruption', 'ransomware', 'ics-disruption'},
    ]
    
    for group in compatible_groups:
        if (seed_set & group) and (candidate_set & group):
            return 'Yes'
    
    return 'No'


def evaluate_candidates(df: pd.DataFrame) -> pd.DataFrame:
    """Evaluate all candidates in the dataframe."""
    for idx, row in df.iterrows():
        apt_name = row['apt']
        seed_sequence = row['seed_set_enriched']
        
        # Evaluate each candidate (C1-C6)
        for i in range(1, 7):
            candidate_col = f'C{i}_enriched'
            candidate_sequence = row[candidate_col]
            
            # Skip if candidate doesn't exist
            if pd.isna(candidate_sequence) or candidate_sequence == '':
                df.at[idx, f'C{i}_LC'] = None
                df.at[idx, f'C{i}_OR'] = None
                df.at[idx, f'C{i}_SO'] = None
                continue
            
            # Evaluate Logical Coherence
            lc_score = evaluate_logical_coherence(candidate_sequence)
            df.at[idx, f'C{i}_LC'] = lc_score
            
            # Evaluate Operational Realism
            or_score = evaluate_operational_realism(candidate_sequence, apt_name)
            df.at[idx, f'C{i}_OR'] = or_score
            
            # Evaluate Same Objective
            so_result = evaluate_same_objective(seed_sequence, candidate_sequence, apt_name)
            df.at[idx, f'C{i}_SO'] = so_result
            
            print(f"Processed: {apt_name} - {row['variant']} - C{i} (LC={lc_score}, OR={or_score}, SO={so_result})")
    
    return df


def main():
    """Main execution function."""
    print("Loading APT variants data...")
    
    # Load the Excel file
    df_raw = pd.read_excel('TE-E2-RESULTS-VALIDATION.xlsx', sheet_name='Judgements', header=None, skiprows=2)
    
    # Define column names
    columns = [
        'apt', 'variant', 'seed_set', 'seed_set_enriched', 'len_seed_set', 'n_unique_techniques',
        'C1_enriched', 'C2_enriched', 'C3_enriched', 'C4_enriched', 'C5_enriched', 'C6_enriched',
        'C1_LC', 'C2_LC', 'C3_LC', 'C4_LC', 'C5_LC', 'C6_LC',
        'C1_OR', 'C2_OR', 'C3_OR', 'C4_OR', 'C5_OR', 'C6_OR',
        'C1_SO', 'C2_SO', 'C3_SO', 'C4_SO', 'C5_SO', 'C6_SO'
    ]
    
    df_raw.columns = columns
    
    print(f"Loaded {len(df_raw)} APT variants")
    print("\nEvaluating candidates...")
    
    # Evaluate all candidates
    df_evaluated = evaluate_candidates(df_raw)
    
    # Save to CSV
    output_file = 'TE-E2-RESULTS-VALIDATED-FLATTENED-COMPLETED.csv'
    df_evaluated.to_csv(output_file, index=False)
    
    print(f"\nEvaluation complete! Results saved to {output_file}")
    print(f"\nSummary statistics:")
    print(f"Total variants evaluated: {len(df_evaluated)}")
    
    # Print average scores
    lc_cols = [f'C{i}_LC' for i in range(1, 7)]
    or_cols = [f'C{i}_OR' for i in range(1, 7)]
    so_cols = [f'C{i}_SO' for i in range(1, 7)]
    
    print(f"\nAverage Logical Coherence: {df_evaluated[lc_cols].mean().mean():.2f}")
    print(f"Average Operational Realism: {df_evaluated[or_cols].mean().mean():.2f}")
    
    # Count Yes/No for Same Objective
    yes_count = 0
    no_count = 0
    for col in so_cols:
        yes_count += (df_evaluated[col] == 'Yes').sum()
        no_count += (df_evaluated[col] == 'No').sum()
    
    total_so = yes_count + no_count
    if total_so > 0:
        print(f"Same Objective - Yes: {yes_count} ({yes_count/total_so*100:.1f}%), No: {no_count} ({no_count/total_so*100:.1f}%)")


if __name__ == '__main__':
    main()
