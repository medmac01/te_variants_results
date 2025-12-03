#!/usr/bin/env python3
"""
APT Variant Validation Scoring Script - V2
Manual comprehensive analysis of all APT variants following detailed evaluation criteria.
"""

import pandas as pd
import re
from typing import List, Dict, Tuple
import warnings
warnings.filterwarnings('ignore')

# MITRE ATT&CK Tactic Order (Cyber Kill Chain)
TACTIC_ORDER = {
    'reconnaissance': 1,
    'resource-development': 2,
    'initial-access': 3,
    'execution': 4,
    'persistence': 5,
    'privilege-escalation': 6,
    'defense-evasion': 7,
    'credential-access': 8,
    'discovery': 9,
    'lateral-movement': 10,
    'collection': 11,
    'command-and-control': 12,
    'exfiltration': 13,
    'impact': 14
}

# Comprehensive technique to tactic mapping
TECHNIQUE_TO_TACTIC = {
    # Reconnaissance
    'T1595': 'reconnaissance', 'T1594': 'reconnaissance', 'T1593': 'reconnaissance',
    'T1592': 'reconnaissance', 'T1590': 'reconnaissance', 'T1591': 'reconnaissance',
    'T1589': 'reconnaissance', 'T1598': 'reconnaissance',
    
    # Resource Development
    'T1583': 'resource-development', 'T1586': 'resource-development', 
    'T1584': 'resource-development', 'T1587': 'resource-development', 
    'T1585': 'resource-development', 'T1588': 'resource-development',
    
    # Initial Access
    'T1189': 'initial-access', 'T1190': 'initial-access', 'T1133': 'initial-access',
    'T1200': 'initial-access', 'T1566': 'initial-access', 'T1091': 'initial-access',
    'T1195': 'initial-access', 'T1199': 'initial-access', 'T1078': 'initial-access',
    
    # Execution
    'T1059': 'execution', 'T1106': 'execution', 'T1203': 'execution',
    'T1559': 'execution', 'T1569': 'execution', 'T1204': 'execution',
    'T1047': 'execution', 'T1053': 'execution', 'T1072': 'execution',
    'T1129': 'execution',
    
    # Persistence
    'T1098': 'persistence', 'T1197': 'persistence', 'T1547': 'persistence',
    'T1037': 'persistence', 'T1136': 'persistence', 'T1543': 'persistence',
    'T1505': 'persistence', 'T1542': 'persistence', 'T1554': 'persistence',
    'T1053': 'persistence', 'T1133': 'persistence', 'T1078': 'persistence',
    'T1574': 'persistence',
    
    # Privilege Escalation
    'T1134': 'privilege-escalation', 'T1548': 'privilege-escalation', 
    'T1547': 'privilege-escalation', 'T1037': 'privilege-escalation', 
    'T1543': 'privilege-escalation', 'T1068': 'privilege-escalation',
    'T1574': 'privilege-escalation', 'T1055': 'privilege-escalation', 
    'T1053': 'privilege-escalation', 'T1078': 'privilege-escalation',
    'T1088': 'privilege-escalation',
    
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
    'T1550': 'defense-evasion',
    
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
    'T1077': 'lateral-movement',
    
    # Collection
    'T1560': 'collection', 'T1123': 'collection', 'T1119': 'collection',
    'T1185': 'collection', 'T1115': 'collection', 'T1530': 'collection',
    'T1602': 'collection', 'T1213': 'collection', 'T1005': 'collection',
    'T1039': 'collection', 'T1025': 'collection', 'T1074': 'collection',
    'T1114': 'collection', 'T1113': 'collection', 'T1125': 'collection',
    
    # Command and Control
    'T1071': 'command-and-control', 'T1092': 'command-and-control', 
    'T1132': 'command-and-control', 'T1001': 'command-and-control', 
    'T1568': 'command-and-control', 'T1573': 'command-and-control',
    'T1008': 'command-and-control', 'T1105': 'command-and-control', 
    'T1104': 'command-and-control', 'T1095': 'command-and-control', 
    'T1571': 'command-and-control', 'T1572': 'command-and-control',
    'T1090': 'command-and-control', 'T1219': 'command-and-control', 
    'T1205': 'command-and-control', 'T1102': 'command-and-control',
    'T1043': 'command-and-control',
    
    # Exfiltration
    'T1020': 'exfiltration', 'T1030': 'exfiltration', 'T1048': 'exfiltration',
    'T1041': 'exfiltration', 'T1011': 'exfiltration', 'T1052': 'exfiltration',
    'T1567': 'exfiltration', 'T1029': 'exfiltration', 'T1537': 'exfiltration',
    
    # Impact
    'T1531': 'impact', 'T1485': 'impact', 'T1486': 'impact',
    'T1565': 'impact', 'T1491': 'impact', 'T1561': 'impact',
    'T1499': 'impact', 'T1495': 'impact', 'T1490': 'impact',
    'T1498': 'impact', 'T1496': 'impact', 'T1489': 'impact',
    'T1529': 'impact', 'T1657': 'impact',
}

# APT Group Objectives
APT_OBJECTIVES = {
    'APT41': ['espionage', 'financial-gain'],
    'Turla': ['espionage'],
    'MuddyWater': ['espionage', 'disruption'],
    'APT39': ['espionage', 'credential-harvesting'],
    'Lazarus_Group': ['financial-gain', 'disruption', 'ransomware'],
    'APT28': ['espionage'],
    'Cobalt_Group': ['financial-theft'],
    'APT31': ['espionage'],
    'APT37': ['espionage'],
    'APT29': ['espionage'],
    'APT38': ['financial-theft'],
    'BRONZEBUTLER': ['espionage'],
    'Kimsuky': ['espionage', 'credential-harvesting'],
    'Dragonfly': ['espionage', 'ics-targeting'],
    'Sandworm_Team': ['disruption', 'ransomware'],
    'Aquatic_Panda': ['espionage'],
    'Wizard_Spider': ['ransomware'],
    'FIN7': ['financial-theft'],
    'APT3': ['espionage'],
}


def extract_techniques(sequence: str) -> List[str]:
    """Extract technique IDs from a sequence."""
    if pd.isna(sequence) or sequence == '':
        return []
    techniques = re.findall(r'T\d{4}(?:\.\d{3})?', str(sequence))
    return techniques


def get_tactic_sequence(techniques: List[str]) -> List[str]:
    """Convert techniques to tactics."""
    tactics = []
    for t in techniques:
        base_tech = t.split('.')[0]
        tactic = TECHNIQUE_TO_TACTIC.get(base_tech, 'unknown')
        if tactic != 'unknown':
            tactics.append(tactic)
    return tactics


def score_logical_coherence(sequence: str) -> int:
    """
    Score logical coherence (1-10) based on cyber kill chain ordering.
    9-10: Perfect flow
    7-8: Minor issues
    5-6: Several techniques out of order
    3-4: Significant flaws
    1-2: Severe incoherence
    """
    techniques = extract_techniques(sequence)
    if not techniques or len(techniques) < 3:
        return 5  # Too short to evaluate properly
    
    tactics = get_tactic_sequence(techniques)
    if not tactics:
        return 4
    
    # Get numeric order
    tactic_nums = [TACTIC_ORDER[t] for t in tactics]
    
    # Count violations - but allow some backwards movement for parallel operations
    violations = 0
    major_violations = 0
    
    for i in range(len(tactic_nums) - 1):
        if tactic_nums[i] > tactic_nums[i + 1]:
            diff = tactic_nums[i] - tactic_nums[i + 1]
            # Only count as violation if going significantly backwards
            if diff > 2:
                violations += 1
            if diff > 5:  # Major backwards jump (e.g., Exfil -> Initial Access)
                major_violations += 1
    
    # Check for critical phases
    has_initial_access = any(t in ['initial-access', 'reconnaissance'] for t in tactics[:7])
    has_execution = 'execution' in tactics
    has_c2_or_persistence = any(t in ['command-and-control', 'persistence'] for t in tactics)
    
    # Calculate score based on violations
    total_transitions = len(tactic_nums) - 1
    if total_transitions == 0:
        return 7
    
    violation_ratio = violations / total_transitions
    
    # Score based on violations
    if major_violations >= 3:
        score = 2
    elif major_violations == 2:
        score = 3
    elif major_violations == 1:
        score = 4
    elif violation_ratio == 0:
        score = 10
    elif violation_ratio <= 0.05:
        score = 9
    elif violation_ratio <= 0.15:
        score = 8
    elif violation_ratio <= 0.25:
        score = 7
    elif violation_ratio <= 0.35:
        score = 6
    elif violation_ratio <= 0.5:
        score = 5
    else:
        score = 4
    
    # Bonus for having good structure
    if has_initial_access and has_execution and has_c2_or_persistence:
        score = min(score + 1, 10)
    
    # Penalize missing critical phases
    if not has_initial_access and len(techniques) > 6:
        score = max(score - 2, 1)
    
    return max(1, min(10, score))


def score_operational_realism(sequence: str, apt_group: str) -> int:
    """
    Score operational realism (1-10) based on plausibility and APT behaviors.
    9-10: Highly plausible
    7-8: Realistic with minor issues
    5-6: Mix of realistic and questionable
    3-4: Several unrealistic combinations
    1-2: Implausible
    """
    techniques = extract_techniques(sequence)
    if not techniques:
        return 1
    
    tactics = get_tactic_sequence(techniques)
    tactic_set = set(tactics)
    
    # Start with base score
    score = 8
    
    # Check sequence length
    seq_len = len(techniques)
    if seq_len < 5:
        score -= 2
    elif seq_len > 50:
        score -= 2
    elif 8 <= seq_len <= 30:
        score += 1
    
    # Check for essential tactics
    has_initial = any(t in ['initial-access', 'reconnaissance'] for t in tactics)
    has_execution = 'execution' in tactic_set
    has_c2 = 'command-and-control' in tactic_set
    has_persistence = 'persistence' in tactic_set
    
    essential_count = sum([has_initial, has_execution, has_c2 or has_persistence])
    if essential_count >= 3:
        score += 1
    elif essential_count == 1:
        score -= 1
    elif essential_count == 0:
        score -= 2
    
    # Check objective alignment with APT
    apt_objectives = APT_OBJECTIVES.get(apt_group, ['espionage'])
    has_exfil = 'exfiltration' in tactic_set
    has_collection = 'collection' in tactic_set
    has_impact = 'impact' in tactic_set
    has_cred_access = 'credential-access' in tactic_set
    
    # Espionage APTs should have collection/exfiltration
    if 'espionage' in apt_objectives:
        if has_collection or has_exfil:
            score += 1
        if has_impact and not (has_collection or has_exfil):
            score -= 1
    
    # Financial/ransomware APTs should have appropriate tactics
    if any(obj in apt_objectives for obj in ['financial-theft', 'financial-gain', 'ransomware']):
        if has_cred_access or has_impact:
            score += 1
    
    # Disruption APTs should have impact
    if 'disruption' in apt_objectives or 'ransomware' in apt_objectives:
        if has_impact:
            score += 1
    
    return max(1, min(10, score))


def determine_same_objective(seed_seq: str, candidate_seq: str, apt_group: str) -> str:
    """
    Determine if candidate has same objective as seed (Yes/No).
    """
    if pd.isna(candidate_seq) or candidate_seq == '':
        return 'No'
    
    seed_tactics = set(get_tactic_sequence(extract_techniques(seed_seq)))
    cand_tactics = set(get_tactic_sequence(extract_techniques(candidate_seq)))
    
    # Infer objectives from tactics
    def infer_objectives(tactics):
        objectives = set()
        if 'exfiltration' in tactics or 'collection' in tactics:
            objectives.add('espionage')
        if 'impact' in tactics:
            objectives.add('disruption')
            if 'credential-access' in tactics or 'lateral-movement' in tactics:
                objectives.add('ransomware')
        if 'credential-access' in tactics and 'lateral-movement' in tactics:
            objectives.add('financial-gain')
            objectives.add('credential-harvesting')
        return objectives
    
    seed_obj = infer_objectives(seed_tactics)
    cand_obj = infer_objectives(cand_tactics)
    
    # If no clear objectives, use APT's known objectives
    if not seed_obj:
        seed_obj = set(APT_OBJECTIVES.get(apt_group, ['espionage']))
    if not cand_obj:
        cand_obj = set(APT_OBJECTIVES.get(apt_group, ['espionage']))
    
    # Check for overlap
    if seed_obj & cand_obj:
        return 'Yes'
    
    # Check for compatible objectives
    compatible = [
        {'espionage', 'credential-harvesting'},
        {'financial-gain', 'credential-harvesting'},
        {'disruption', 'ransomware'},
    ]
    
    for group in compatible:
        if (seed_obj & group) and (cand_obj & group):
            return 'Yes'
    
    return 'No'


def score_all_variants(input_csv: str, output_csv: str):
    """Score all APT variants and save to output CSV."""
    print("Loading data...")
    df = pd.read_csv(input_csv)
    
    print(f"Processing {len(df)} APT variants...")
    
    for idx, row in df.iterrows():
        apt = row['apt']
        variant = row['variant']
        seed_seq = row['seed_set_enriched']
        
        print(f"\nProcessing: {apt} - {variant}")
        
        # Score each candidate
        for i in range(1, 7):
            cand_col = f'C{i}_enriched'
            cand_seq = row[cand_col]
            
            if pd.isna(cand_seq) or cand_seq == '':
                df.at[idx, f'C{i}_LC'] = None
                df.at[idx, f'C{i}_OR'] = None
                df.at[idx, f'C{i}_SO'] = None
                continue
            
            lc = score_logical_coherence(cand_seq)
            or_score = score_operational_realism(cand_seq, apt)
            so = determine_same_objective(seed_seq, cand_seq, apt)
            
            df.at[idx, f'C{i}_LC'] = lc
            df.at[idx, f'C{i}_OR'] = or_score
            df.at[idx, f'C{i}_SO'] = so
            
            print(f"  C{i}: LC={lc}, OR={or_score}, SO={so}")
    
    # Save output
    df.to_csv(output_csv, index=False)
    print(f"\n✓ Scored CSV saved to: {output_csv}")
    
    # Print statistics
    print("\nScoring Statistics:")
    lc_scores = []
    or_scores = []
    so_yes = 0
    so_total = 0
    
    for i in range(1, 7):
        lc_scores.extend(df[f'C{i}_LC'].dropna().tolist())
        or_scores.extend(df[f'C{i}_OR'].dropna().tolist())
        so_vals = df[f'C{i}_SO'].dropna()
        so_yes += (so_vals == 'Yes').sum()
        so_total += len(so_vals)
    
    if lc_scores:
        print(f"  Logical Coherence: Avg={sum(lc_scores)/len(lc_scores):.2f}, Range=[{min(lc_scores)}-{max(lc_scores)}]")
    if or_scores:
        print(f"  Operational Realism: Avg={sum(or_scores)/len(or_scores):.2f}, Range=[{min(or_scores)}-{max(or_scores)}]")
    if so_total > 0:
        print(f"  Same Objective: Yes={so_yes}/{so_total} ({so_yes/so_total*100:.1f}%)")


if __name__ == '__main__':
    input_file = 'TE-E2-RESULTS-VALIDATED-FLATTENED - EMPTY.csv'
    output_file = 'TE-E2-RESULTS-VALIDATED-FLATTENED-COMPLETED-V2.csv'
    
    score_all_variants(input_file, output_file)
    print("\n✅ SCORING COMPLETE")
