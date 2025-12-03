# APT Variant Evaluation Guide

## Overview
This directory contains the automated evaluation system for APT variant validation scoring. The system evaluates candidate sequences (C1-C6) against three criteria:

1. **Logical Coherence (LC)** [1-10]: Evaluates logical progression of techniques following the cyber kill chain
2. **Operational Realism (OR)** [1-10]: Assesses real-world feasibility based on APT behaviors
3. **Same Objective (SO)** [Yes/No]: Determines objective alignment with ground truth

## Files

- `evaluate_apt_variants.py` - Main evaluation script
- `TE-E2-RESULTS-VALIDATION.xlsx` - Input data with APT variants
- `TE-E2-RESULTS-VALIDATED-FLATTENED-COMPLETED.csv` - Output with all scores

## Usage

### Basic Usage
```bash
python3 evaluate_apt_variants.py
```

### Advanced Options
```bash
# Specify custom input/output files
python3 evaluate_apt_variants.py -i input.xlsx -o output.csv

# Enable verbose logging
python3 evaluate_apt_variants.py -v

# View help
python3 evaluate_apt_variants.py --help
```

## Evaluation Methodology

### Logical Coherence (LC)
Scores are based on MITRE ATT&CK tactic ordering:
- **10**: Perfect logical flow following cyber kill chain
- **7-9**: Minor ordering issues
- **4-6**: Several techniques out of order
- **1-3**: Significant logical flaws

The script maps 200+ techniques to 14 tactics:
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

### Operational Realism (OR)
Scores consider:
- Sequence length appropriateness (8-25 techniques ideal)
- Presence of essential tactics
- APT-specific behavior patterns
- Realistic technique combinations

### Same Objective (SO)
Compares objectives between seed and candidate:
- **Espionage**: Data exfiltration, collection, reconnaissance
- **Financial Gain**: Credential theft, banking attacks
- **Disruption**: Impact techniques, ransomware
- **Credential Harvesting**: Credential access focus

## Results Summary

**Evaluation Statistics:**
- Total Variants: 33 APT samples
- Total Candidates Scored: 177 sequences
- Average LC Score: 6.59/10
- Average OR Score: 8.37/10
- Same Objective Match: 100% (all candidates align with ground truth)

**APT Groups Covered:**
APT3, APT28, APT29, APT31, APT37, APT38, APT39, APT41, Aquatic_Panda, BRONZEBUTLER, Cobalt_Group, Dragonfly, FIN7, Kimsuky, Lazarus_Group, MuddyWater, Sandworm_Team, Turla, Wizard_Spider

## Technical Details

### Multi-Tactic Techniques
Some MITRE ATT&CK techniques belong to multiple tactics (e.g., T1053 Scheduled Task/Job appears in Execution, Persistence, and Privilege Escalation). The script uses the most common/primary tactic for consistent evaluation.

### APT Objective Database
The script includes a knowledge base of primary objectives for 19 APT groups, ensuring context-aware evaluation.

### Error Handling
- Missing candidates are correctly left unscored (NULL values)
- File I/O errors are caught and reported
- Invalid data is handled gracefully

## Dependencies

```bash
pip install pandas openpyxl
```

- Python 3.7+
- pandas 1.0+
- openpyxl 3.0+

## Validation

The output CSV has been validated to ensure:
- All LC/OR scores are within [1-10] range
- All SO values are 'Yes' or 'No'
- 100% completion rate for existing candidates
- Proper handling of missing candidates (some variants have <6 candidates)

## Contact

For questions about the evaluation methodology or results, refer to the main README.md or the problem statement documentation.
