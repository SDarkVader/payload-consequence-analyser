#!/usr/bin/env python3
"""
Payload Consequence Analyzer
Detects destructive payloads hidden in code suggestions before merge

Usage:
    python analyze.py /path/to/repo branch-name [target-branch]
    python analyze.py /path/to/repo branch-name main
    
Example:
    python analyze.py . feature-branch main
"""

import git
import sys
import json
from datetime import datetime
from pathlib import Path


class PayloadAnalyzer:
    """
    Three-layer analysis system for detecting destructive merges.
    
    Layer 1: Surface Scan - Extract intent, identify red flags
    Layer 2: Deep Forensic Analysis - File/line deltas, temporal validation
    Layer 3: Consequence Modeling - What breaks if merged?
    """
    
    def __init__(self, repo_path, branch, target_branch="main"):
        """Initialize analyzer with repo and branch info"""
        try:
            self.repo = git.Repo(repo_path)
        except Exception as e:
            print(f"ERROR: Could not open repository at {repo_path}")
            print(f"Details: {e}")
            sys.exit(1)
        
        self.branch = branch
        self.target = target_branch
        self.repo_path = repo_path
        
    def analyze(self):
        """Execute three-layer analysis and return complete report"""
        
        try:
            # Verify both branches exist
            try:
                self.repo.commit(self.target)
            except git.exc.BadName:
                return {
                    "error": f"Target branch '{self.target}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads]
                }
            
            try:
                self.repo.commit(self.branch)
            except git.exc.BadName:
                return {
                    "error": f"Branch '{self.branch}' not found",
                    "available_branches": [ref.name for ref in self.repo.heads]
                }
            
            # Get merge base (common ancestor)
            merge_base = self.repo.merge_base(self.target, self.branch)
            
            # LAYER 2: DEEP FORENSIC ANALYSIS
            diffs = merge_base.diff(self.branch)
            
            # Count file changes by type
            files_added = len([d for d in diffs if d.change_type == 'A'])
            files_deleted = len([d for d in diffs if d.change_type == 'D'])
            files_modified = len([d for d in diffs if d.change_type == 'M'])
            files_renamed = len([d for d in diffs if d.change_type == 'R'])
            files_copied = len([d for d in diffs if d.change_type == 'C'])
            files_typed = len([d for d in diffs if d.change_type == 'T'])
            
            # Calculate line changes
            lines_added = 0
            lines_deleted = 0
            
            for d in diffs:
                if d.change_type == 'A':
                    try:
                        content = d.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                        lines_added += len(content.split('\n'))
                    except Exception:
                        pass
                elif d.change_type == 'D':
                    try:
                        content = d.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                        lines_deleted += len(content.split('\n'))
                    except Exception:
                        pass
            
            # Temporal analysis
            branch_commit = self.repo.commit(self.branch)
            target_commit = self.repo.commit(self.target)
            branch_date = branch_commit.committed_datetime
            target_date = target_commit.committed_datetime
            days_old = (target_date - branch_date).days
            
            # Calculate deletion ratio
            total_lines_changed = lines_added + lines_deleted
            deletion_ratio = (lines_deleted / total_lines_changed * 100) if total_lines_changed > 0 else 0
            
            # Calculate codebase reduction percentage
            codebase_reduction = (lines_deleted / total_lines_changed * 100) if total_lines_changed > 0 else 0
            
            # LAYER 3: CONSEQUENCE ASSESSMENT
            verdict = self._assess_consequence(
                files_deleted,
                lines_deleted,
                days_old,
                deletion_ratio
            )
            
            # Get list of deleted files
            deleted_files = [d.a_path for d in diffs if d.change_type == 'D']
            
            # Identify critical deletions
            critical_patterns = [
                'test', 'tests', '.github/workflows', 'requirements', 'setup.py',
                '__init__.py', 'core', 'modules', 'config', '.yml', '.yaml'
            ]
            critical_deletions = [
                f for f in deleted_files 
                if any(pattern.lower() in f.lower() for pattern in critical_patterns)
            ]
            
            # Build comprehensive report
            report = {
                "timestamp": datetime.now().isoformat(),
                "analysis": {
                    "branch": self.branch,
                    "target": self.target,
                    "repo_path": str(self.repo_path)
                },
                "files": {
                    "added": files_added,
                    "deleted": files_deleted,
                    "modified": files_modified,
                    "renamed": files_renamed,
                    "copied": files_copied,
                    "type_changed": files_typed,
                    "total_changed": files_added + files_deleted + files_modified + files_renamed + files_copied + files_typed
                },
                "lines": {
                    "added": lines_added,
                    "deleted": lines_deleted,
                    "net_change": lines_added - lines_deleted,
                    "deletion_ratio_percent": round(deletion_ratio, 1),
                    "codebase_reduction_percent": round(codebase_reduction, 1)
                },
                "temporal": {
                    "branch_age_days": days_old,
                    "branch_last_commit": branch_date.isoformat(),
                    "branch_commit_hash": branch_commit.hexsha[:7],
                    "target_last_commit": target_date.isoformat(),
                    "target_commit_hash": target_commit.hexsha[:7]
                },
                "verdict": verdict,
                "deleted_files": {
                    "total": len(deleted_files),
                    "critical": critical_deletions[:10],
                    "all": deleted_files[:30]
                }
            }
            
            return report
            
        except Exception as e:
            return {
                "error": f"Analysis failed: {str(e)}",
                "error_type": type(e).__name__
            }
    
    def _assess_consequence(self, files_deleted, lines_deleted, days_old, deletion_ratio):
        """
        Assess the consequence of merging this branch.
        Returns verdict with flags and recommendation.
        """
        
        flags = []
        severity_score = 0
        
        # TEMPORAL RED FLAGS
        if days_old > 365:
            flags.append(f"Branch is {days_old} days old (1+ year)")
            severity_score += 3
        elif days_old > 180:
            flags.append(f"Branch is {days_old} days old (6+ months)")
            severity_score += 2
        elif days_old > 90:
            flags.append(f"Branch is {days_old} days old (3+ months)")
            severity_score += 1
        
        # FILE DELETION RED FLAGS
        if files_deleted > 50:
            flags.append(f"{files_deleted} files would be deleted (massive scope)")
            severity_score += 3
        elif files_deleted > 20:
            flags.append(f"{files_deleted} files would be deleted (large scope)")
            severity_score += 2
        elif files_deleted > 10:
            flags.append(f"{files_deleted} files would be deleted")
            severity_score += 1
        
        # DELETION RATIO RED FLAGS
        if deletion_ratio > 90:
            flags.append(f"Deletion ratio: {deletion_ratio}% (almost entire changeset is deletions)")
            severity_score += 3
        elif deletion_ratio > 70:
            flags.append(f"Deletion ratio: {deletion_ratio}% (majority of changes are deletions)")
            severity_score += 2
        elif deletion_ratio > 50:
            flags.append(f"Deletion ratio: {deletion_ratio}% (more deletions than additions)")
            severity_score += 1
        
        # LINE COUNT RED FLAGS
        if lines_deleted > 50000:
            flags.append(f"{lines_deleted:,} lines would be deleted (massive codebase change)")
            severity_score += 3
        elif lines_deleted > 10000:
            flags.append(f"{lines_deleted:,} lines would be deleted (large codebase change)")
            severity_score += 2
        elif lines_deleted > 5000:
            flags.append(f"{lines_deleted:,} lines would be deleted")
            severity_score += 1
        
        # DETERMINE VERDICT
        if severity_score >= 5:
            return {
                "status": "DESTRUCTIVE",
                "severity": "CRITICAL",
                "flags": flags,
                "recommendation": "❌ DO NOT MERGE — This would catastrophically alter the codebase",
                "severity_score": severity_score
            }
        elif severity_score >= 3:
            return {
                "status": "CAUTION",
                "severity": "HIGH",
                "flags": flags,
                "recommendation": "⚠️  REVIEW CAREFULLY — Significant destructive changes detected",
                "severity_score": severity_score
            }
        elif severity_score >= 1:
            return {
                "status": "REVIEW",
                "severity": "MEDIUM",
                "flags": flags if flags else ["Some changes detected"],
                "recommendation": "→ Proceed with normal review process, but note the flags above",
                "severity_score": severity_score
            }
        else:
            return {
                "status": "SAFE",
                "severity": "LOW",
                "flags": flags if flags else ["No major red flags detected"],
                "recommendation": "✓ Proceed with normal review process",
                "severity_score": severity_score
            }


def print_report(report):
    """Format and print the analysis report to terminal"""
    
    if "error" in report:
        print("\n" + "="*70)
        print("❌ ANALYSIS FAILED")
        print("="*70)
        print(f"\nError: {report['error']}")
        if "error_type" in report:
            print(f"Type: {report['error_type']}")
        if "available_branches" in report:
            print(f"\nAvailable branches: {', '.join(report['available_branches'][:5])}")
        print()
        return
    
    analysis = report['analysis']
    files = report['files']
    lines = report['lines']
    temporal = report['temporal']
    verdict = report['verdict']
    deleted = report['deleted_files']
    
    # Print header
    print("\n" + "="*70)
    print(f"PAYLOAD CONSEQUENCE ANALYSIS: {analysis['branch']} → {analysis['target']}")
    print("="*70)
    
    # Temporal info
    print(f"\n📅 TEMPORAL ANALYSIS")
    print(f"   Branch age: {temporal['branch_age_days']} days")
    print(f"   Branch: {temporal['branch_commit_hash']} ({temporal['branch_last_commit'][:10]})")
    print(f"   Target: {temporal['target_commit_hash']} ({temporal['target_last_commit'][:10]})")
    
    # File changes
    print(f"\n📁 FILE CHANGES")
    print(f"   Added:    {files['added']:3d}")
    print(f"   Deleted:  {files['deleted']:3d}")
    print(f"   Modified: {files['modified']:3d}")
    print(f"   Total:    {files['total_changed']:3d}")
    
    # Line changes
    print(f"\n📝 LINE CHANGES")
    print(f"   Added:    {lines['added']:>7,} lines")
    print(f"   Deleted:  {lines['deleted']:>7,} lines")
    print(f"   Net:      {lines['net_change']:>7,} lines")
    print(f"   Deletion ratio: {lines['deletion_ratio_percent']}%")
    print(f"   Codebase reduction: {lines['codebase_reduction_percent']}%")
    
    # Verdict
    print(f"\n🔍 VERDICT: {verdict['status']} [{verdict['severity']}]")
    for flag in verdict['flags']:
        print(f"   ⚠️  {flag}")
    
    print(f"\n✉️  RECOMMENDATION:")
    print(f"   {verdict['recommendation']}")
    
    # Deleted files
    if deleted['total'] > 0:
        print(f"\n🗑️  DELETED FILES ({deleted['total']} total)")
        
        if deleted['critical']:
            print(f"\n   CRITICAL DELETIONS:")
            for f in deleted['critical']:
                print(f"      - {f}")
        
        if deleted['all'] and len(deleted['all']) > 0:
            print(f"\n   OTHER DELETIONS:")
            for f in deleted['all'][:10]:
                print(f"      - {f}")
        
        if deleted['total'] > 30:
            remaining = deleted['total'] - len(deleted['all'])
            if remaining > 0:
                print(f"      ... and {remaining} more files")
    
    print("\n" + "="*70 + "\n")


def save_json_report(report, filename="consequence_report.json"):
    """Save analysis report as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"✓ Report saved to {filename}")
    except Exception as e:
        print(f"⚠️  Could not save JSON report: {e}")


def main():
    """Main entry point"""
    
    if len(sys.argv) < 3:
        print("\n" + "="*70)
        print("PAYLOAD CONSEQUENCE ANALYZER v0.1")
        print("="*70)
        print("\nDetects destructive payloads hidden in code suggestions before merge")
        print("\nUSAGE:")
        print("  python analyze.py <repo_path> <branch> [target_branch]")
        print("\nEXAMPLES:")
        print("  python analyze.py . feature-branch main")
        print("  python analyze.py /path/to/repo old-branch main")
        print("  python analyze.py https://github.com/user/repo.git branch-name main")
        print("\nDEFAULTS:")
        print("  target_branch: main")
        print("\n" + "="*70 + "\n")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    branch = sys.argv[2]
    target_branch = sys.argv[3] if len(sys.argv) > 3 else "main"
    
    # Run analysis
    analyzer = PayloadAnalyzer(repo_path, branch, target_branch)
    report = analyzer.analyze()
    
    # Display results
    print_report(report)
    
    # Optionally save JSON
    if len(sys.argv) > 4 and sys.argv[4] == "--save-json":
        save_json_report(report)
    
    # Exit with appropriate code
    if "error" in report:
        sys.exit(1)
    elif report.get('verdict', {}).get('status') == 'DESTRUCTIVE':
        sys.exit(2)  # Destructive merge detected
    else:
        sys.exit(0)  # Safe


if __name__ == "__main__":
    main()
