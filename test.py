# export_findings.py
"""
Export Findings Module

Exports security scan findings to HTML, JSON, and PDF formats.
Generates interactive HTML reports with client-side export functionality.
"""

import json
import math
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style

# dependency for templating
from jinja2 import Template, Environment, select_autoescape, Undefined
from test3 import VULNERABILITY_DEFINITIONS


# Import vulnerability definitions for enrichment
try:
    from test3 import enrich_all_findings, VULNERABILITY_DEFINITIONS
except ImportError:
    # Fallback if vulnerability_definitions.py is not available
    def enrich_all_findings(findings):
        return findings
    VULNERABILITY_DEFINITIONS = {}


def export_to_json(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.json", target_url: str = None) -> bool:
    """Export findings to a JSON file.""" 
    try:
        total_high = sum(counts.get("High", 0) for counts in summary.values())
        total_medium = sum(counts.get("Medium", 0) for counts in summary.values())
        total_low = sum(counts.get("Low", 0) for counts in summary.values())

        report = {
            "scan_metadata": {
                "target_url": target_url or "Unknown",
                "scan_time": datetime.now().isoformat(),
                "total_findings": len(findings),
                "severity_counts": {
                    "High": total_high,
                    "Medium": total_medium,
                    "Low": total_low
                }
            },
            "summary": summary,
            "findings": findings
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(Fore.GREEN + f"✅ JSON report exported to {filename}" + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to export JSON: {e}" + Style.RESET_ALL)
        return False


# ---------------------------
# Embedded Jinja2 HTML template
# ---------------------------
REPORT_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>WebSecScan Security Report</title>

  <!-- Chart.js CDN -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

  <style>
    /* Global reset */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html,body { height:100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      color: #203040;
      background: #f2f4f8;
      padding: 20px;
      -webkit-font-smoothing:antialiased;
    }

    /* A4 sizing for print and WeasyPrint */
    .page {
      width: 210mm;
      margin: 0 auto;
      background: white;
      border-radius: 6px;
      overflow: hidden;
      box-shadow: 0 8px 30px rgba(15,23,42,0.12);
    }

    /* Header */
    .report-header {
      background: linear-gradient(135deg,#ABE7B2 0%,#F7A5A5 100%);
      color: white;
      padding: 28px 32px;
    }
    .report-title { font-size: 28px; font-weight:800; margin-bottom:6px; }
    .report-sub { color: rgba(255,255,255,0.92); opacity:0.95; font-size:14px; }

    /* Meta */
    .meta {
      display:flex;
      gap:20px;
      padding:18px 32px;
      align-items:center;
      border-bottom: 1px solid #eef2fb;
    }
    .meta .meta-item { font-size:13px; color:#2f3a47; }
    .meta code { background:#eef3ff; padding:3px 6px; border-radius:4px; font-family:monospace; }

    /* Summary area */
    .summary {
      padding: 22px 32px 30px 32px;
      display:flex;
      gap:18px;
      align-items:flex-start;
      justify-content:flex-start;
    }
    /* left summary column width match screenshot */
    .left-summary { width: 560px; min-width:360px; }
    /* right summary is a fixed card */
    .right-summary { width: 360px; flex: 0 0 360px; margin-left:18px; }

    .stat-cards { display:flex; gap:12px; margin-bottom:14px; }
    .card {
      flex:1;
      background:linear-gradient(180deg,#fff 0,#FFF5F2 150%);
      border-radius:8px;
      padding:12px;
      border:1px solid #e7eefc;
      text-align:center;
    }
    .card .num { font-size:22px; font-weight:800; color:#243140; }
    .card .label { font-size:12px; color:#6b7280; margin-top:6px; text-transform:uppercase; letter-spacing:0.6px; }

    /* Table summary */
    table.summary-table { width:100%; border-collapse:collapse; margin-top:10px; background:#F9F8F6; }
    table.summary-table th, table.summary-table td {
      padding:10px 8px; text-align:center; border-bottom:1px solid #CBCBCB;
      font-size:13px;
    }
    table.summary-table th { background:#11224E; color:#CBDCEB; font-weight:700; font-size:12px; text-transform:uppercase; }
    table.summary-table tr:hover td { background:#EFE9E3; }

    /* Chart container (right card) */
    .chart-wrapper {
      background: #FFF0EF;
      border-radius: 12px;
      padding: 20px 18px;
      border: 2px solid rgba(0,0,0,0.08);
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      min-height: 420px;
      position: relative;
    }

    .chart-wrapper .card-title {
      font-size: 18px;
      font-weight: 800;
      color: #3f5f9a;
      text-align: center;
      margin-bottom: 12px;
    }

    /* Chart canvas container */
    .chart-container {
      position: relative;
      width: 320px;
      height: 320px;
    }

    #categoryChart {
      max-width: 100%;
      max-height: 100%;
    }

    /* Details */
    .details { padding: 24px 32px 40px; }
    .details h2 { font-size:23px; color:#243140; border-bottom:3px solid #eef3ff; padding-bottom:10px; margin-bottom:18px; }

    /* Vulnerability category box */
    .category-section {
      margin-bottom:24px;
      background: white;
      border-radius:8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .category-section.risk-high { border-left: 6px solid #dc3545; }
    .category-section.risk-medium { border-left: 6px solid #fd7e14; }
    .category-section.risk-low { border-left: 6px solid #28a745; }

    .vuln-header { background: #f8f9fa; padding: 16px 20px; border-bottom: 2px solid #e9ecef; }
    .vuln-title { font-size: 18px; font-weight:700; color:#1a1a1a; margin-bottom:4px; }
    .vuln-content { padding: 20px; }

    .vuln-section { margin-bottom:20px; }
    .section-title { font-size: 14px; font-weight:700; color:#495057; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px; }
    .section-content { font-size:14px; line-height:1.6; color:#2f3a47; }

    .risk-rating { display:flex; gap:20px; align-items:center; }
    .risk-item { display:flex; align-items:center; gap:8px; }
    .risk-label { font-weight:600; color:#495057; }
    .risk-value { padding:4px 12px; border-radius:4px; font-weight:700; font-size:13px; color:white; }
    .risk-value.high { background:#dc3545; }
    .risk-value.medium { background:#fd7e14; }
    .risk-value.low { background:#28a745; }

    .instances-table { width:100%; border-collapse:collapse; margin-top:8px; border:1px solid #dee2e6; font-size:13px; }
    .instances-table th { background:#f1f3f5; padding:10px 12px; text-align:left; font-weight:600; color:#495057; border-bottom:2px solid #dee2e6; }
    .instances-table td { padding:10px 12px; border-bottom:1px solid #e9ecef; color:#2f3a47; }
    .instances-table tr:last-child td { border-bottom:none; }
    .instances-table tr:hover { background:#f8f9fa; }
    .instances-table code { background:#e7f1ff; padding:2px 6px; border-radius:3px; font-family:monospace; font-size:12px; }

    .remediation-box { background:#fff3cd; border-left:4px solid #ffc107; padding:14px 16px; border-radius:4px; }
    .remediation-box .section-title { color:#856404; margin-bottom:8px; }
    .remediation-box .section-content { color:#664d03; }

    .report-footer { background:#f8fafc; padding:14px 32px; color:#5b6b7a; font-size:13px; border-top:1px solid #eef2fb; text-align:center; }

    /* responsive */
    @media (max-width:900px) {
      .page { width:calc(100% - 40px); }
      .summary { flex-direction:column; }
      .left-summary { width:100%; }
      .right-summary { width:100%; flex: none; margin-left:0; }
      .chart-container { width: 260px; height: 260px; }
    }

    /* print */
    @page { size: A4 portrait; margin: 12mm; }
    @media print {
      body { background: white; }
      .page { box-shadow:none; border-radius:0; width: auto; }
      .chart-wrapper, .card, .summary-table { page-break-inside: avoid; }
      .report-header, .meta, .report-footer { -webkit-print-color-adjust: exact; }
      .no-print { display:none !important; }
    }

    .anchor { display:block; padding-top:40px; margin-top:-40px; }
  </style>
</head>
<body>
  <div class="page" role="document">
    <!-- HEADER -->
    <header class="report-header">
      <div class="report-title">WebSecScan Security Report</div>
      <div class="report-sub">Web Application Security Analysis</div>
    </header>

    <!-- META -->
    <div class="meta">
      <div class="meta-item"><strong>Target:</strong> <code>{{ target_url }}</code></div>
      <div class="meta-item"><strong>Scan Time:</strong> {{ scan_time }}</div>
    </div>

    <!-- SUMMARY -->
    <section class="summary" aria-label="Executive summary">
      <div class="left-summary">
        <div class="stat-cards">
          <div class="card">
            <div class="num">{{ total_findings }}</div>
            <div class="label">Total Findings</div>
          </div>
          <div class="card">
            <div class="num" style="color:Red;">{{ total_high }}</div>
            <div class="label">High</div>
          </div>
          <div class="card">
            <div class="num" style="color:Orange;">{{ total_medium }}</div>
            <div class="label">Medium</div>
          </div>
          <div class="card">
            <div class="num" style="color:Green;">{{ total_low }}</div>
            <div class="label">Low</div>
          </div>
        </div>

        <table class="summary-table" role="table" aria-label="Findings summary by category">
          <thead>
            <tr><th>Category</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
          </thead>
          <tbody>
            {% for c in categories %}
            <tr>
              <td style="font-weight:700; color:#452829">{{ c.display_name }}</td>
              <td style="font-weight:700; color:Red">{{ c.high }}</td>
              <td style="font-weight:700; color:Orange">{{ c.medium }}</td>
              <td style="font-weight:700; color:Green">{{ c.low }}</td>
              <td style="font-weight:800; color:#452829">{{ (c.high|int + c.medium|int + c.low|int) }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="right-summary">
        <div class="chart-wrapper" role="img" aria-label="Vulnerability categories chart">
          <div class="card-title">Vulnerability Categories Chart</div>
          <div class="chart-container">
            <canvas id="categoryChart"></canvas>
          </div>
          <div style="margin-top:16px;font-size:13px;font-weight:700;color:#5b6b7a;">
            Click a slice to jump to that details section.
          </div>
        </div>
      </div>
    </section>

    <!-- DETAILED FINDINGS -->
    <section class="details" id="details">
      <h2>Detailed Findings</h2>

      {% for c in categories %}
        {% set cat_name = c.name %}
        {% set findings = findings_by_category.get(cat_name, []) %}
        {% if findings|length > 0 %}

        {% set first_finding = findings[0] if findings|length > 0 else None %}

        {# derive class based on summary counts #}
        {% set risk_class = 'risk-low' %}
        {% if c.high > 0 %}
          {% set risk_class = 'risk-high' %}
        {% elif c.medium > 0 %}
          {% set risk_class = 'risk-medium' %}
        {% endif %}

        <a id="anchor-{{ loop.index0 }}" class="anchor" aria-hidden="true"></a>
        <div class="category-section {{ risk_class }}" data-category="{{ cat_name|e }}">
          <div class="vuln-header">
            {% set cat_def = category_defs.get(cat_name, {}) %}
            {% set display_title = (first_finding.get('DisplayName') if first_finding else None) or cat_def.get('DisplayName') or cat_name %}
            <div class="vuln-title">{{ display_title }}</div>
          </div>

          <div class="vuln-content">
              <div class="vuln-section">
                <div class="section-title">Description</div>
                                <div class="section-content">
                  {{ cat_def.get('Description') or (first_finding.get('Description') if first_finding else 'No description provided.') }}
                </div>
              </div>

              <div class="vuln-section">
                <div class="section-title">Risk Rating</div>
                <div class="risk-rating">
                                    {# use computed category_stats for severity/cvss per your rule #}
                  {% set stats = category_stats.get(cat_name, {}) %}
                  {% set sev = stats.get('severity') %}
                  {% set cvss_label = stats.get('cvss') or (first_finding.get('CVSS') if first_finding else 'N/A') %}

                  <div class="risk-item">
                    <span class="risk-label">Severity:</span>
                    {% if sev == 'High' %}
                      <span class="risk-value high">High</span>
                    {% elif sev == 'Medium' %}
                      <span class="risk-value medium">Medium</span>
                    {% elif sev == 'Low' %}
                      <span class="risk-value low">Low</span>
                    {% else %}
                      {# fallback to previous category-count-based display if no stats (no findings) #}
                      {% if c.high > 0 %}
                        <span class="risk-value high">High</span>
                      {% elif c.medium > 0 %}
                        <span class="risk-value medium">Medium</span>
                      {% else %}
                        <span class="risk-value low">Low</span>
                      {% endif %}
                    {% endif %}
                  </div>

                  <div class="risk-item">
                    <span class="risk-label">CVSS:</span>
                    {% set sev_class = 'low' %}
                    {% if sev == 'High' %}{% set sev_class = 'high' %}
                    {% elif sev == 'Medium' %}{% set sev_class = 'medium' %}{% endif %}
                    <span class="risk-value {{ sev_class }}">{{ cvss_label }}</span>
                  </div>
                </div>
              </div>

              <div class="vuln-section">
                <div class="section-title">Findings</div>
                <table class="instances-table" role="table" aria-label="Findings">
                  <thead>
                    <tr>
                      <th>Header</th>
                      <th>Status</th>
                      <th>Current Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for f in findings %}
                      <tr>
                        <td style="font-weight:600;">
                          {{ f.get('Header') or f.get('Context') or f.get('Detail') or 'Finding' }}
                        </td>
                        <td>{{ f.get('Status', 'Missing') }}</td>
                        <td>
                          {%- set cur = (f.get('CurrentValue') or f.get('Current Value') or f.get('Value') or f.get('Detail') or f.get('detail')) -%}
                          {%- set cur_str = (cur|string).strip() -%}
                          {% if cur is none or cur_str == "" or cur_str == "-" %}
                            - 
                          {% else %}
                            <code>{{ cur }}</code>
                          {% endif %}
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>

              {# IMPACT/CONSEQUENCE SECTION - Show specific impacts for each header #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="section-title" style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;color:#495057;">Impact / Consequence:</div>
                {% for f in findings %}
                  {% set header_name = f.get('Header', f.get('Context', '')) %}
                  {% set impact_text = f.get('Impact') %}
                  {% if impact_text and header_name %}
                    <div class="section-content" style="margin-top:12px;">
                      <div style="font-weight:600;color:#1a1a1a;margin-bottom:4px;">{{ header_name }}</div>
                      <div style="padding-left:0px;">
                        {{ impact_text }}
                      </div>
                    </div>
                  {% endif %}
                {% endfor %}
              </div>

              {# REMEDIATION SECTION - Show specific remediations for each header #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="remediation-box">
                  <div class="section-title" style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;">Remediation:</div>
                  {% for f in findings %}
                    {% set header_name = f.get('Header', f.get('Context', '')) %}
                    {% set recommendation_text = f.get('Recommendation', '') %}
                    {% if recommendation_text and header_name %}
                      <div class="section-content" style="margin-top:12px;">
                        <div style="font-weight:600;color:#856404;margin-bottom:4px;">{{ header_name }}</div>
                        <div style="padding-left:0px;">
                          {{ recommendation_text }}
                        </div>
                      </div>
                    {% endif %}
                  {% endfor %}
                </div>
              </div>

            {% else %}
              <div style="padding:10px;color:#5b6b7a;background:#f8f9fa;border-radius:6px;">
                No findings recorded for this category.
              </div>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </section>

    <footer class="report-footer">
      WebSecScan — Web Security Misconfiguration Analyzer · Generated {{ scan_time }} · <span style="opacity:.85">Lee Zhi Hui</span>
    </footer>
  </div>

  <!-- Chart.js script -->
  <script>
    (function(){
      const categories = [
        {% for c in categories %}
          { name: {{ c.name|tojson }}, high: {{ c.high|int }}, medium: {{ c.medium|int }}, low: {{ c.low|int }} }{% if not loop.last %},{% endif %}
        {% endfor %}
      ];
      const labels = categories.map(c => c.name);
      const values = categories.map(c => (c.high + c.medium + c.low));
      const palette = ['#FF6B6B','#FF9F43','#FFD43B','#6BCB77','#4D96FF','#845EC2','#00C9A7','#FF9671'];
      const colors = labels.map((_,i)=>palette[i%palette.length]);

      const ctx = document.getElementById('categoryChart').getContext('2d');
      const categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors,
            borderWidth: 2,
            borderColor: '#fff',
            hoverOffset: 8,
            spacing: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: {
              position: 'right',
              labels: { 
                boxWidth: 14, 
                padding: 10, 
                usePointStyle: true,
                font: {
                  size: 12
                }
              }
            },
            tooltip: {
              callbacks: {
                label: (ctx) => `${ctx.label}: ${ctx.raw} findings`
              }
            }
          },
          onClick(evt) {
            const points = categoryChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
            if (!points.length) return;
            const idx = points[0].index;
            const anchorId = 'anchor-' + idx;
            const el = document.getElementById(anchorId);
            if (el) { 
              el.scrollIntoView({ behavior: 'smooth', block: 'start' }); 
              return; 
            }
            const catName = labels[idx];
            const sec = document.querySelector(`[data-category="${catName}"]`);
            if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }
      });

      // keyboard accessibility for chart wrapper
      const chartWrapper = document.querySelector('.chart-wrapper');
      if (chartWrapper) {
        chartWrapper.setAttribute('tabindex','0');
        chartWrapper.addEventListener('keydown', (e)=>{
          if (e.key === 'Enter' || e.key === ' ') {
            const details = document.getElementById('details');
            if (details) details.scrollIntoView({ behavior: 'smooth' });
            e.preventDefault();
          }
        });
      }
    })();
  </script>
</body>
</html>
"""

# ---------------------------
# Helper: transform your findings+summary into 'categories' and 'findings_by_category'
# ---------------------------
def _prepare_report_data(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], debug: bool = False):
    """
    Build categories (list of {name, high, medium, low}) and findings_by_category (dict).
    This version ALWAYS computes counts from the actual `findings` list to avoid
    mismatches when `summary` is stale or empty. `summary` is used only as a
    preferred order if provided.

    Args:
        findings: list of finding dicts (each may have Category and Severity)
        summary: optional precomputed summary dict (category -> {High,Medium,Low})
        debug: if True, will print a short debug snapshot to stdout

    Returns:
        categories, findings_by_category
    """
    # 1) Group findings by category and count severities from actual findings
    findings_by_category: Dict[str, List[Dict[str, Any]]] = {}
    counts_by_category: Dict[str, Dict[str, int]] = {}

    for f in findings:
        # Normalize keys (support both "Category" and "category")
        cat = f.get("Category") or f.get("category") or "Uncategorized"
        sev = f.get("Severity") or f.get("severity") or "Low"
        sev = sev if sev in ("High", "Medium", "Low") else ("High" if sev.lower()=="high" else ("Medium" if sev.lower()=="medium" else "Low"))

        findings_by_category.setdefault(cat, []).append(f)
        if cat not in counts_by_category:
            counts_by_category[cat] = {"High": 0, "Medium": 0, "Low": 0}
        counts_by_category[cat][sev] = counts_by_category[cat].get(sev, 0) + 1

    # 2) If summary provided, try to use its order. Otherwise order by total counts desc.
    ordered_category_names = []
    if summary and isinstance(summary, dict) and len(summary) > 0:
        # preserve order of summary dict (likely insertion order from generate_summary)
        ordered_category_names = list(summary.keys())
        # But ensure we include any categories that appear in findings but not in summary
        for cat in counts_by_category.keys():
            if cat not in ordered_category_names:
                ordered_category_names.append(cat)
    else:
        # sort by total findings per category desc
        ordered_category_names = sorted(counts_by_category.keys(), key=lambda c: sum(counts_by_category[c].values()), reverse=True)

    # 3) Build final categories list using counts computed from findings
    categories = []
    for cat in ordered_category_names:
        cnts = counts_by_category.get(cat, {"High":0,"Medium":0,"Low":0})
        categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    # 4) Add any categories present in findings but missing in ordered list (shouldn't happen, but safe)
    existing = set(ordered_category_names)
    for cat, cnts in counts_by_category.items():
        if cat not in existing:
            categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    # Debugging snapshot
    if debug:
        try:
            print("DEBUG: derived categories (name, high, medium, low):")
            for c in categories:
                print(f"  - {c['name']}: H={c['high']} M={c['medium']} L={c['low']}")
            # show one example finding for each of first 3 categories (if present)
            shown = 0
            for cat in categories:
                if shown >= 3:
                    break
                items = findings_by_category.get(cat['name'], [])
                if items:
                    sample = items[0]
                    print(f"  SAMPLE for {cat['name']}: Severity={sample.get('Severity')} Desc={str(sample.get('Description',''))[:80]}")
                    shown += 1
        except Exception as e:
            print("[DEBUG] failed to print debug info:", e)

    return categories, findings_by_category


def _match_vuln_def_for_category(cat_name: str, vuln_defs: Dict[str, Any]):
    """
    Try to find the best matching vulnerability definition for a category name.
    - Exact key match first.
    - Then case-insensitive substring match (category in definition key or definition key in category).
    Returns the matched definition dict or empty dict if none found.
    """
    if not vuln_defs or not cat_name:
        return {}

    # exact match
    if cat_name in vuln_defs:
        return vuln_defs[cat_name]

    # case-insensitive substring matches
    lower_cat = cat_name.lower()
    for def_key, val in vuln_defs.items():
        key_low = def_key.lower()
        if lower_cat == key_low or lower_cat in key_low or key_low in lower_cat:
            return val

    return {}


def _compute_category_risk_for_methods(detected_items: list):
    """
    Simple rule per your requirement:
      - if detected_items is non-empty and the set == {'OPTIONS'} -> Low / 3.7 CVSS
      - if detected_items is non-empty and not the OPTIONS-only case -> Medium / 5.3 CVSS
      - if detected_items empty -> return None (caller can fall back to category default or 'N/A')
    Returns: dict with keys: severity (str) or None, cvss (str) or None
    """
    if not detected_items:
        return {"severity": None, "cvss": None}

    # Normalize names to uppercase and strip
    detected = {str(i).strip().upper() for i in detected_items if i is not None and str(i).strip() != ""}

    # OPTIONS-only case
    if detected == {"OPTIONS"}:
        return {"severity": "Low", "cvss": "3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)"}

    # Any other detected item (including OPTIONS plus others) => Medium / 5.3
    return {"severity": "Medium", "cvss": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"}


def generate_interactive_html_report(findings: List[Dict[str, Any]],
                                    summary: Dict[str, Dict[str, int]],
                                    filename: str = "security_scan_report.html",
                                    target_url: str = None) -> bool:
    """
    Generate an interactive HTML report using the embedded Jinja2 template.

    Notes:
      - The template uses Chart.js for interactive charts in the browser.
      - Findings are automatically enriched with detailed vulnerability information.
    """
    try:
        # ENRICH FINDINGS with detailed vulnerability information
        enriched_findings = enrich_all_findings(findings)
        
        # Ensure summary/findings are in expected shapes
        categories, findings_by_category = _prepare_report_data(enriched_findings, summary)

        # --- ensure each category has a category-level Description / DisplayName available ---
        category_defs: Dict[str, Dict[str, Any]] = {}
        for cat, flist in findings_by_category.items():
            if not flist:
                continue

            # look up vuln definition for this category using intelligent matching
            vuln_def = _match_vuln_def_for_category(cat, VULNERABILITY_DEFINITIONS) or {}

            # Force set Description and DisplayName for ALL findings in this category if missing
            for finding in flist:
                # Always set Description from definition if not present
                if vuln_def.get("Description") and not finding.get("Description"):
                    finding["Description"] = vuln_def["Description"]
                
                # Always set DisplayName from definition if available and not overridden
                if vuln_def.get("DisplayName") and not finding.get("DisplayName"):
                    finding["DisplayName"] = vuln_def["DisplayName"]

            # store matched def so template can prefer category-level description/title
            category_defs[cat] = vuln_def

        # category_stats: map category_name -> {"severity": "Low|Medium|None", "cvss": "x.y (...)"}
        category_stats = {}
        for cat_name, flist in findings_by_category.items():
            # If no findings for this category, keep None so template can show "No findings recorded..."
            if not flist:
                category_stats[cat_name] = {"severity": None, "cvss": None}
                continue

            # Build the set/list of detected "sub-items" that represent the finding identity
            # For HTTP methods scanner, findings typically have e.g. f.get('Method') or f.get('Header') or f.get('Context')
            # We'll try common keys; adjust if your findings use a different key.
            detected_items = []
            for f in flist:
                # prefer explicit 'Method' if present, otherwise fallback to known fields
                method_name = f.get("Method") or f.get("Header") or f.get("Context") or f.get("Detail") or f.get("name") or ""
                if method_name:
                    detected_items.append(method_name)

            # compute risk using the simple rule function
            risk = _compute_category_risk_for_methods(detected_items)
            category_stats[cat_name] = {"severity": risk.get("severity"), "cvss": risk.get("cvss")}

        # Totals
        total_high = sum(c["high"] for c in categories)
        total_medium = sum(c["medium"] for c in categories)
        total_low = sum(c["low"] for c in categories)
        total_findings = total_high + total_medium + total_low

        # Add a display_name into each category entry (prefer definition DisplayName -> category name)
        for c in categories:
            matched_def = _match_vuln_def_for_category(c["name"], VULNERABILITY_DEFINITIONS) or {}
            # If matched_def has DisplayName, use it; fallback to the raw category name
            c["display_name"] = matched_def.get("DisplayName") or c["name"]

        # Render the template using an Environment that enables `do`
        env = Environment(
            extensions=["jinja2.ext.do"],
            autoescape=select_autoescape(["html", "xml"]),
            undefined=Undefined
        )

        tmpl = env.from_string(REPORT_TEMPLATE)
        rendered = tmpl.render(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            categories=categories,
            findings_by_category=findings_by_category,
            vuln_defs=VULNERABILITY_DEFINITIONS,
            category_defs=category_defs,
            category_stats=category_stats
        )

        # Write file
        with open(filename, 'w', encoding='utf-8') as f:  
            f.write(rendered)

        print(Fore.GREEN + f"✅ Interactive HTML report generated: {filename}" + Style.RESET_ALL)
        print(Fore.CYAN + f"   Open the file in a browser to view and export the report." + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to generate interactive HTML: {e}" + Style.RESET_ALL)
        import traceback
        traceback.print_exc()
        return False


# Legacy function for backward compatibility
def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """Legacy function - redirects to interactive HTML generation."""
    return generate_interactive_html_report(findings, summary, filename, target_url)