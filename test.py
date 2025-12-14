# export_findings.py
"""
Export Findings Module

Exports security scan findings to HTML, JSON, and PDF formats.
Generates interactive HTML reports with client-side export functionality.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style

# dependency for templating
from jinja2 import Environment, select_autoescape, Undefined

# vulnerability definitions (enrichment + config)
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
    <div class="page" role="document"{{ page_style|default('') }}>
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

        {# derive class based on dynamic category_stats severity, fallback to counts #}
        {% set stats_for_cat = category_stats.get(cat_name, {}) %}
        {% set sev_for_cat = stats_for_cat.get('severity') %}
        {% if sev_for_cat == 'High' %}
          {% set risk_class = 'risk-high' %}
        {% elif sev_for_cat == 'Medium' %}
          {% set risk_class = 'risk-medium' %}
        {% elif sev_for_cat == 'Low' %}
          {% set risk_class = 'risk-low' %}
        {% else %}
          {# fallback to previous category-count-based display if no computed stats #}
          {% if c.high > 0 %}
            {% set risk_class = 'risk-high' %}
          {% elif c.medium > 0 %}
            {% set risk_class = 'risk-medium' %}
          {% else %}
            {% set risk_class = 'risk-low' %}
          {% endif %}
        {% endif %}

        <a id="anchor-{{ loop.index0 }}" class="anchor" aria-hidden="true"></a>
        <div class="category-section {{ risk_class }}" data-category="{{ cat_name|e }}">
          <div class="vuln-header">
            {% set cat_def = category_defs.get(cat_name, {}) %}
            {% set display_title = (first_finding.get('DisplayName') if first_finding else None) or cat_def.get('DisplayName') or cat_name %}
            <div class="vuln-title">{{ display_title }}</div>

            {% if "Server-Side" in cat_name %}
              <span style="
                display:inline-block;
                margin-top:6px;
                padding:4px 10px;
                font-size:12px;
                font-weight:700;
                background:#e7f1ff;
                color:#1c4ed8;
                border-radius:999px;">
                SERVER-SIDE
              </span>
            {% elif "Client-Side" in cat_name %}
              <span style="
                display:inline-block;
                margin-top:6px;
                padding:4px 10px;
                font-size:12px;
                font-weight:700;
                background:#fff3cd;
                color:#92400e;
                border-radius:999px;">
                CLIENT-SIDE
              </span>
            {% endif %}
          </div>

          <div class="vuln-content">
              <div class="vuln-section">
                <div class="section-title">Description</div>
                  {% set desc = cat_def.get('Description') or (first_finding.get('Description') if first_finding else 'No description provided.') %}
                  <div class="section-content">
                    {% for para in desc.split('\n\n') %}
                      <p>{{ para | trim | replace('\n', '<br/>') | safe }}</p>
                    {% endfor %}
                  </div>
              </div>

              <div class="vuln-section">
                <div class="section-title">Risk Rating</div>
                <div class="risk-rating">
                  {# use computed category_stats for severity/cvss per your rule #}
                  {% set stats = category_stats.get(cat_name, {}) %}
                  {% set sev = stats.get('severity') %}
                  {% set cvss_label = stats.get('cvss') %}

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

                {# Get schema and rows for this category #}
                {% set schema = table_schema.get(cat_name, ["Finding","Status","Current Value"]) %}
                {% set rows = table_rows.get(cat_name, []) %}

                <table class="instances-table" role="table" aria-label="Findings">
                  <thead>
                    <tr>
                      {% for col in schema %}
                        <th>{{ col }}</th>
                      {% endfor %}
                    </tr>
                  </thead>
                  <tbody>
                    {% for row in rows %}
                      {# last element of row is the enriched finding dict we appended in row builder #}
                      {% set finding_obj = row[-1] if row|length > 0 else {} %}
                      {% set visible = row[:-1] %}
                      <tr>
                        {# render visible cells (first cell bold) #}
                        {% for cell in visible %}
                          <td {% if loop.index0 == 0 %} style="font-weight:600;" {% endif %}>
                            {% set col_name = schema[loop.index0] if schema and schema|length > loop.index0 else "" %}

                            {# --- Status column --- #}
                            {% if col_name == "Status" %}
                              <code>{{ cell }}</code>

                            {# --- Evidence / Current Value column --- #}
                            {% elif col_name in ["Evidence", "Current Value"] %}
                              {% if finding_obj.get("CurrentValue") %}
                                <code style="color:#0d6efd;">{{ finding_obj.get("CurrentValue") }}</code>
                              {% endif %}

                              {% if finding_obj.get("Detail") %}
                                <div style="margin-top:4px;">
                                  {{ finding_obj.get("Detail") }}
                                </div>
                              {% endif %}

                              {# fallback if neither exists #}
                              {% if not finding_obj.get("CurrentValue") and not finding_obj.get("Detail") %}
                                {{ cell }}
                              {% endif %}

                            {# --- default rendering --- #}
                            {% else %}
                              {{ cell }}
                            {% endif %}
                          </td>
                        {% endfor %}
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>

              {# IMPACT/CONSEQUENCE SECTION - use rows so we have the exact finding dict appended by builders #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="section-title"
                    style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;color:#495057;">
                  Impact / Consequence:
                </div>

                {% set rows_for_cat = table_rows.get(cat_name, []) %}
                {% set seen = [] %}

                {% for row in rows_for_cat %}
                  {% set f = row[-1] %}
                  {% set key = f.get('Type') or f.get('_item_short') %}
                  {% if key and key not in seen %}
                    {% do seen.append(key) %}
                    {% if f.get('Impact') %}
                      <div class="section-content" style="margin-top:12px;">
                        <div style="font-weight:600;color:#1a1a1a;margin-bottom:4px;">
                          {{ key }}
                        </div>
                        <div>{{ f.get('Impact') }}</div>
                      </div>
                    {% endif %}
                  {% endif %}
                {% endfor %}
              </div>

              {# REMEDIATION SECTION - Show specific remediations for each item #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="remediation-box">
                  <div class="section-title"
                      style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;">
                    Remediation:
                  </div>

                  {% set rows_for_cat = table_rows.get(cat_name, []) %}
                  {% set seen = [] %}

                  {% for row in rows_for_cat %}
                    {% set f = row[-1] %}
                    {% set key = f.get('Type') or f.get('_item_short') %}
                    {% if key and key not in seen %}
                      {% do seen.append(key) %}
                      {% if f.get('Recommendation') %}
                        <div class="section-content" style="margin-top:12px;">
                          <div style="font-weight:600;color:#856404;margin-bottom:4px;">
                            {{ key }}
                          </div>
                          <div>{{ f.get('Recommendation') }}</div>
                        </div>
                      {% endif %}
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
    Counts are derived from the actual findings list (summary is used only for preferred order).
    """
    findings_by_category: Dict[str, List[Dict[str, Any]]] = {}
    counts_by_category: Dict[str, Dict[str, int]] = {}

    for f in findings:
        cat = f.get("Category") or f.get("category") or "Uncategorized"
        sev = f.get("Severity") or f.get("severity") or "Low"
        sev = sev if sev in ("High", "Medium", "Low") else ("High" if str(sev).lower() == "high" else ("Medium" if str(sev).lower() == "medium" else "Low"))

        findings_by_category.setdefault(cat, []).append(f)
        counts_by_category.setdefault(cat, {"High": 0, "Medium": 0, "Low": 0})
        counts_by_category[cat][sev] = counts_by_category[cat].get(sev, 0) + 1

    ordered_category_names = []
    if summary and isinstance(summary, dict) and len(summary) > 0:
        ordered_category_names = list(summary.keys())
        for cat in counts_by_category.keys():
            if cat not in ordered_category_names:
                ordered_category_names.append(cat)
    else:
        ordered_category_names = sorted(counts_by_category.keys(), key=lambda c: sum(counts_by_category[c].values()), reverse=True)

    categories = []
    for cat in ordered_category_names:
        cnts = counts_by_category.get(cat, {"High":0,"Medium":0,"Low":0})
        categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    existing = set(ordered_category_names)
    for cat, cnts in counts_by_category.items():
        if cat not in existing:
            categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    if debug:
        try:
            print("DEBUG: derived categories (name, high, medium, low):")
            for c in categories:
                print(f"  - {c['name']}: H={c['high']} M={c['medium']} L={c['low']}")
        except Exception as e:
            print("[DEBUG] failed to print debug info:", e)

    return categories, findings_by_category


def _match_vuln_def_for_category(cat_name: str, vuln_defs: Dict[str, Any]):
    """
    Find best matching vulnerability definition for a category name.
    Exact key match first; then case-insensitive substring matches.
    """
    if not vuln_defs or not cat_name:
        return {}
    if cat_name in vuln_defs:
        return vuln_defs[cat_name]
    lower_cat = cat_name.lower()
    for def_key, val in vuln_defs.items():
        key_low = def_key.lower()
        if lower_cat == key_low or lower_cat in key_low or key_low in lower_cat:
            return val
    return {}

# ---------- Generic table builder helpers ----------
def _first_non_empty(f: dict, keys):
    """Return the first non-empty string-like value for keys from finding f."""
    for k in keys:
        if k is None:
            continue
        # allow tuple/list key => try each one
        if isinstance(k, (list, tuple)):
            for sub in k:
                v = f.get(sub)
                if v is not None and str(v).strip() != "":
                    return v
        else:
            v = f.get(k)
            if v is not None and str(v).strip() != "":
                return v
    return ""

def _rows_generic(flist, col_map):
    """
    col_map: ordered list of (column_name, candidate_keys)
      candidate_keys: list/tuple of field names to try (first non-empty wins).
    Example:
      col_map = [
        ("Finding", ["_item_short","Header","name"]),
        ("Evidence", ["CurrentValue","Current Value","Value"])
      ]
    Returns rows as list of [col1, col2, ..., finding_dict(optional?)]
    """
    rows = []
    for f in flist:
        row = []
        for _, keys in col_map:
            val = _first_non_empty(f, keys)
            row.append(val if val is not None else "")
        # append the original finding object as last cell if you need it later in template
        # but your template expects only the visible columns; do NOT append f if template assumes n cols.
        # For compatibility with current template (which expects a finding object sometimes),
        # append the finding object as extra element:
        row.append(f)
        rows.append(row)
    return rows

def _make_col_map_from_def(cat_def):
    """
    Build col_map from category definition convenience keys:
      - cat_def.get('TableColumns') -> ["Finding","Evidence"]
      - cat_def.get('TableColumnMap') -> { "Finding": ["_item_short","Header"], "Evidence": ["CurrentValue"] }
    Fallback common mapping if TableColumnMap not provided.
    """
    cols = cat_def.get("TableColumns") or []
    explicit_map = cat_def.get("TableColumnMap") or {}
    default_candidates = {
        "Finding": ["_item_short", "Header", "Context", "name"],
        "Status": ["Status", "state"],
        "Evidence": ["CurrentValue", "Current Value", "Value", "Detail"],
        "Current Value": ["CurrentValue", "Current Value", "Value", "Detail"]
    }
    col_map = []
    for col_name in cols:
        candidates = explicit_map.get(col_name) or default_candidates.get(col_name) or [col_name]
        # ensure list
        if isinstance(candidates, (str,)):
            candidates = [candidates]
        col_map.append((col_name, candidates))
    return col_map


# ---------- Utility / Table builders ----------
def _rows_for_methods(flist):
    """Return rows for methods table: [Method, Status, finding]"""
    rows = []
    for f in flist:
        method = f.get("_item_short") or f.get("Method") or f.get("Header") or f.get("Context") or ""
        method_display = str(method).strip()
        status_display = "Present"
        rows.append([method_display, status_display, f])
    return rows

def _rows_for_headers(flist):
    """Return rows for header-style table: [Header, Status, CurrentValue, finding]"""
    rows = []
    for f in flist:
        header = f.get("Header") or f.get("Context") or f.get("Detail") or f.get("_item_short") or ""
        status = f.get("Status") or f.get("state") or "Unsafe"
        cur = (f.get("CurrentValue") or f.get("Current Value") or f.get("Value") or f.get("Detail") or f.get("detail"))
        rows.append([header, status, cur, f])
    return rows

_TABLETYPE_BUILDERS = {
    "methods": (["Method", "Status"], _rows_for_methods),
    "headers": (["Header", "Status", "Current Value"], _rows_for_headers),
    "server": (["Finding", "Evidence"], _rows_for_methods),
}

# ---------- Risk rule helpers (pluggable) ----------
def _normalize_item_name(item):
    """Normalize item names for method rules (strip prefix like 'HTTP Method: OPTIONS')."""
    if not item:
        return ""
    s = str(item).strip()
    if ":" in s:
        s = s.split(":", 1)[1].strip()
    return s.upper()

def _rule_methods_options_only(cat_name, flist, cat_def):
    """Dynamic rule for Unsafe HTTP Methods."""
    if not flist:
        return {"severity": None, "cvss": None}
    detected = set()
    for f in flist:
        item = f.get("_item_short") or f.get("Method") or f.get("Header") or f.get("Context")
        nm = _normalize_item_name(item)
        if nm:
            detected.add(nm)
    if detected == {"OPTIONS"}:
        return {"severity": "Low", "cvss": "3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)"}
    else:
        return {"severity": "Medium", "cvss": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"}

_RISK_RULES = {
    "methods_options_only": _rule_methods_options_only
}

def _compute_category_risk_generic(cat_name, flist, category_defs):
    """Dispatcher for category-level dynamic risk rating. Falls back to definitions' defaults."""
    cat_def = category_defs.get(cat_name, {}) or {}
    rule_key = cat_def.get("RiskRule")
    if rule_key and rule_key in _RISK_RULES:
        result = _RISK_RULES[rule_key](cat_name, flist, cat_def)
        return {
            "severity": result.get("severity") or cat_def.get("DefaultSeverity"),
            "cvss": result.get("cvss") or cat_def.get("DefaultCVSS")
        }
    if flist:
        return {"severity": cat_def.get("DefaultSeverity"), "cvss": cat_def.get("DefaultCVSS")}
    return {"severity": None, "cvss": None}

# A4 enforcement helper (returns inline style)
def _page_style_for_a4(force_a4: bool):
    return ' style="width:210mm;max-width:210mm;margin:0 auto;"' if force_a4 else ""


def generate_interactive_html_report(findings: List[Dict[str, Any]],
                                    summary: Dict[str, Dict[str, int]],
                                    filename: str = "security_scan_report.html",
                                    target_url: str = None,
                                    force_a4: bool = False) -> bool:
    """
    Generate an interactive HTML report using the embedded Jinja2 template.
    - force_a4: when True, the outer .page gets an inline style to force A4 width
    """
    try:
        enriched_findings = enrich_all_findings(findings)
        categories, findings_by_category = _prepare_report_data(enriched_findings, summary)

        # Match defs and normalize some fields
        category_defs: Dict[str, Dict[str, Any]] = {}
        for cat, flist in findings_by_category.items():
            vuln_def = _match_vuln_def_for_category(cat, VULNERABILITY_DEFINITIONS) or {}
            category_defs[cat] = vuln_def

            if not flist:
                continue

            # figure out per-item key if present
            item_key = None
            if "ItemDetails" in vuln_def: 
                item_key = "ItemDetails"

            for finding in flist:
                if vuln_def.get("DisplayName") and not finding.get("DisplayName"):
                    finding["DisplayName"] = vuln_def["DisplayName"]

                item_name = finding.get("Method") or finding.get("Header") or finding.get("Context") or finding.get("Detail") or finding.get("name")
                short_name = None
                if item_name:
                    if isinstance(item_name, str) and ":" in item_name:
                        short_name = item_name.split(":", 1)[1].strip()
                    else:
                        short_name = str(item_name).strip()
                    finding["_item_short"] = short_name

                # attach per-item Impact/Recommendation from defs
                if item_key and item_name and isinstance(vuln_def.get(item_key, {}), dict):
                    key = short_name if short_name else item_name
                    item_def = vuln_def[item_key].get(key, {}) or {}
                    if item_def.get("Impact") and not finding.get("Impact"):
                        finding["Impact"] = item_def.get("Impact")
                    if item_def.get("Recommendation") and not finding.get("Recommendation"):
                        finding["Recommendation"] = item_def.get("Recommendation")

        for cat_name, cat_def in list(category_defs.items()):
            if (cat_def.get("TableType") == "methods") or ("method" in cat_name.lower()):
                # ensure TableType
                cat_def.setdefault("TableType", "methods")
                # ensure RiskRule is set so generic dispatcher picks it up
                cat_def.setdefault("RiskRule", "methods_options_only")
                # default severity / cvss (used if rule does not return a value)
                cat_def.setdefault("DefaultSeverity", "Medium")
                cat_def.setdefault("DefaultCVSS", "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)")
                
                # save back
                category_defs[cat_name] = cat_def

        name_to_def = {k: v or {} for k, v in category_defs.items()}
        for c in categories:
            catname = c.get("name")
            c_def = name_to_def.get(catname, {})
            # prefer explicit DisplayName from definition; fallback to existing or category name
            c["display_name"] = c_def.get("DisplayName") or c.get("display_name") or catname

        # Totals
        total_high = sum(c["high"] for c in categories)
        total_medium = sum(c["medium"] for c in categories)
        total_low = sum(c["low"] for c in categories)
        total_findings = total_high + total_medium + total_low

        # Category-level dynamic risk (uses dispatcher)
        category_stats = {}
        for cat_name, flist in findings_by_category.items():
            category_stats[cat_name] = _compute_category_risk_generic(cat_name, flist, category_defs)

        # Build table schema + rows
        table_schema: Dict[str, List[str]] = {}
        table_rows: Dict[str, List[List[Any]]] = {}
        # inside generate_interactive_html_report, while building table_schema/table_rows
        for cat_name, flist in findings_by_category.items():
            cat_def = category_defs.get(cat_name, {}) or {}

            # 1) explicit TableType standard builders (methods/headers)
            tt = cat_def.get("TableType")
            entry = _TABLETYPE_BUILDERS.get(tt)
            if entry:
                schema, builder = entry
                table_schema[cat_name] = schema
                table_rows[cat_name] = builder(flist)
                continue

            # 2) category wants a custom column layout (recommended)
            if cat_def.get("TableColumns"):
                # build schema from TableColumns
                schema = cat_def.get("TableColumns")
                col_map = _make_col_map_from_def(cat_def)  # returns list of (name, candidates)
                # create rows using generic builder
                table_schema[cat_name] = schema
                table_rows[cat_name] = _rows_generic(flist, col_map)
                continue

            # 3) fallback heuristics (existing logic)
            is_methods_like = any(
                (f.get("Method") or f.get("_item_short") or "").upper() in ("OPTIONS","PUT","DELETE","TRACE","DEBUG")
                for f in flist
            )
            if is_methods_like:
                table_schema[cat_name] = ["Method", "Status"]
                table_rows[cat_name] = _rows_for_methods(flist)
            else:
                table_schema[cat_name] = ["Header", "Status", "Current Value"]
                table_rows[cat_name] = _rows_for_headers(flist)

        # Render template
        env = Environment(extensions=["jinja2.ext.do"], autoescape=select_autoescape(["html", "xml"]), undefined=Undefined)
        tmpl = env.from_string(REPORT_TEMPLATE)
        page_style = _page_style_for_a4(force_a4)
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
            category_stats=category_stats,
            table_schema=table_schema,
            table_rows=table_rows,
            page_style=page_style
        )

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


def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """Legacy/backwards-compatible entrypoint."""
    return generate_interactive_html_report(findings, summary, filename, target_url)