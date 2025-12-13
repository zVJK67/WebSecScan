# export_findings.py
"""
Export Findings Module

Exports security scan findings to HTML, JSON, and PDF formats.
Generates interactive HTML reports with client-side export functionality.
"""
'''
import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style

# dependency for templating
from jinja2 import Template


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
# Embedded Jinja2 HTML template (fixed: removed stray loop references)
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
    }
    .left-summary { width: 480px; min-width:300px; }
    .right-summary { flex:1; }

    .stat-cards {
      display:flex;
      gap:12px;
      margin-bottom:14px;
    }
    .card {
      flex:1;
      background:linear-gradient(180deg,#fff 0,#fffaf8 100%);
      border-radius:8px;
      padding:12px;
      border:1px solid #e7eefc;
      text-align:center;
    }
    .card .num { font-size:22px; font-weight:800; color:#243140; }
    .card .label { font-size:12px; color:#6b7280; margin-top:6px; text-transform:uppercase; letter-spacing:0.6px; }

    /* Table summary */
    table.summary-table { width:100%; border-collapse:collapse; margin-top:10px; background:#F9F8F6}
    table.summary-table th, table.summary-table td {
      padding:10px 8px; text-align:center; border-bottom:1px solid #CBCBCB;
      font-size:13px;
    }
    table.summary-table th { background:#11224E; color:#BADFDB; font-weight:700; font-size:12px; text-transform:uppercase; }
    table.summary-table tr:hover td { background:#EFE9E3; }

    /* Chart container */
    .chart-wrapper {
      background: #fffaf8;
      border-radius:8px;
      padding:16px;
      border:1px solid #e0e0e0;
      display:flex;
      gap:12px;
      align-items:center;
      justify-content:center;
    }
    #categoryChart { width:280px; height:280px; }

    /* Details */
    .details { padding: 24px 32px 40px; }
    .details h2 { font-size:22px; color:#4A70A9; font-weight:800; border-bottom:3px solid #eef3ff; padding-bottom:10px; margin-bottom:18px; }

    .category-section {
      margin-bottom:24px;
      background: white;
      border-radius:8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    
    /* Colored left border for severity */
    .category-section.risk-high { border-left: 6px solid #dc3545; }
    .category-section.risk-medium { border-left: 6px solid #fd7e14; }
    .category-section.risk-low { border-left: 6px solid #28a745; }
    
    .vuln-header {
      background: #f8f9fa;
      padding: 16px 20px;
      border-bottom: 2px solid #e9ecef;
    }
    .vuln-title { 
      font-size: 18px; 
      font-weight: 700; 
      color: #1a1a1a;
      margin-bottom: 4px;
    }
    
    .vuln-content { padding: 20px; }
    
    .vuln-section {
      margin-bottom: 20px;
    }
    .vuln-section:last-child { margin-bottom: 0; }
    
    .section-title {
      font-size: 14px;
      font-weight: 700;
      color: #495057;
      margin-bottom: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .section-content {
      font-size: 14px;
      line-height: 1.6;
      color: #2f3a47;
    }
    
    /* Risk Rating styling */
    .risk-rating {
      display: flex;
      gap: 20px;
      align-items: center;
    }
    .risk-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .risk-label {
      font-weight: 600;
      color: #495057;
    }
    .risk-value {
      padding: 4px 12px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 13px;
    }
    .risk-value.high { background: #dc3545; color: white; }
    .risk-value.medium { background: #fd7e14; color: white; }
    .risk-value.low { background: #28a745; color: white; }
    
    /* Instances table */
    .instances-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      border: 1px solid #dee2e6;
      font-size: 13px;
    }
    .instances-table th {
      background: #f1f3f5;
      padding: 10px 12px;
      text-align: left;
      font-weight: 600;
      color: #495057;
      border-bottom: 2px solid #dee2e6;
    }
    .instances-table td {
      padding: 10px 12px;
      border-bottom: 1px solid #e9ecef;
      color: #2f3a47;
    }
    .instances-table tr:last-child td {
      border-bottom: none;
    }
    .instances-table tr:hover {
      background: #f8f9fa;
    }
    .instances-table code {
      background: #e7f1ff;
      padding: 2px 6px;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
    }
    
    /* Remediation box */
    .remediation-box {
      background: #fff3cd;
      border-left: 4px solid #ffc107;
      padding: 14px 16px;
      border-radius: 4px;
    }
    .remediation-box .section-title {
      color: #856404;
      margin-bottom: 8px;
    }
    .remediation-box .section-content {
      color: #664d03;
    }

    /* footer */
    .report-footer { background:#f8fafc; padding:14px 32px; color:#5b6b7a; font-size:13px; border-top:1px solid #eef2fb; text-align:center; }

    /* small screen fallback (not used for print) */
    @media (max-width:900px) {
      .page { width:calc(100% - 40px); }
      .summary { flex-direction:column; }
      .left-summary { width:100%; }
    }

    /* Print friendly / WeasyPrint */
    @page { size: A4 portrait; margin: 12mm 12mm 12mm 12mm; }
    @media print {
      body { background: white; }
      .page { box-shadow:none; border-radius:0; width: auto; }
      .chart-wrapper, .card, .summary-table { page-break-inside: avoid; }
      .report-header, .meta, .report-footer { -webkit-print-color-adjust: exact; }
      .no-print { display:none !important; }
    }

    /* small helper link style used by chart click target */
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
              <td style="font-weight:700; color:#452829">{{ c.name }}</td>
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
        <div style="text-align:center; margin-bottom:12px;">
          <div style="font-size:16px; font-weight:700; color:#4A70A9; margin-bottom:4px;">Vulnerability Categories Chart</div>
        </div>
        <div class="chart-wrapper" role="img" aria-label="Vulnerability categories chart">
          <canvas id="categoryChart" aria-hidden="false"></canvas>
        </div>
        <div style="margin-top:12px;font-size:12px;color:#5b6b7a;text-align:center;font-weight:600;">
          Click a slice to jump to that details section.
        </div>
      </div>
    </section>

    <!-- DETAILED FINDINGS -->
    <section class="details" id="details">
      <h2>Detailed Findings</h2>

      {% for c in categories %}
        {% set cat_name = c.name %}
        {% set findings = findings_by_category.get(cat_name, []) %}
        
        {# Determine category risk level - use highest severity from its findings #}
        {% set risk_class = 'risk-low' %}
        {% if c.high > 0 %}
          {% set risk_class = 'risk-high' %}
        {% elif c.medium > 0 %}
          {% set risk_class = 'risk-medium' %}
        {% endif %}
        
        <a id="anchor-{{ loop.index0 }}" class="anchor" aria-hidden="true"></a>
        <div class="category-section {{ risk_class }}" data-category="{{ cat_name|e }}">
          
          <!-- Vulnerability Header -->
          <div class="vuln-header">
            <div class="vuln-title">{{ cat_name }}</div>
          </div>
          
          <div class="vuln-content">
            {% if findings %}
              {# Get first finding for description (assuming all findings in category share same description) #}
              {% set first_finding = findings[0] %}
              
              <!-- Description Section -->
              <div class="vuln-section">
                <div class="section-title">Description:</div>
                <div class="section-content">
                  {{ first_finding.Description or first_finding.get('Description', 'No description provided.') }}
                </div>
              </div>
              
              <!-- Risk Rating Section -->
              <div class="vuln-section">
                <div class="section-title">Risk Rating:</div>
                <div class="risk-rating">
                  <div class="risk-item">
                    <span class="risk-label">Severity:</span>
                    {% if c.high > 0 %}
                      <span class="risk-value high">High</span>
                    {% elif c.medium > 0 %}
                      <span class="risk-value medium">Medium</span>
                    {% else %}
                      <span class="risk-value low">Low</span>
                    {% endif %}
                  </div>
                  <div class="risk-item">
                    <span class="risk-label">CVSS:</span>
                    <span class="risk-value {% if c.high > 0 %}high{% elif c.medium > 0 %}medium{% else %}low{% endif %}">
                      {{ first_finding.CVSS or first_finding.get('CVSS', 'N/A') }}
                    </span>
                  </div>
                </div>
              </div>
              
              <!-- Instances Section -->
              <div class="vuln-section">
                <div class="section-title">Instances:</div>
                <table class="instances-table">
                  <thead>
                    <tr>
                      {% if findings[0].URL or findings[0].get('URL') %}
                        <th>Page Affected</th>
                      {% endif %}
                      {% if findings[0].Status or findings[0].get('Status') %}
                        <th>Status</th>
                      {% endif %}
                      {% if findings[0].Context or findings[0].get('Context') %}
                        <th>Context</th>
                      {% endif %}
                      {% if findings[0].Detail or findings[0].get('Detail') %}
                        <th>Details</th>
                      {% endif %}
                      {# Fallback if no standard fields #}
                      {% if not (findings[0].URL or findings[0].Status or findings[0].Context or findings[0].Detail) %}
                        <th>Finding Details</th>
                      {% endif %}
                    </tr>
                  </thead>
                  <tbody>
                    {% for f in findings %}
                      <tr>
                        {% if f.URL or f.get('URL') %}
                          <td><code>{{ f.URL or f.get('URL', 'N/A') }}</code></td>
                        {% endif %}
                        {% if f.Status or f.get('Status') %}
                          <td>{{ f.Status or f.get('Status', 'N/A') }}</td>
                        {% endif %}
                        {% if f.Context or f.get('Context') %}
                          <td>{{ f.Context or f.get('Context', 'N/A') }}</td>
                        {% endif %}
                        {% if f.Detail or f.get('Detail') %}
                          <td>
                            {% if f.Detail is string %}
                              {{ f.Detail }}
                            {% else %}
                              {{ f.Detail|tojson }}
                            {% endif %}
                          </td>
                        {% endif %}
                        {# Fallback row #}
                        {% if not (f.URL or f.Status or f.Context or f.Detail) %}
                          <td>{{ f.Description or f.get('Description', 'Finding recorded') }}</td>
                        {% endif %}
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
              
              <!-- Impact/Consequence Section -->
              {% if first_finding.Impact or first_finding.get('Impact') %}
              <div class="vuln-section">
                <div class="section-title">Impact/Consequence:</div>
                <div class="section-content">
                  {{ first_finding.Impact or first_finding.get('Impact', 'Impact information not available.') }}
                </div>
              </div>
              {% endif %}
              
              <!-- Remediation Section -->
              {% if first_finding.Recommendation or first_finding.get('Recommendation') %}
              <div class="vuln-section">
                <div class="remediation-box">
                  <div class="section-title">Remediation:</div>
                  <div class="section-content">
                    {{ first_finding.Recommendation or first_finding.get('Recommendation') }}
                  </div>
                </div>
              </div>
              {% endif %}
              
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

  <!-- Inline script to build Chart.js chart and wire click -> scroll -->
  <script>
    (function(){
      // Build category arrays from Jinja-provided "categories"
      const categories = [
        {% for c in categories %}
          { name: {{ c.name|tojson }}, high: {{ c.high|int }}, medium: {{ c.medium|int }}, low: {{ c.low|int }} }{% if not loop.last %},{% endif %}
        {% endfor %}
      ];

      // Chart values and labels
      const labels = categories.map(c => c.name);
      const values = categories.map(c => (c.high + c.medium + c.low));
      const colors = labels.map((_, i) => {
        // simple deterministic palette
        const palette = [
          '#FF6B6B','#FF9F43','#FFD43B','#6BCB77','#4D96FF','#845EC2','#00C9A7','#FF9671'
        ];
        return palette[i % palette.length];
      });

      const ctx = document.getElementById('categoryChart').getContext('2d');
      const categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors,
            borderWidth: 0.5,
            hoverOffset: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { boxWidth:12, padding:8 } },
            tooltip: { callbacks: { label: (ctx)=> `${ctx.label}: ${ctx.raw}` } }
          },
          onClick(evt, activeEls) {
            // get clicked index if any and scroll to that category
            const points = categoryChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
            if (!points.length) return;
            const idx = points[0].index;
            const anchorId = 'anchor-' + idx;
            const el = document.getElementById(anchorId);
            if (el) {
              el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
              // fallback: find first matching category section by data-category
              const catName = labels[idx];
              const sec = document.querySelector(`[data-category="${catName}"]`);
              if (sec) sec.scrollIntoView({ behavior: 'smooth', block:'start' });
            }
          }
        }
      });

      // Improve keyboard accessibility: pressing Enter on chart wrapper focuses first category
      const chartWrapper = document.querySelector('.chart-wrapper');
      if (chartWrapper) {
        chartWrapper.setAttribute('tabindex', '0');
        chartWrapper.addEventListener('keydown', (e)=>{
          if (e.key === 'Enter' || e.key === ' ') {
            // go to details top
            const details = document.getElementById('details');
            if (details) details.scrollIntoView({behavior:'smooth'});
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


def generate_interactive_html_report(findings: List[Dict[str, Any]],
                                    summary: Dict[str, Dict[str, int]],
                                    filename: str = "security_scan_report.html",
                                    target_url: str = None) -> bool:
    """
    Generate an interactive HTML report using the embedded Jinja2 template.

    Notes:
      - The template uses Chart.js for interactive charts in the browser.
      - For server-side PDF generation with WeasyPrint, Chart.js won't execute on the server.
        If you need faithful server PDFs with charts, generate a PNG chart on the Python side
        (e.g., matplotlib) and replace the chart area with an <img src="data:image/png;base64,...">.
    """
    try:
        # Ensure summary/findings are in expected shapes
        categories, findings_by_category = _prepare_report_data(findings, summary)

        # Totals
        total_high = sum(c["high"] for c in categories)
        total_medium = sum(c["medium"] for c in categories)
        total_low = sum(c["low"] for c in categories)
        total_findings = total_high + total_medium + total_low

        # Render the template
        tmpl = Template(REPORT_TEMPLATE)
        rendered = tmpl.render(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            categories=categories,
            findings_by_category=findings_by_category
        )

        # Write file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(rendered)

        print(Fore.GREEN + f"✅ Interactive HTML report generated: {filename}" + Style.RESET_ALL)
        print(Fore.CYAN + f"   Open the file in a browser to view and export the report." + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to generate interactive HTML: {e}" + Style.RESET_ALL)
        return False


# Legacy function for backward compatibility
def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """Legacy function - redirects to interactive HTML generation."""
    return generate_interactive_html_report(findings, summary, filename, target_url)
'''

from test3 import VULNERABILITY_DEFINITIONS
sample_f = {
    "Category": "Server Info",
    "Header": "Server Header Exposed",
    "CurrentValue": "server: gunicorn/19.9.0",
    "Severity": "Low"
}

def _rows_for_headers(flist):
    """Return rows for header-style table: [Header, Status, CurrentValue, finding]"""
    rows = []
    for f in flist:
        header = f.get("Header") or f.get("Context") or f.get("Detail") or f.get("_item_short") or ""
        status = f.get("Status") or f.get("state") or "Unsafe"
        cur = (f.get("CurrentValue") or f.get("Current Value") or f.get("Value") or f.get("Detail") or f.get("detail"))
        rows.append([header, status, cur, f])
    return rows

def enrich_finding_with_details(finding: dict) -> dict:
    """
    Enrich a finding dictionary with detailed information from the definitions database.

    - Safely reads CVSS (supports either 'CVSS' or 'DefaultCVSS' in definitions).
    - Supports per-item detail blocks named 'ItemDetails', 'HeaderDetails' or 'MethodDetails'.
    - Does not overwrite fields that are already present in the finding.
    """
    category = finding.get("Category", "") or ""

    # try exact match first
    vuln_def = VULNERABILITY_DEFINITIONS.get(category)

    # if no exact match, try best-effort substring matching
    if not vuln_def:
        for def_category, details in VULNERABILITY_DEFINITIONS.items():
            if category and (category.lower() in def_category.lower() or def_category.lower() in category.lower()):
                vuln_def = details
                break

    # fallback to a minimal definition if nothing found
    if not vuln_def:
        vuln_def = {
            "Description": finding.get("Description", "Security misconfiguration detected."),
            "CVSS": finding.get("CVSS") or "N/A",
            "Impact": "This configuration may pose a security risk to the application.",
            "Recommendation": finding.get("Recommendation", "Review and remediate this security issue.")
        }

    # start with a shallow copy so we don't mutate original input
    enriched = finding.copy()

    # Description: prefer finding value, otherwise use vuln_def Description (if present)
    if not enriched.get("Description"):
        enriched["Description"] = vuln_def.get("Description", "")

    # CVSS: check multiple possible keys in the definitions, then fall back to any finding value, then 'N/A'
    enriched_cvss = enriched.get("CVSS") or vuln_def.get("CVSS") or vuln_def.get("DefaultCVSS") or "N/A"
    enriched["CVSS"] = enriched_cvss

    # Determine which per-item details map to use (support multiple legacy names)
    per_item_keys = []
    for key_name in ("ItemDetails", "HeaderDetails", "MethodDetails"):
        if isinstance(vuln_def.get(key_name), dict):
            per_item_keys.append(key_name)

    # Normalize item identifier for lookup (e.g., "HTTP Method: OPTIONS" -> "OPTIONS")
    item_name = (
        finding.get("Header")
        or finding.get("Method")
        or finding.get("Context")
        or finding.get("Detail")
        or finding.get("name")
        or ""
    )
    short_name = ""
    if item_name:
        try:
            s = str(item_name).strip()
            if ":" in s:
                s = s.split(":", 1)[1].strip()
            short_name = s
        except Exception:
            short_name = str(item_name)

    # If we have per-item detail maps, try to attach Impact/Recommendation for the item
    attached = False
    for key_name in per_item_keys:
        item_map = vuln_def.get(key_name, {}) or {}
        # prefer short_name lookup, fallback to raw item_name
        lookup_key = short_name if short_name else item_name
        # some maps may use uppercase keys (e.g., "OPTIONS") - try both
        candidates = [lookup_key, lookup_key.upper(), lookup_key.lower()]
        item_def = {}
        for k in candidates:
            if k in item_map:
                item_def = item_map[k] or {}
                break

        if item_def:
            # Impact
            if item_def.get("Impact") and not enriched.get("Impact"):
                enriched["Impact"] = item_def.get("Impact")
            # Recommendation
            if item_def.get("Recommendation") and not enriched.get("Recommendation"):
                enriched["Recommendation"] = item_def.get("Recommendation")
            attached = True
            break

    # If nothing attached above, fall back to category-level Impact/Recommendation if finding lacks them
    if not attached:
        if not enriched.get("Impact"):
            enriched["Impact"] = vuln_def.get("Impact", "")
        if not enriched.get("Recommendation"):
            # support both 'Recommendation' and 'Recommendations' variants (just in case)
            enriched["Recommendation"] = vuln_def.get("Recommendation") or vuln_def.get("Recommendations") or ""

    return enriched

# simulate row builder
rows = _rows_for_headers([sample_f])
print("rows:", rows)
print("_item_short:", sample_f.get("_item_short"))
# then run enrichment (if you have enrich_finding_with_details loaded)
en = enrich_finding_with_details(sample_f)
print("Impact:", en.get("Impact"))
print("Recommendation:", en.get("Recommendation"))
