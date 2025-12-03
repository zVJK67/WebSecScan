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
      width: 210mm;               /* A4 width */
      margin: 0 auto;
      background: white;
      border-radius: 6px;
      overflow: hidden;
      box-shadow: 0 8px 30px rgba(15,23,42,0.12);
    }

    /* Header */
    .report-header {
      background: linear-gradient(135deg,#667eea 0%,#764ba2 100%);
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
      background:linear-gradient(180deg,#fff 0,#f7fbff 100%);
      border-radius:8px;
      padding:12px;
      border:1px solid #e7eefc;
      text-align:center;
    }
    .card .num { font-size:22px; font-weight:800; color:#243140; }
    .card .label { font-size:12px; color:#6b7280; margin-top:6px; text-transform:uppercase; letter-spacing:0.6px; }

    /* Table summary */
    table.summary-table { width:100%; border-collapse:collapse; margin-top:10px; }
    table.summary-table th, table.summary-table td {
      padding:10px 8px; text-align:left; border-bottom:1px solid #f1f6ff;
      font-size:13px;
    }
    table.summary-table th { background:#f8fbff; color:#243140; font-weight:700; font-size:12px; text-transform:uppercase; }
    table.summary-table tr:hover td { background:#fbfdff; }

    /* Chart container */
    .chart-wrapper {
      background: white;
      border-radius:8px;
      padding:12px;
      border:1px solid #eef2fb;
      display:flex;
      gap:12px;
      align-items:center;
      justify-content:center;
    }
    #categoryChart { width:260px; height:260px; }

    /* Details */
    .details { padding: 24px 32px 40px; }
    .details h2 { font-size:20px; color:#243140; border-bottom:3px solid #eef3ff; padding-bottom:10px; margin-bottom:18px; }

    .category-section {
      margin-bottom:20px;
      padding:16px;
      background: white;
      border-radius:8px;
      border:1px solid #eef5ff;
    }
    .category-title {
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      margin-bottom:12px;
    }
    .category-title .left { font-weight:700; font-size:16px; color:#243140; }
    .badge { font-size:12px; color:#3b4a5a; background:#f3f7ff; padding:6px 8px; border-radius:6px; }

    .finding-item {
      background:#fbfdff;
      border-left:4px solid #667eea;
      padding:12px;
      margin-bottom:12px;
      border-radius:6px;
    }
    .finding-header { display:flex; gap:12px; align-items:center; margin-bottom:8px; }
    .finding-number { background:#6c757d;color:white;padding:4px 10px;border-radius:999px;font-weight:700; }
    .severity-badge { padding:6px 10px;border-radius:20px;color:white;font-weight:700;font-size:12px; }
    .sev-high { background:#dc3545; }
    .sev-medium { background:#fd7e14; }
    .sev-low { background:#28a745; }

    .finding-description { color:#2f3a47; margin-bottom:8px; }
    .detail-item { font-size:13px; background:white;padding:8px;border-radius:6px;border:1px solid #eef3ff; margin-bottom:6px; }
    .detail-item code { background:#f1f6ff; padding:2px 6px; border-radius:4px; font-family:monospace; }

    .recommend { background:#fff8e6; border-left:4px solid #f59e0b; padding:10px;border-radius:6px; }

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
      /* hide interactive UI if added */
      .no-print { display:none !important; }
    }

    /* small helper link style used by chart click target */
    .anchor { display:block; padding-top:40px; margin-top:-40px; } /* offset for scroll */
  </style>
</head>
<body>
  <div class="page" role="document">
    <!-- HEADER -->
    <header class="report-header">
      <div class="report-title">🛡️ WebSecScan Security Report</div>
      <div class="report-sub">Comprehensive Security Analysis</div>
    </header>

    <!-- META -->
    <div class="meta">
      <div class="meta-item"><strong>Target:</strong> <code>{{ target_url }}</code></div>
      <div class="meta-item"><strong>Scan Time:</strong> {{ scan_time }}</div>
      <div class="meta-item"><strong>Total Issues:</strong> {{ total_findings }}</div>
      <div style="margin-left:auto;font-size:12px;color:#6b7280;">Generated by WebSecScan</div>
    </div>

    <!-- SUMMARY -->
    <section class="summary" aria-label="Executive summary">
      <div class="left-summary">
        <div class="stat-cards">
          <div class="card">
            <div class="num">{{ total_findings }}</div>
            <div class="label">Total Issues</div>
          </div>
          <div class="card">
            <div class="num" style="color:#b91c1c;">{{ total_high }}</div>
            <div class="label">High</div>
          </div>
          <div class="card">
            <div class="num" style="color:#c2410c;">{{ total_medium }}</div>
            <div class="label">Medium</div>
          </div>
          <div class="card">
            <div class="num" style="color:#0f766e;">{{ total_low }}</div>
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
              <td>{{ c.name }}</td>
              <td>{{ c.high }}</td>
              <td>{{ c.medium }}</td>
              <td>{{ c.low }}</td>
              <td>{{ (c.high|int + c.medium|int + c.low|int) }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="right-summary">
        <div class="chart-wrapper" role="img" aria-label="Vulnerability categories chart">
          <canvas id="categoryChart" aria-hidden="false" title="Click a slice to go to details"></canvas>
        </div>
        <div style="margin-top:10px;font-size:12px;color:#5b6b7a;">
          Click a slice to jump to the details section for that category.
        </div>
      </div>
    </section>

    <!-- DETAILED FINDINGS -->
    <section class="details" id="details">
      <h2>🔍 Detailed Findings</h2>

      {% for c in categories %}
        {% set cat_name = c.name %}
        <a id="anchor-{{ loop.index0 }}" class="anchor" aria-hidden="true"></a>
        <div class="category-section" data-category="{{ cat_name|e }}">
          <div class="category-title">
            <div class="left">{{ cat_name }}</div>
            <div class="badge">High: {{ c.high }} &nbsp; | &nbsp; Medium: {{ c.medium }} &nbsp; | &nbsp; Low: {{ c.low }}</div>
          </div>

          {% set findings = findings_by_category.get(cat_name, []) %}
          {% if findings %}
            {% for f in findings %}
              <article class="finding-item" role="article" aria-labelledby="f-{{ cat_name|replace(' ','-') }}-{{ loop.index }}">
                <div class="finding-header">
                  <div class="finding-number">#{{ loop.index }}</div>
                  {% set sev = (f.Severity or f.get('Severity','Low')) %}
                  <div class="severity-badge {% if sev == 'High' %}sev-high{% elif sev == 'Medium' %}sev-medium{% else %}sev-low{% endif %}">{{ sev }}</div>
                </div>

                <div id="f-{{ cat_name|replace(' ','-') }}-{{ loop.index }}" class="finding-description">
                  {{ f.Description or f.get('Description','No description provided.') }}
                </div>

                <div class="detail-item">
                  {% if f.URL %}
                    <div><strong>URL:</strong> <code>{{ f.URL }}</code></div>
                  {% endif %}
                  {% if f.Status %}
                    <div><strong>Status:</strong> {{ f.Status }}</div>
                  {% endif %}
                  {% if f.Context %}
                    <div><strong>Context:</strong> {{ f.Context }}</div>
                  {% endif %}
                  {% if f.Detail %}
                    <div><strong>Detail:</strong>
                      <pre style="white-space:pre-wrap; font-family:monospace; font-size:12px; margin-top:6px;">{{ f.Detail if f.Detail is string else (f.Detail|tojson(indent=2)) }}</pre>
                    </div>
                  {% endif %}
                </div>

                {% if f.Recommendation or f.get("Recommendation") %}
                <div class="recommend" role="note">
                  <strong>Recommendation:</strong>
                  <div style="margin-top:6px;">{{ f.Recommendation or f.get("Recommendation") }}</div>
                </div>
                {% endif %}
              </article>
            {% endfor %}
          {% else %}
            <div style="padding:10px;color:#5b6b7a;background:#fbfdff;border-radius:6px;border:1px solid #eef3ff;">
              No findings recorded for this category.
            </div>
          {% endif %}
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
