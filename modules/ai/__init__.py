import os
import sys
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from openai import OpenAI
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                 Spacer, Table, TableStyle,
                                 HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from config.settings import OPENAI_KEY, OPENAI_MODEL, REPORTS_DIR
from modules.logger import (log, get_findings,
                             get_logs, get_all_sessions,
                             DB_PATH)
import sqlite3
from datetime import datetime

load_dotenv()
client = OpenAI(api_key=OPENAI_KEY)

class AIModule:

    def __init__(self, session_id: str):
        self.session_id = session_id

    def _get_session_info(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT * FROM sessions WHERE id=?",
                  (self.session_id,))
        row  = c.fetchone()
        conn.close()
        return row

    def _build_context(self) -> dict:
        findings = get_findings(self.session_id)
        session  = self._get_session_info()

        context = {
            "session_id" : self.session_id,
            "target"     : session[2] if session else "Unknown",
            "target_type": session[3] if session else "Unknown",
            "findings"   : []
        }

        severity_count = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0,   "LOW": 0, "INFO": 0
        }

        for f in findings:
            sev = f[5]
            if sev in severity_count:
                severity_count[sev] += 1
            context["findings"].append({
                "module"     : f[3],
                "type"       : f[4],
                "severity"   : sev,
                "title"      : f[6],
                "description": f[7]
            })

        context["severity_count"] = severity_count
        return context

    def analyze_findings(self) -> dict:
        context = self._build_context()
        log(self.session_id, "AI", "Analyzing findings...")

        prompt = f"""
You are a senior penetration tester writing a professional
security assessment report.

Analyze these findings from a pentest against
{context['target']} ({context['target_type']}):

{json.dumps(context['findings'], indent=2)}

Return a JSON object with:
{{
  "risk_score": <0-100 integer>,
  "risk_level": "<Critical|High|Medium|Low>",
  "executive_summary": "<2-3 sentence executive summary>",
  "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],
  "attack_narrative": "<paragraph describing attack chain>",
  "recommendations": [
    {{"priority": "Critical", "action": "...", "detail": "..."}},
    {{"priority": "High",     "action": "...", "detail": "..."}},
    {{"priority": "Medium",   "action": "...", "detail": "..."}}
  ],
  "conclusion": "<concluding paragraph>"
}}
"""
        try:
            r = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system",
                     "content": "You are an expert penetration tester. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=2000,
                temperature=0.3
            )
            result = json.loads(
                r.choices[0].message.content
            )
            log(self.session_id, "AI",
                f"Analysis complete — Risk: {result.get('risk_level','?')} ({result.get('risk_score','?')}/100)")
            return result
        except Exception as e:
            log(self.session_id, "AI",
                f"AI analysis failed: {e}", "ERROR")
            return {
                "risk_score"       : 50,
                "risk_level"       : "Medium",
                "executive_summary": "Analysis unavailable.",
                "key_findings"     : [],
                "attack_narrative" : "",
                "recommendations"  : [],
                "conclusion"       : ""
            }

    def generate_report(self) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        context  = self._build_context()
        analysis = self.analyze_findings()
        session  = self._get_session_info()
        path     = os.path.join(REPORTS_DIR,
                                f"{self.session_id}.pdf")

        doc    = SimpleDocTemplate(
            path, pagesize=letter,
            rightMargin=0.75*inch, leftMargin=0.75*inch,
            topMargin=0.75*inch, bottomMargin=0.75*inch
        )
        styles = getSampleStyleSheet()
        story  = []

        # ── Color palette ─────────────────────────────────────────
        C_BG     = colors.HexColor('#0a0e1a')
        C_ACCENT = colors.HexColor('#00d4ff')
        C_DARK   = colors.HexColor('#141c2e')
        C_TEXT   = colors.HexColor('#e2e8f0')
        C_RED    = colors.HexColor('#ff3366')
        C_YELLOW = colors.HexColor('#ffaa00')
        C_GREEN  = colors.HexColor('#00ff88')
        C_MUTED  = colors.HexColor('#64748b')

        SEV_COLORS = {
            "CRITICAL": colors.HexColor('#ff0033'),
            "HIGH"    : colors.HexColor('#ff3366'),
            "MEDIUM"  : colors.HexColor('#ffaa00'),
            "LOW"     : colors.HexColor('#00ff88'),
            "INFO"    : colors.HexColor('#00d4ff'),
        }

        # ── Custom styles ─────────────────────────────────────────
        def S(name, **kw):
            s = ParagraphStyle(name, **kw)
            return s

        title_style = S('Title2',
            fontSize=28, textColor=C_ACCENT,
            spaceAfter=6, fontName='Helvetica-Bold',
            alignment=TA_CENTER
        )
        sub_style = S('Sub',
            fontSize=12, textColor=C_MUTED,
            spaceAfter=4, alignment=TA_CENTER
        )
        h1_style = S('H1',
            fontSize=16, textColor=C_ACCENT,
            spaceBefore=16, spaceAfter=8,
            fontName='Helvetica-Bold'
        )
        h2_style = S('H2',
            fontSize=13, textColor=C_TEXT,
            spaceBefore=12, spaceAfter=6,
            fontName='Helvetica-Bold'
        )
        body_style = S('Body2',
            fontSize=10, textColor=C_TEXT,
            spaceAfter=6, leading=16
        )
        mono_style = S('Mono',
            fontSize=9, textColor=C_ACCENT,
            fontName='Courier', spaceAfter=4
        )

        # ── Cover ─────────────────────────────────────────────────
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph("⚡ NETSTRIKE", title_style))
        story.append(Paragraph(
            "AI-Powered Penetration Testing Report",
            sub_style
        ))
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=C_ACCENT, spaceAfter=16
        ))

        # Meta table
        risk_color = SEV_COLORS.get(
            analysis.get('risk_level','Medium').upper(),
            C_YELLOW
        )
        meta_data = [
            ['Target',       context['target']],
            ['Target Type',  context['target_type'].upper()],
            ['Session ID',   self.session_id],
            ['Date',         datetime.now().strftime("%Y-%m-%d %H:%M")],
            ['Risk Level',   analysis.get('risk_level','?')],
            ['Risk Score',   f"{analysis.get('risk_score',0)}/100"],
        ]
        meta_table = Table(meta_data,
                           colWidths=[2*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), C_DARK),
            ('TEXTCOLOR',  (0,0), (0,-1), C_MUTED),
            ('TEXTCOLOR',  (1,0), (1,-1), C_TEXT),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS', (0,0), (-1,-1),
             [C_DARK, colors.HexColor('#0f1623')]),
            ('GRID', (0,0), (-1,-1), 0.5,
             colors.HexColor('#1e2d45')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3*inch))

        # ── Executive Summary ─────────────────────────────────────
        story.append(Paragraph("1. Executive Summary", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        story.append(Paragraph(
            analysis.get('executive_summary', ''),
            body_style
        ))

        # ── Risk Score Visual ─────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        score = analysis.get('risk_score', 0)
        risk_data = [[
            Paragraph("RISK SCORE", S('rs',
                fontSize=10, textColor=C_MUTED,
                alignment=TA_CENTER
            )),
            Paragraph(f"{score}/100", S('rsv',
                fontSize=24, textColor=risk_color,
                fontName='Helvetica-Bold',
                alignment=TA_CENTER
            )),
            Paragraph(
                analysis.get('risk_level','?').upper(),
                S('rl', fontSize=14, textColor=risk_color,
                  fontName='Helvetica-Bold',
                  alignment=TA_CENTER)
            )
        ]]
        risk_table = Table(risk_data,
                           colWidths=[2*inch, 2.5*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_DARK),
            ('GRID', (0,0), (-1,-1), 1,
             colors.HexColor('#1e2d45')),
            ('PADDING', (0,0), (-1,-1), 12),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(risk_table)

        # ── Findings Summary ──────────────────────────────────────
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("2. Findings Summary", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))

        sev  = context.get('severity_count', {})
        sev_data = [
            ['Severity', 'Count', 'Risk'],
            ['CRITICAL', str(sev.get('CRITICAL',0)), 'Immediate action required'],
            ['HIGH',     str(sev.get('HIGH',0)),     'Address within 24 hours'],
            ['MEDIUM',   str(sev.get('MEDIUM',0)),   'Address within 1 week'],
            ['LOW',      str(sev.get('LOW',0)),       'Address when possible'],
        ]
        sev_table = Table(sev_data,
                          colWidths=[1.5*inch, 1*inch, 4*inch])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_DARK),
            ('TEXTCOLOR',  (0,0), (-1,0), C_MUTED),
            ('TEXTCOLOR',  (0,1), (0,1), SEV_COLORS['CRITICAL']),
            ('TEXTCOLOR',  (0,2), (0,2), SEV_COLORS['HIGH']),
            ('TEXTCOLOR',  (0,3), (0,3), SEV_COLORS['MEDIUM']),
            ('TEXTCOLOR',  (0,4), (0,4), SEV_COLORS['LOW']),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 0.5,
             colors.HexColor('#1e2d45')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
             [C_DARK, colors.HexColor('#0f1623')]),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        story.append(sev_table)

        # ── Key Findings ──────────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("3. Key Findings", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        for i, finding in enumerate(
            analysis.get('key_findings', []), 1
        ):
            story.append(Paragraph(
                f"• {finding}", body_style
            ))

        # ── Attack Narrative ──────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("4. Attack Narrative", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        story.append(Paragraph(
            analysis.get('attack_narrative', ''),
            body_style
        ))

        # ── Detailed Findings ─────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "5. Detailed Technical Findings", h1_style
        ))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        for f in context['findings'][:20]:
            sev_c = SEV_COLORS.get(f['severity'], C_MUTED)
            story.append(Paragraph(
                f"[{f['severity']}] {f['title']}",
                S('fh', fontSize=11, textColor=sev_c,
                  fontName='Helvetica-Bold', spaceAfter=2)
            ))
            story.append(Paragraph(
                f"Module: {f['module']} | "
                f"Type: {f['type']}",
                S('fm', fontSize=9, textColor=C_MUTED,
                  spaceAfter=2)
            ))
            story.append(Paragraph(
                f['description'], body_style
            ))
            story.append(HRFlowable(
                width="100%", thickness=0.3,
                color=C_DARK, spaceAfter=6
            ))

        # ── Recommendations ───────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "6. Recommendations", h1_style
        ))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        for rec in analysis.get('recommendations', []):
            p = rec.get('priority', 'Medium')
            story.append(Paragraph(
                f"[{p}] {rec.get('action','')}",
                S('rh', fontSize=11,
                  textColor=SEV_COLORS.get(
                      p.upper(), C_YELLOW
                  ),
                  fontName='Helvetica-Bold', spaceAfter=2)
            ))
            story.append(Paragraph(
                rec.get('detail', ''), body_style
            ))

        # ── Conclusion ────────────────────────────────────────────
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("7. Conclusion", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=C_DARK, spaceAfter=8
        ))
        story.append(Paragraph(
            analysis.get('conclusion', ''), body_style
        ))

        # ── Footer ────────────────────────────────────────────────
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=C_ACCENT, spaceAfter=8
        ))
        story.append(Paragraph(
            f"Generated by NetStrike AI Pentest Framework | "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"For authorized testing only",
            S('footer', fontSize=9, textColor=C_MUTED,
              alignment=TA_CENTER)
        ))

        doc.build(story)
        log(self.session_id, "AI",
            f"PDF report generated → {path}")
        return path
