from __future__ import annotations

from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'CyberVaultX_Final_Project_Report.pdf'

FONT_REG = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
FONT_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
pdfmetrics.registerFont(TTFont('DejaVuSans', FONT_REG))
pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', FONT_BOLD))

styles = getSampleStyleSheet()
styles.add(ParagraphStyle('TitleX', parent=styles['Title'], fontName='DejaVuSans-Bold', fontSize=25, leading=31, textColor=colors.HexColor('#102033'), spaceAfter=14))
styles.add(ParagraphStyle('SubtitleX', parent=styles['Normal'], fontName='DejaVuSans', fontSize=11, leading=16, textColor=colors.HexColor('#52616f'), spaceAfter=12))
styles.add(ParagraphStyle('H1X', parent=styles['Heading1'], fontName='DejaVuSans-Bold', fontSize=16, leading=20, textColor=colors.HexColor('#173b5f'), spaceBefore=12, spaceAfter=7))
styles.add(ParagraphStyle('H2X', parent=styles['Heading2'], fontName='DejaVuSans-Bold', fontSize=12.5, leading=16, textColor=colors.HexColor('#185d7a'), spaceBefore=8, spaceAfter=4))
styles.add(ParagraphStyle('BodyX', parent=styles['BodyText'], fontName='DejaVuSans', fontSize=9.5, leading=14, textColor=colors.HexColor('#1d2939'), spaceAfter=6))
styles.add(ParagraphStyle('SmallX', parent=styles['BodyText'], fontName='DejaVuSans', fontSize=8.3, leading=11, textColor=colors.HexColor('#475467')))
styles.add(ParagraphStyle('CodeX', parent=styles['BodyText'], fontName='DejaVuSans', fontSize=8, leading=11, textColor=colors.HexColor('#1d2939'), backColor=colors.HexColor('#f2f4f7'), borderPadding=5, spaceBefore=4, spaceAfter=6))


def header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(colors.HexColor('#d0d5dd'))
    canvas.line(1.5*cm, h-1.25*cm, w-1.5*cm, h-1.25*cm)
    canvas.setFont('DejaVuSans', 8)
    canvas.setFillColor(colors.HexColor('#667085'))
    canvas.drawString(1.5*cm, h-1.0*cm, 'CyberVault X - Final Project Report')
    canvas.drawRightString(w-1.5*cm, 1.0*cm, f'Page {doc.page}')
    canvas.restoreState()


def p(text, style='BodyX'):
    return Paragraph(text, styles[style])


def table(data, widths=None):
    t = Table(data, colWidths=widths, hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#173b5f')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'DejaVuSans-Bold'),
        ('FONTNAME', (0,1), (-1,-1), 'DejaVuSans'),
        ('FONTSIZE', (0,0), (-1,-1), 8.4),
        ('LEADING', (0,0), (-1,-1), 11),
        ('GRID', (0,0), (-1,-1), 0.35, colors.HexColor('#d0d5dd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    return t

story = []
story.append(Spacer(1, 1.0*cm))
story.append(p('CyberVault X', 'TitleX'))
story.append(p('Secure Password Manager with End-to-End Encryption', 'SubtitleX'))
story.append(p('<b>Version:</b> 5.7.2 Strict Final Review<br/><b>Course:</b> CET334 - Cryptographic Algorithms & Protocols<br/><b>Project:</b> Project 4 - Secure Password Manager<br/><b>Delivery:</b> working desktop application, code, tests, documentation, presentation, and live demo.', 'BodyX'))
story.append(Spacer(1, 0.45*cm))
story.append(table([
    ['Core Requirement', 'Implementation'],
    ['Encrypted Password Vault', 'AES-GCM field encryption before SQLite storage.'],
    ['Master Password Protection', 'PBKDF2-SHA256 with password policy and unlock throttling.'],
    ['Password Generation', 'Configurable generator with entropy feedback.'],
    ['Breach Detection', 'Offline SHA1 breach hash list for local checks.'],
    ['Strength Analysis', 'Weak, reused, breached, stale, and metadata risk scoring.'],
], [5.2*cm, 10.4*cm]))
story.append(PageBreak())

sections = [
    ('1. Executive Summary', 'CyberVault X is a local-first password manager designed to protect user credentials using end-to-end encryption, master-password protection, password generation, breach checking, and security posture analysis. It satisfies the original academic requirements and adds a professional product layer: AI Guardian, Security Proof Center, encrypted backups, tamper-evident audit logs, privacy-safe reports, and report-package verification.'),
    ('2. Problem Statement', 'Users often reuse weak passwords across many services. When one service is breached, attackers can use credential stuffing to compromise other accounts. CyberVault X reduces this risk by storing credentials safely, generating strong passwords, warning about weak/reused/breached passwords, and guiding the user through remediation.'),
    ('3. Project Objectives', 'The project objectives are: build an encrypted vault, protect it with a master password, use AES-GCM for authenticated encryption, provide a strong password generator, perform offline breach detection, generate safe reports, and provide proof screens that demonstrate the security controls during the live demo.'),
]
for title, body in sections:
    story.append(p(title, 'H1X'))
    story.append(p(body, 'BodyX'))

story.append(p('4. Tools and Technologies', 'H1X'))
story.append(table([
    ['Area', 'Technology'],
    ['Language', 'Python 3.11+'],
    ['Desktop GUI', 'Tkinter, chosen as a lightweight built-in alternative to PyQt5'],
    ['Encryption', 'PyCryptodome AES-GCM'],
    ['Key Derivation', 'PBKDF2-SHA256'],
    ['Storage', 'SQLite'],
    ['Testing', 'pytest / unittest'],
    ['Packaging', 'PyInstaller'],
], [5*cm, 11*cm]))
story.append(p('GUI note: the original idea suggested PyQt5. This implementation uses Tkinter to keep the project portable while preserving the same functional and security objectives.', 'SmallX'))

story.append(p('5. Architecture', 'H1X'))
story.append(p('CyberVault X uses a layered architecture: UI layer, manager/orchestration layer, service layer, cryptographic layer, database layer, and automated testing layer. This separation keeps the cryptographic logic independent from the interface and makes future UI migration possible.', 'BodyX'))
story.append(table([
    ['Layer', 'Responsibility'],
    ['UI', 'Desktop screens, dialogs, workflow controls, presentation mode.'],
    ['Manager', 'Vault actions, authentication, settings, and service coordination.'],
    ['Services', 'Backup, reporting, AI Guardian, proof checks, and product intelligence.'],
    ['Crypto', 'AES-GCM, backup encryption, master verification, passphrase policy.'],
    ['Database', 'SQLite schema, migrations, metadata, credentials, history, audit logs.'],
], [4.2*cm, 11.8*cm]))
story.append(PageBreak())

story.append(p('6. Cryptographic Design', 'H1X'))
for subtitle, body in [
    ('Master Password', 'The master password is never stored directly. PBKDF2-SHA256 derives cryptographic material from the password and a random salt.'),
    ('AES-GCM Field Encryption', 'Sensitive credential fields are encrypted before database storage. Each field is stored as a nonce/cipher pair and authenticated during decryption.'),
    ('Additional Authenticated Data', 'AAD binds encrypted data to the credential id and field name, reducing ciphertext-swapping risks between fields or records.'),
    ('Encrypted Backup', 'Backups use a dedicated encrypted envelope format. Restore preview and rollback protect the active vault from partial import failures.'),
]:
    story.append(p(subtitle, 'H2X'))
    story.append(p(body, 'BodyX'))

story.append(p('7. Main Features', 'H1X'))
story.append(table([
    ['Feature', 'Value'],
    ['Encrypted Vault', 'Add, edit, delete, restore, and search credentials while keeping sensitive fields encrypted at rest.'],
    ['Security Center', 'Detect weak, reused, breached, stale, and metadata-incomplete credentials.'],
    ['AI Guardian', 'Local deterministic advisor that turns findings into prioritized actions and attacker-view explanations.'],
    ['Security Proof Center', 'Verifies encrypted schema, AAD posture, audit chain, report package, and backup preview.'],
    ['Tamper-Evident Audit', 'Activity events are linked with hashes to detect modification, deletion, or reordering.'],
    ['Privacy-Safe Reports', 'Exports executive evidence without raw passwords and with manifest hashes.'],
], [4.4*cm, 11.6*cm]))
story.append(PageBreak())

story.append(p('8. Database Design', 'H1X'))
story.append(p('The SQLite database contains app metadata, encrypted credentials, encrypted credential history, tamper-evident activity logs, and schema migration tracking. The schema avoids plaintext password columns and supports future migrations.', 'BodyX'))
story.append(p('9. Testing and Validation', 'H1X'))
story.append(p('Automated tests cover encryption, AAD protections, backup roundtrip, backup rollback, report manifest verification, AI Guardian redaction, security scoring, and audit-chain behavior.', 'BodyX'))
story.append(p('Recommended commands:', 'BodyX'))
story.append(p('python -m pytest -q tests<br/>python tools/release_preflight.py<br/>build_release.bat', 'CodeX'))

story.append(p('10. Live Demo Scenario', 'H1X'))
story.append(p('Launch the application, create/unlock a vault, load the Assessment Dataset, explain the Dashboard score, review Security Center findings, generate an AI Guardian plan, replace a weak password, open Security Proof Center, export and verify a report package, export an encrypted backup, preview restore impact, and demonstrate panic lock.', 'BodyX'))

story.append(p('11. Limitations', 'H1X'))
story.append(table([
    ['Limitation', 'Professional Handling'],
    ['Breach dataset is demo-sized', 'Documented honestly; future work supports larger offline import.'],
    ['Python memory handling', 'Auto-lock and clipboard clearing reduce exposure; full zeroization is limited in Python.'],
    ['HMAC report signing', 'Strong local integrity proof; future work can add Ed25519 public verification.'],
    ['Tkinter instead of PyQt5', 'Chosen for portability; service layers can be reused in a PyQt5 interface.'],
], [5*cm, 11*cm]))

story.append(p('12. Future Improvements', 'H1X'))
story.append(p('Argon2id migration path, custom offline breach-list import wizard, Ed25519 public/private report signatures, secure-memory improvements, deeper UI component refactor, Windows screenshot automation, and optional PyQt5 interface variant.', 'BodyX'))

story.append(p('13. Conclusion', 'H1X'))
story.append(p('CyberVault X satisfies the core secure password manager requirements and extends them with professional security workflows. The project demonstrates applied cryptography, local privacy protection, secure software design, test coverage, report generation, and live-demo readiness.', 'BodyX'))

OUT.parent.mkdir(parents=True, exist_ok=True)
doc = SimpleDocTemplate(str(OUT), pagesize=A4, rightMargin=1.55*cm, leftMargin=1.55*cm, topMargin=1.75*cm, bottomMargin=1.5*cm)
doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
print(OUT)
