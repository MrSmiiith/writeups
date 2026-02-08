import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import textwrap

BG = '#1e1e2e'
RED = '#f38ba8'
GREEN = '#a6e3a1'
BLUE = '#89b4fa'
YELLOW = '#f9e2af'
ORANGE = '#fab387'
TEXT = '#cdd6f4'
SURFACE = '#313244'
MAUVE = '#cba6f7'

def save(fig, name):
    plt.savefig(f'{name}', dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'  [+] {name}')

# ============================================================
# 01 - Challenge Overview
# ============================================================
fig, ax = plt.subplots(figsize=(14, 8))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.95, 'DOMAIN REGISTRAR - Challenge Overview', fontsize=22, fontweight='bold',
        color=ORANGE, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

info = [
    ('Platform', 'Pragyan CTF 2026'),
    ('Category', 'Web Exploitation'),
    ('Points', '500 (Maximum)'),
    ('URL', 'https://domain-registrar.ctf.prgy.in/'),
    ('Description', '"This website looks like a good place to'),
    ('', ' get a domain for my homelab, but this'),
    ('', ' bloody KYC..."'),
]

y = 0.80
for label, val in info:
    if label:
        ax.text(0.08, y, f'{label}:', fontsize=14, color=MAUVE, fontfamily='monospace',
                fontweight='bold', transform=ax.transAxes)
    ax.text(0.35, y, val, fontsize=14, color=TEXT if label else YELLOW,
            fontfamily='monospace', transform=ax.transAxes)
    y -= 0.07

# Site structure box
ax.add_patch(mpatches.FancyBboxPatch((0.05, 0.02), 0.9, 0.30,
    boxstyle="round,pad=0.02", facecolor=SURFACE, edgecolor=BLUE, linewidth=2,
    transform=ax.transAxes))

ax.text(0.5, 0.28, 'Discovered Endpoints', fontsize=14, fontweight='bold',
        color=BLUE, ha='center', fontfamily='monospace', transform=ax.transAxes)

endpoints = [
    ('index.html', 'Main page - domain listing', GREEN),
    ('avlbl.php?action=get_domains', 'API - returns domain JSON', GREEN),
    ('avlbl.php?list=X', 'Always returns "sus"', RED),
    ('kyc.php', 'POST - file upload endpoint', YELLOW),
    ('kyc.html / checkout.html', 'KYC form / order status', GREEN),
    ('nginx.conf', 'EXPOSED CONFIG = FLAG!', RED),
]

y = 0.22
for ep, desc, color in endpoints:
    ax.text(0.10, y, f'  {ep}', fontsize=11, color=color, fontfamily='monospace',
            transform=ax.transAxes)
    ax.text(0.58, y, desc, fontsize=11, color=TEXT, fontfamily='monospace',
            transform=ax.transAxes)
    y -= 0.04

save(fig, '01_challenge_overview.png')

# ============================================================
# 02 - The Rabbit Holes
# ============================================================
fig, ax = plt.subplots(figsize=(14, 9))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.96, 'The Rabbit Holes (aka Pain)', fontsize=22, fontweight='bold',
        color=RED, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

holes = [
    ('1. avlbl.php?list= Parameter', [
        '> Every string value returns "sus"',
        '> Array bypass list[]= returns empty',
        '> Tried: LFI, SQLi, PHP wrappers, HPP',
        '> Verdict: COMPLETE RED HERRING',
    ], RED),
    ('2. KYC File Upload (kyc.php)', [
        '> Accepts ANY file type (PHP, SVG, PHAR...)',
        '> Returns random 6-char reference ID',
        '> Files stored outside web root',
        '> No server-side image processing',
        '> Verdict: DEAD END',
    ], RED),
    ('3. Checkout XSS', [
        '> DOM XSS via msg parameter (innerHTML)',
        '> No admin bot to exploit',
        '> Verdict: DISTRACTION',
    ], RED),
]

y = 0.87
for title, items, color in holes:
    ax.text(0.05, y, title, fontsize=14, fontweight='bold', color=color,
            fontfamily='monospace', transform=ax.transAxes)
    y -= 0.05
    for item in items:
        ax.text(0.08, y, item, fontsize=11, color=TEXT if 'Verdict' not in item else ORANGE,
                fontfamily='monospace', transform=ax.transAxes)
        y -= 0.04
    y -= 0.03

# Time wasted counter
ax.add_patch(mpatches.FancyBboxPatch((0.15, 0.02), 0.7, 0.12,
    boxstyle="round,pad=0.02", facecolor='#45475a', edgecolor=RED, linewidth=3,
    transform=ax.transAxes))
ax.text(0.5, 0.09, 'TIME WASTED ON RABBIT HOLES: ~45 minutes', fontsize=16,
        fontweight='bold', color=RED, ha='center', fontfamily='monospace', transform=ax.transAxes)
ax.text(0.5, 0.04, 'TIME TO FIND nginx.conf: ~2 seconds', fontsize=14,
        fontweight='bold', color=GREEN, ha='center', fontfamily='monospace', transform=ax.transAxes)

save(fig, '02_rabbit_holes.png')

# ============================================================
# 03 - The "sus" Wall
# ============================================================
fig, ax = plt.subplots(figsize=(14, 7))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.95, 'The "sus" Wall - avlbl.php?list=', fontsize=20, fontweight='bold',
        color=RED, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

tests = [
    ('list=test',            'sus'),
    ('list=a',               'sus'),
    ('list=0',               'sus'),
    ('list=.',               'sus'),
    ('list=/',               'sus'),
    ('list=Available',       'sus'),
    ('list=../etc/passwd',   'sus'),
    ('list=php://filter/..', 'sus'),
    ('list[]=test',          '(empty)'),
    ('list[]=../etc/passwd', '(empty)'),
    ('(no list param)',      'List parameter missing'),
]

y = 0.84
for test, result in tests:
    color = RED if result == 'sus' else (YELLOW if 'empty' in result else BLUE)
    ax.text(0.05, y, f'$ curl "avlbl.php?{test}"', fontsize=11, color=GREEN,
            fontfamily='monospace', transform=ax.transAxes)
    ax.text(0.72, y, f'-> {result}', fontsize=11, color=color, fontweight='bold',
            fontfamily='monospace', transform=ax.transAxes)
    y -= 0.065

ax.text(0.5, 0.06, 'EVERY. SINGLE. INPUT. -> "sus"', fontsize=18, fontweight='bold',
        color=RED, ha='center', fontfamily='monospace', transform=ax.transAxes)

save(fig, '03_sus_wall.png')

# ============================================================
# 04 - The Breakthrough
# ============================================================
fig, ax = plt.subplots(figsize=(14, 7))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.95, 'The Breakthrough - Config File Exposure', fontsize=20, fontweight='bold',
        color=GREEN, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

# Terminal-style output
terminal_lines = [
    ('$ # Scanning for exposed configuration files...', YELLOW),
    ('', TEXT),
    ('$ curl https://domain-registrar.ctf.prgy.in/nginx.conf', GREEN),
    ('', TEXT),
    ('HTTP/2 200 OK', BLUE),
    ('Content-Type: text/plain', BLUE),
    ('', TEXT),
    ('"p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}"', RED),
    ('', TEXT),
    ('', TEXT),
    ('$ # WAIT... IS THAT THE FLAG?!', ORANGE),
    ('$ # IN THE NGINX CONFIG?!', ORANGE),
    ('$ # ...yes. yes it is.', GREEN),
]

y = 0.84
for line, color in terminal_lines:
    ax.text(0.05, y, line, fontsize=13, color=color, fontfamily='monospace',
            transform=ax.transAxes)
    y -= 0.06

# Big flag box
ax.add_patch(mpatches.FancyBboxPatch((0.05, 0.02), 0.9, 0.14,
    boxstyle="round,pad=0.02", facecolor=SURFACE, edgecolor=GREEN, linewidth=3,
    transform=ax.transAxes))
ax.text(0.5, 0.10, 'FLAG FOUND', fontsize=16, fontweight='bold',
        color=GREEN, ha='center', fontfamily='monospace', transform=ax.transAxes)
ax.text(0.5, 0.05, 'p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}', fontsize=14,
        fontweight='bold', color=YELLOW, ha='center', fontfamily='monospace', transform=ax.transAxes)

save(fig, '04_breakthrough.png')

# ============================================================
# 05 - Flag Decode
# ============================================================
fig, ax = plt.subplots(figsize=(14, 6))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.93, 'Flag Decode - Leetspeak Breakdown', fontsize=20, fontweight='bold',
        color=ORANGE, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

ax.text(0.5, 0.78, 'p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}', fontsize=15,
        fontweight='bold', color=YELLOW, ha='center', fontfamily='monospace', transform=ax.transAxes)

mappings = [
    ('c@n',   'can',     '@->a'),
    ('nEVer', 'never',   'mixed case'),
    ('%ru$T', 'trust',   '%->t, $->s'),
    ('D0M@!nS','domains','0->o, @->a, !->i'),
    ('FR0m',  'from',    '0->o'),
    ('p0Ps',  'pops',    '0->o (GoPops!)'),
]

y = 0.63
ax.text(0.12, y, 'ENCODED', fontsize=12, fontweight='bold', color=MAUVE,
        fontfamily='monospace', transform=ax.transAxes)
ax.text(0.38, y, 'DECODED', fontsize=12, fontweight='bold', color=GREEN,
        fontfamily='monospace', transform=ax.transAxes)
ax.text(0.58, y, 'SUBSTITUTION', fontsize=12, fontweight='bold', color=BLUE,
        fontfamily='monospace', transform=ax.transAxes)
y -= 0.07

for enc, dec, sub in mappings:
    ax.text(0.12, y, enc, fontsize=13, color=YELLOW, fontfamily='monospace', transform=ax.transAxes)
    ax.text(0.30, y, '->', fontsize=13, color=TEXT, fontfamily='monospace', transform=ax.transAxes)
    ax.text(0.38, y, dec, fontsize=13, color=GREEN, fontfamily='monospace', transform=ax.transAxes)
    ax.text(0.58, y, f'({sub})', fontsize=11, color=BLUE, fontfamily='monospace', transform=ax.transAxes)
    y -= 0.065

ax.add_patch(mpatches.FancyBboxPatch((0.1, 0.03), 0.8, 0.1,
    boxstyle="round,pad=0.02", facecolor=SURFACE, edgecolor=ORANGE, linewidth=2,
    transform=ax.transAxes))
ax.text(0.5, 0.08, '"Can Never Trust Domains From Pops"', fontsize=16,
        fontweight='bold', color=ORANGE, ha='center', fontfamily='monospace',
        transform=ax.transAxes, style='italic')

save(fig, '05_flag_decode.png')

# ============================================================
# 06 - Attack Surface Map
# ============================================================
fig, ax = plt.subplots(figsize=(14, 8))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.95, 'Attack Surface Map', fontsize=20, fontweight='bold',
        color=BLUE, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

# Draw the flow
boxes = [
    (0.05, 0.72, 0.22, 0.12, 'index.html\nDomain Listing', GREEN, SURFACE),
    (0.35, 0.72, 0.22, 0.12, 'avlbl.php\nAPI Endpoint', YELLOW, SURFACE),
    (0.67, 0.72, 0.28, 0.12, 'avlbl.php?list=\nALWAYS "sus"', RED, '#45475a'),
    (0.05, 0.48, 0.22, 0.12, 'kyc.html\nUpload Form', GREEN, SURFACE),
    (0.35, 0.48, 0.22, 0.12, 'kyc.php\nFile Upload', YELLOW, SURFACE),
    (0.67, 0.48, 0.28, 0.12, 'checkout.html\nDOM XSS (unused)', RED, '#45475a'),
    (0.30, 0.15, 0.40, 0.15, 'nginx.conf\nFLAG HERE!', GREEN, '#1a4a1a'),
]

for x, y, w, h, label, ec, fc in boxes:
    ax.add_patch(mpatches.FancyBboxPatch((x, y), w, h,
        boxstyle="round,pad=0.01", facecolor=fc, edgecolor=ec, linewidth=2,
        transform=ax.transAxes))
    ax.text(x + w/2, y + h/2, label, fontsize=11, color=TEXT,
            ha='center', va='center', fontfamily='monospace', fontweight='bold',
            transform=ax.transAxes)

# Arrows
ax.annotate('', xy=(0.35, 0.78), xytext=(0.27, 0.78),
    arrowprops=dict(arrowstyle='->', color=TEXT, lw=2), transform=ax.transAxes)
ax.annotate('', xy=(0.67, 0.78), xytext=(0.57, 0.78),
    arrowprops=dict(arrowstyle='->', color=RED, lw=2), transform=ax.transAxes)
ax.annotate('', xy=(0.35, 0.54), xytext=(0.27, 0.54),
    arrowprops=dict(arrowstyle='->', color=TEXT, lw=2), transform=ax.transAxes)
ax.annotate('', xy=(0.67, 0.54), xytext=(0.57, 0.54),
    arrowprops=dict(arrowstyle='->', color=RED, lw=2), transform=ax.transAxes)

# Big arrow to flag
ax.annotate('', xy=(0.50, 0.30), xytext=(0.50, 0.45),
    arrowprops=dict(arrowstyle='->', color=GREEN, lw=4), transform=ax.transAxes)
ax.text(0.58, 0.37, 'ACTUAL\nVULN', fontsize=12, color=GREEN,
        fontweight='bold', fontfamily='monospace', transform=ax.transAxes)

# Labels
ax.text(0.78, 0.65, 'RED HERRING', fontsize=10, color=RED, fontweight='bold',
        fontfamily='monospace', ha='center', transform=ax.transAxes, rotation=-15)

save(fig, '06_attack_surface.png')

# ============================================================
# 07 - Lesson Learned
# ============================================================
fig, ax = plt.subplots(figsize=(14, 7))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.93, 'The Lesson: Enumerate Config Files FIRST', fontsize=20, fontweight='bold',
        color=GREEN, ha='center', va='top', fontfamily='monospace', transform=ax.transAxes)

checklist = [
    ('CHECK THESE BEFORE GOING DEEP:', '', ORANGE),
    ('  nginx.conf', 'FOUND THE FLAG', GREEN),
    ('  Dockerfile', 'Leaks architecture', YELLOW),
    ('  docker-compose.yml', 'Leaks services & ports', YELLOW),
    ('  .env', 'Leaks secrets/keys', YELLOW),
    ('  Makefile', 'Leaks build process', YELLOW),
    ('  .htaccess', 'Leaks access rules', YELLOW),
    ('  .git/HEAD', 'Source code leak', YELLOW),
    ('  composer.json / package.json', 'Leaks dependencies', YELLOW),
    ('  *.bak / *~ / *.swp / *.old', 'Backup source files', YELLOW),
    ('', '', TEXT),
    ('DO NOT SPEND 45 MINUTES ON', '', RED),
    ('RABBIT HOLES BEFORE CHECKING', '', RED),
    ('THESE FILES.', '', RED),
]

y = 0.83
for left, right, color in checklist:
    ax.text(0.08, y, left, fontsize=13, color=color, fontfamily='monospace',
            fontweight='bold', transform=ax.transAxes)
    if right:
        ax.text(0.60, y, f'<- {right}', fontsize=12, color=color,
                fontfamily='monospace', transform=ax.transAxes)
    y -= 0.06

save(fig, '07_lesson_learned.png')

print('\n[*] All screenshots generated!')
