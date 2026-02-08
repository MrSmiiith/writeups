import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

BG = '#1e1e2e'
GREEN = '#a6e3a1'
YELLOW = '#f9e2af'
ORANGE = '#fab387'
TEXT = '#cdd6f4'
RED = '#f38ba8'
BLUE = '#89b4fa'
SURFACE = '#313244'

fig, ax = plt.subplots(figsize=(14, 5))
ax.set_facecolor(BG)
fig.patch.set_facecolor(BG)
ax.axis('off')

lines = [
    ('$ curl -s https://domain-registrar.ctf.prgy.in/nginx.conf', GREEN),
    ('', TEXT),
    ('"p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}"', RED),
    ('', TEXT),
    ('$', GREEN),
]

y = 0.88
for line, color in lines:
    ax.text(0.03, y, line, fontsize=16, color=color, fontfamily='monospace',
            fontweight='bold', transform=ax.transAxes)
    y -= 0.12

# Title bar
ax.add_patch(mpatches.FancyBboxPatch((-0.01, 0.92), 1.02, 0.09,
    boxstyle="square,pad=0", facecolor='#45475a', edgecolor='#585b70',
    linewidth=1, transform=ax.transAxes))
ax.text(0.5, 0.96, 'smothy@kali:~/CTF/pragyan/domain-registrar', fontsize=11,
        color=TEXT, ha='center', fontfamily='monospace', transform=ax.transAxes)

plt.savefig('nginx_conf_flag.png', dpi=150, bbox_inches='tight', facecolor=BG)
plt.close()
print('[+] nginx_conf_flag.png')
