from __future__ import annotations

import csv
import json
import secrets
import string
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .analyzer import analyze_password, normalize_site, password_is_old
from .breach_db import breach_db_size
from .manager import Credential, VaultManager
from .ui_helpers import normalize_http_url, safe_cache_name, safe_favicon_host
from .io_utils import atomic_write_bytes
from .ui_shared import *

class VisualMixin:
    def _apply_theme(self, accent_name: str) -> None:
        self.accent = ACCENTS.get(accent_name, ACCENTS['Cyan'])
        self.accent_soft = self.accent
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        # Base surfaces
        self.style.configure('TFrame', background=PANEL_BG)
        self.style.configure('TLabelframe', background=PANEL_BG, bordercolor=BORDER, relief='flat')
        self.style.configure('TLabelframe.Label', background=PANEL_BG, foreground=TEXT, font=('Segoe UI Semibold', 11))
        self.style.configure('TLabel', background=PANEL_BG, foreground=TEXT, font=('Segoe UI', 11))
        self.style.configure('Muted.TLabel', background=PANEL_BG, foreground=SUBTEXT, font=('Segoe UI', 11))
        self.style.configure('SmallMuted.TLabel', background=PANEL_BG, foreground=MUTED, font=('Segoe UI', 9))
        self.style.configure('Section.TLabel', background=PANEL_BG, foreground=TEXT, font=('Segoe UI Semibold', 12))

        # Data views
        self.style.configure(
            'Treeview',
            background=INPUT_BG,
            fieldbackground=INPUT_BG,
            foreground=TEXT,
            rowheight=36,
            relief='flat',
            borderwidth=0,
            font=('Segoe UI', 10),
        )
        self.style.configure(
            'Treeview.Heading',
            background=PANEL_DEEP,
            foreground=TEXT,
            font=('Segoe UI Semibold', 10),
            relief='flat',
            borderwidth=0,
        )
        self.style.map('Treeview', background=[('selected', self.accent)], foreground=[('selected', APP_BG)])

        # Inputs
        for style_name in ('TEntry', 'TCombobox'):
            self.style.configure(
                style_name,
                fieldbackground=INPUT_BG,
                foreground=TEXT,
                insertcolor=TEXT,
                bordercolor=INPUT_BORDER,
                lightcolor=INPUT_BORDER,
                darkcolor=INPUT_BORDER,
                borderwidth=1,
                padding=(8, 6),
            )
        self.style.map(
            'TCombobox',
            fieldbackground=[('readonly', INPUT_BG), ('focus', INPUT_BG)],
            foreground=[('readonly', TEXT)],
            selectbackground=[('readonly', INPUT_BG)],
            selectforeground=[('readonly', TEXT)],
        )
        self.style.configure('TCheckbutton', background=PANEL_BG, foreground=TEXT, focuscolor=PANEL_BG)
        self.style.map('TCheckbutton', background=[('active', PANEL_BG)], foreground=[('active', TEXT)])
        self.style.configure('Horizontal.TScale', background=PANEL_BG, troughcolor=INPUT_BG, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)

        # Unified buttons
        button_font = ('Segoe UI Semibold', 10)
        self.style.configure('Accent.TButton', background=self.accent, foreground=APP_BG, padding=(16, 10), borderwidth=0, font=button_font)
        self.style.map('Accent.TButton', background=[('active', self.accent), ('pressed', self.accent)], foreground=[('disabled', MUTED)])
        self.style.configure('Ghost.TButton', background=SURFACE_3, foreground=TEXT, padding=(15, 10), borderwidth=0, font=button_font)
        self.style.map('Ghost.TButton', background=[('active', '#203A5F'), ('pressed', '#203A5F')], foreground=[('disabled', MUTED)])
        self.style.configure('Danger.TButton', background=DANGER, foreground='white', padding=(14, 9), borderwidth=0, font=button_font)
        self.style.map('Danger.TButton', background=[('active', '#F87171'), ('pressed', '#F87171')], foreground=[('disabled', '#FCA5A5')])
        self.style.configure('Quiet.TButton', background=PANEL_DEEP, foreground=SUBTEXT, padding=(12, 8), borderwidth=0, font=button_font)
        self.style.configure('Pill.TButton', background=SURFACE_2, foreground=TEXT, padding=(10, 6), borderwidth=0, font=('Segoe UI Semibold', 9))
        self.style.map('Pill.TButton', background=[('active', HOVER), ('pressed', HOVER)], foreground=[('active', TEXT)])
        self.style.map('Quiet.TButton', background=[('active', SURFACE_3)], foreground=[('active', TEXT)])
        self.style.configure('TNotebook', background=PANEL_BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        self.style.configure('TNotebook.Tab', background=SURFACE_2, foreground=SUBTEXT, padding=(14, 8), font=('Segoe UI Semibold', 10), borderwidth=0)
        self.style.map('TNotebook.Tab', background=[('selected', self.accent), ('active', HOVER)], foreground=[('selected', APP_BG), ('active', TEXT)])

        # Scrollbars for dialogs and long panels.  Use a custom dark style so
        # Windows/Linux do not show bright native scrollbars inside dark pages.
        self.style.configure(
            'Vertical.TScrollbar',
            gripcount=0,
            background=SURFACE_3,
            troughcolor=PANEL_DEEP,
            bordercolor=PANEL_DEEP,
            arrowcolor=MUTED,
            lightcolor=SURFACE_3,
            darkcolor=SURFACE_3,
            relief='flat',
            width=12,
        )
        self.style.map(
            'Vertical.TScrollbar',
            background=[('active', self.accent), ('pressed', self.accent)],
            arrowcolor=[('active', TEXT), ('pressed', TEXT)],
        )
        self.style.configure(
            'Horizontal.TScrollbar',
            gripcount=0,
            background=SURFACE_3,
            troughcolor=PANEL_DEEP,
            bordercolor=PANEL_DEEP,
            arrowcolor=MUTED,
            lightcolor=SURFACE_3,
            darkcolor=SURFACE_3,
            relief='flat',
            width=12,
        )

        self.option_add('*Font', ('Segoe UI', 10))
        self.option_add('*TCombobox*Listbox*Background', INPUT_BG)
        self.option_add('*TCombobox*Listbox*Foreground', TEXT)
        self.option_add('*TCombobox*Listbox*selectBackground', self.accent)
        self.option_add('*TCombobox*Listbox*selectForeground', APP_BG)
        if self.sidebar_buttons:
            self._refresh_nav_styles()
            if hasattr(self, 'health_score_canvas'):
                metric_value = self.metric_vars.get('health_score', tk.StringVar(value='N/A')).get()
                draw_score = None if metric_value == 'N/A' else int(metric_value.replace('/100', '') or 0)
                self._draw_health_score(draw_score)
                self._draw_command_center(draw_score)

    def _card(self, parent: tk.Widget, *, bg: str = CARD_BG, padx: int = 18, pady: int = 18, height: int | None = None) -> tk.Frame:
        # Soft glass card primitive.  The old UI overused hard cyan borders,
        # which made the app feel noisy and heavy.  This version keeps depth
        # but uses a subtle border and a slightly darker shell for cleaner pages.
        card = tk.Frame(parent, bg=bg, bd=0, highlightthickness=1, highlightbackground=BORDER_SOFT)
        if height:
            card.configure(height=height)
            card.pack_propagate(False)
        inner = tk.Frame(card, bg=bg, padx=padx, pady=pady)
        inner.pack(fill='both', expand=True)
        card.inner = inner  # type: ignore[attr-defined]
        return card

    def _glow_card(self, parent: tk.Widget, *, bg: str = CARD_BG, accent: str | None = None, padx: int = 18, pady: int = 18, height: int | None = None) -> tk.Frame:
        # Highlight cards should guide the eye, not draw a loud rectangle around
        # every section.  The accent is now a slim left rail instead of a full
        # hard border + top stripe.
        outer = tk.Frame(parent, bg=bg, bd=0, highlightthickness=1, highlightbackground=BORDER_SOFT)
        if height:
            outer.configure(height=height)
            outer.pack_propagate(False)
        shell = tk.Frame(outer, bg=bg)
        shell.pack(fill='both', expand=True)
        rail_color = accent or self.accent
        rail = tk.Frame(shell, bg=rail_color, width=3)
        rail.pack(side='left', fill='y')
        inner = tk.Frame(shell, bg=bg, padx=padx, pady=pady)
        inner.pack(side='left', fill='both', expand=True)
        outer.inner = inner  # type: ignore[attr-defined]
        outer.accent_rail = rail  # type: ignore[attr-defined]
        return outer

    def _mini_stat_card(self, parent: tk.Widget, title: str, variable: tk.StringVar | str, *, accent: str | None = None, subtitle: str = '', icon: str = '•') -> tk.Frame:
        card = self._glow_card(parent, bg=CARD_BG, accent=accent or self.accent, padx=14, pady=12, height=82)
        ci = card.inner
        top = tk.Frame(ci, bg=ci.cget('bg'))
        top.pack(fill='x')
        tk.Label(top, text=icon, bg=PANEL_DEEP, fg=accent or self.accent, width=3, pady=3, font=('Segoe UI Semibold', 10), highlightthickness=1, highlightbackground=BORDER_SOFT).pack(side='left')
        self._label(top, title, fg=SUBTEXT, bg=top.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(9, 0))
        if isinstance(variable, tk.StringVar):
            self._label(ci, textvariable=variable, bg=ci.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(6, 0))
        else:
            self._label(ci, variable, bg=ci.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(6, 0))
        if subtitle:
            self._label(ci, subtitle, fg=MUTED, bg=ci.cget('bg'), font=('Segoe UI', 8)).pack(anchor='w', pady=(1, 0))
        return card

    def _label(self, parent: tk.Widget, text: str = '', *, fg: str = TEXT, bg: str | None = None, font=('Segoe UI', 11), wraplength: int | None = None, justify='left', textvariable=None, **kwargs) -> tk.Label:
        label = tk.Label(parent, text=text, textvariable=textvariable, fg=fg, bg=bg or parent.cget('bg'), font=font, wraplength=wraplength, justify=justify, anchor='w', **kwargs)
        # Most labels are inside resizable cards.  Fixed wraplengths looked good
        # on the developer screen but clipped on laptop/projector resolutions.
        # Keep the requested max width while shrinking automatically with the
        # parent, so long hints and report text remain readable instead of
        # disappearing beyond the right edge.
        if wraplength:
            self._auto_wrap_label(label, max_width=int(wraplength))
        return label

    def _auto_wrap_label(self, label: tk.Label, *, max_width: int, min_width: int = 180, margin: int = 28) -> None:
        try:
            parent = label.master
        except Exception:
            return

        def _sync(_event=None) -> None:
            try:
                width = parent.winfo_width()
                if width <= 1:
                    return
                label.configure(wraplength=max(min_width, min(max_width, width - margin)))
            except Exception:
                pass

        try:
            parent.bind('<Configure>', _sync, add='+')
            label.after_idle(_sync)
        except Exception:
            pass

    def _action_bar(self, parent: tk.Widget, *, align: str = 'left') -> tk.Frame:
        """Consistent button row with a dark surface and safe wrapping space."""
        bar = tk.Frame(parent, bg=parent.cget('bg'))
        bar.pack(fill='x')
        bar._cvx_align = align  # type: ignore[attr-defined]
        return bar

    def _compact_button_text(self, text: str, *, max_chars: int = 22) -> str:
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + '…'

    def _center_window(self, window: tk.Toplevel, width: int | None = None, height: int | None = None) -> None:
        """Center a dialog after geometry is set. Safe when running under tests/headless."""
        try:
            window.update_idletasks()
            if width is None:
                width = window.winfo_width()
            if height is None:
                height = window.winfo_height()
            screen_w = window.winfo_screenwidth()
            screen_h = window.winfo_screenheight()
            x = max(0, int((screen_w - width) / 2))
            y = max(0, int((screen_h - height) / 2))
            window.geometry(f'{width}x{height}+{x}+{y}')
        except Exception:
            pass


    def _asset_path(self, name: str) -> Path:
        return Path(__file__).resolve().parent / 'assets' / name

    def _apply_window_branding(self) -> None:
        """Apply bundled icon assets when running from source or PyInstaller."""
        try:
            icon_path = self._asset_path('app_icon.png')
            if icon_path.exists():
                icon = tk.PhotoImage(file=str(icon_path))
                self._brand_images['app_icon'] = icon
                self.iconphoto(True, icon)
        except Exception:
            # Branding must never break vault startup.
            pass

    def _show_splash_screen(self) -> None:
        """Show a short non-blocking splash screen before the setup/unlock dialog."""
        try:
            splash_path = self._asset_path('splash.png')
            if not splash_path.exists():
                return
            splash = tk.Toplevel(self)
            splash.overrideredirect(True)
            splash.configure(bg=APP_BG)
            image = tk.PhotoImage(file=str(splash_path))
            self._brand_images['splash'] = image
            label = tk.Label(splash, image=image, bg=APP_BG, bd=0)
            label.pack()
            width = image.width()
            height = image.height()
            self._center_window(splash, width, height)
            splash.lift()
            self.splash_window = splash
            self.after(850, self._hide_splash_screen)
        except Exception:
            self.splash_window = None

    def _hide_splash_screen(self) -> None:
        try:
            if self.splash_window and self.splash_window.winfo_exists():
                self.splash_window.destroy()
        except Exception:
            pass
        self.splash_window = None

    def _scrollable_panel(self, parent: tk.Widget, *, bg: str, padx: int = 0, pady: int = 0) -> tuple[tk.Canvas, tk.Frame]:
        """Create a lightweight scrollable frame used by dialogs that may clip on 125%+ scaling."""
        outer = tk.Frame(parent, bg=bg)
        outer.pack(fill='both', expand=True)
        canvas = tk.Canvas(outer, bg=bg, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview, style='Vertical.TScrollbar')
        body = tk.Frame(canvas, bg=bg, padx=padx, pady=pady)
        window_id = canvas.create_window((0, 0), window=body, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        def _sync_region(_event=None) -> None:
            try:
                canvas.configure(scrollregion=canvas.bbox('all'))
            except Exception:
                pass

        def _sync_width(event) -> None:
            try:
                canvas.itemconfigure(window_id, width=event.width)
            except Exception:
                pass

        body.bind('<Configure>', _sync_region)
        canvas.bind('<Configure>', _sync_width)

        def _on_mousewheel(event) -> None:
            try:
                if getattr(event, 'num', None) == 4:
                    canvas.yview_scroll(-1, 'units')
                elif getattr(event, 'num', None) == 5:
                    canvas.yview_scroll(1, 'units')
                else:
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
            except Exception:
                pass

        canvas.bind('<MouseWheel>', _on_mousewheel)
        body.bind('<MouseWheel>', _on_mousewheel)
        canvas.bind('<Button-4>', _on_mousewheel)
        canvas.bind('<Button-5>', _on_mousewheel)
        body.bind('<Button-4>', _on_mousewheel)
        body.bind('<Button-5>', _on_mousewheel)
        return canvas, body

    def _styled_entry(self, parent: tk.Widget, variable: tk.StringVar, *, show: str = '') -> tk.Entry:
        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=INPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief='flat',
            bd=0,
            highlightthickness=1,
            highlightbackground=INPUT_BORDER,
            highlightcolor=self.accent,
            font=('Segoe UI', 11),
        )
        return entry

    def _empty_state_card(self, parent: tk.Widget, *, title: str, body: str, button_text: str | None = None, command=None) -> tk.Frame:
        card = tk.Frame(parent, bg=SURFACE_2, padx=24, pady=22, highlightthickness=1, highlightbackground=BORDER)
        icon = tk.Canvas(card, width=44, height=44, bg=card.cget('bg'), highlightthickness=0)
        icon.pack(anchor='center')
        icon.create_oval(4, 4, 40, 40, fill=PANEL_DEEP, outline=BORDER)
        icon.create_text(22, 22, text='✧', fill=self.accent, font=('Segoe UI Semibold', 16))
        self._label(card, title, bg=card.cget('bg'), font=('Segoe UI Semibold', 14), justify='center').pack(anchor='center', pady=(10, 0))
        self._label(card, body, fg=SUBTEXT, bg=card.cget('bg'), font=('Segoe UI', 11), wraplength=460, justify='center').pack(anchor='center', pady=(8, 0))
        if button_text and command:
            ttk.Button(card, text=button_text, command=command, style='Accent.TButton').pack(anchor='center', pady=(14, 0))
        return card

    def _section_header(self, parent: tk.Widget, title: str, subtitle: str = '', *, action_text: str | None = None, action_command=None) -> tk.Frame:
        """Reusable premium section heading used across dense pages."""
        row = tk.Frame(parent, bg=parent.cget('bg'))
        row.pack(fill='x', pady=(0, 12))
        left = tk.Frame(row, bg=row.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, title, bg=left.cget('bg'), font=('Segoe UI Semibold', 13)).pack(anchor='w')
        if subtitle:
            self._label(left, subtitle, fg=MUTED, bg=left.cget('bg'), font=('Segoe UI', 9), wraplength=760).pack(anchor='w', pady=(3, 0))
        if action_text and action_command:
            self._top_action_button(row, action_text, action_command, kind='accent').pack(side='right')
        return row

    def _status_pill(self, parent: tk.Widget, text: str, *, color: str | None = None) -> tk.Label:
        # Compact chip with less visual weight than the older square badges.
        chip_bg = color or SURFACE_2
        chip_fg = APP_BG if color else SUBTEXT
        label = tk.Label(
            parent,
            text=text,
            bg=chip_bg,
            fg=chip_fg,
            padx=11,
            pady=5,
            font=('Segoe UI Semibold', 8),
            highlightthickness=1,
            highlightbackground=(color or BORDER_SOFT),
        )
        return label

    def _configure_tree_visuals(self, tree: ttk.Treeview) -> None:
        """Apply consistent table tags so all tables feel like one product."""
        try:
            tree.tag_configure('oddrow', background=INPUT_BG, foreground=TEXT)
            tree.tag_configure('evenrow', background=ROW_ALT, foreground=TEXT)
            tree.tag_configure('critical', background=RISK_TAG_BG.get('Critical', INPUT_BG), foreground=TEXT)
            tree.tag_configure('high', background=RISK_TAG_BG.get('High', INPUT_BG), foreground=TEXT)
            tree.tag_configure('moderate', background=RISK_TAG_BG.get('Moderate', INPUT_BG), foreground=TEXT)
            tree.tag_configure('low', background=RISK_TAG_BG.get('Low', INPUT_BG), foreground=TEXT)
            tree.tag_configure('warning', background='#2F2410', foreground=WARNING)
            tree.tag_configure('danger', background='#321522', foreground=DANGER)
            tree.tag_configure('success', background='#102B22', foreground=SUCCESS)
        except Exception:
            pass

    def _attach_tree_scrollbars(self, tree: ttk.Treeview) -> None:
        """Attach slim dark scrollbars only when a table really needs them.

        V11 always overlaid a horizontal bar.  On Windows that bar can render as
        a bright native strip, which looked broken in wide empty tables.  V12
        auto-hides horizontal and vertical bars when the content fits, while
        still exposing them for dense AI/Proof evidence tables.
        """
        try:
            parent = tree.master
            vsb = ttk.Scrollbar(parent, orient='vertical', command=tree.yview, style='Vertical.TScrollbar')
            hsb = ttk.Scrollbar(parent, orient='horizontal', command=tree.xview, style='Horizontal.TScrollbar')
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

            sync_pending = {'id': None}

            def _content_width() -> int:
                try:
                    total = 0
                    show = str(tree.cget('show'))
                    if '#0' in show or show in {'tree', 'tree headings'}:
                        total += int(tree.column('#0', 'width') or 0)
                    for col in tree.cget('columns') or ():
                        total += int(tree.column(col, 'width') or 0)
                    return total
                except Exception:
                    return 0

            def _sync_bars(_event=None) -> None:
                try:
                    if sync_pending['id'] is not None:
                        return

                    def _apply() -> None:
                        sync_pending['id'] = None
                        try:
                            width = max(1, tree.winfo_width())
                            content_width = _content_width()
                            if content_width > width + 10:
                                hsb.place(in_=tree, relx=0, rely=1.0, relwidth=1.0, anchor='sw')
                            else:
                                hsb.place_forget()
                                tree.xview_moveto(0)

                            rowheight = int(self.style.lookup('Treeview', 'rowheight') or 36)
                            visible_rows = max(1, int((tree.winfo_height() - rowheight) / max(rowheight, 1)))
                            if len(tree.get_children('')) > visible_rows:
                                vsb.place(in_=tree, relx=1.0, rely=0, relheight=1.0, anchor='ne')
                            else:
                                vsb.place_forget()
                                tree.yview_moveto(0)
                        except Exception:
                            pass

                    sync_pending['id'] = tree.after_idle(_apply)
                except Exception:
                    pass

            def _wheel(event, target=tree):
                try:
                    if getattr(event, 'num', None) == 4:
                        target.yview_scroll(-3, 'units')
                    elif getattr(event, 'num', None) == 5:
                        target.yview_scroll(3, 'units')
                    else:
                        target.yview_scroll(int(-1 * (event.delta / 120)) * 3, 'units')
                    _sync_bars()
                    return 'break'
                except Exception:
                    return None

            tree.bind('<Configure>', _sync_bars, add='+')
            tree.bind('<<TreeviewSelect>>', _sync_bars, add='+')
            tree.bind('<Map>', _sync_bars, add='+')
            tree.bind('<MouseWheel>', _wheel, add='+')
            tree.bind('<Button-4>', _wheel, add='+')
            tree.bind('<Button-5>', _wheel, add='+')
            tree.after_idle(_sync_bars)
            tree.after(500, _sync_bars)
        except Exception:
            pass

    def _attach_text_scrollbar(self, text: tk.Text) -> None:
        """Give dense read-only text panels an integrated dark scrollbar.

        This prevents AI explanation/action-plan content from feeling cut off
        inside fixed-height panels and keeps page scrolling available when the
        text block itself reaches its edge.
        """
        try:
            parent = text.master
            vsb = ttk.Scrollbar(parent, orient='vertical', command=text.yview, style='Vertical.TScrollbar')
            text.configure(yscrollcommand=vsb.set)
            vsb.place(in_=text, relx=1.0, rely=0, relheight=1.0, anchor='ne')
        except Exception:
            pass

    def _style_text_widget(self, widget: tk.Text) -> None:
        try:
            widget.configure(
                bg=PANEL_DEEP,
                fg=TEXT,
                insertbackground=TEXT,
                selectbackground=self.accent,
                selectforeground=APP_BG,
                relief='flat',
                bd=0,
                padx=12,
                pady=10,
                highlightthickness=1,
                highlightbackground=BORDER_SOFT,
                highlightcolor=self.accent,
                font=('Segoe UI', 11),
            )
        except Exception:
            pass

    def _sidebar_button(self, parent: tk.Widget, page_key: str, text: str) -> tk.Button:
        icon = PAGE_ICONS.get(page_key, '•')
        btn = tk.Button(
            parent,
            text=f'  {icon}  {text}',
            command=lambda k=page_key: self.show_view(k),
            relief='flat',
            bd=0,
            bg=SIDEBAR_BG,
            fg=SUBTEXT,
            activebackground=HOVER,
            activeforeground=TEXT,
            highlightthickness=1,
            highlightbackground=SIDEBAR_BG,
            highlightcolor=SIDEBAR_BG,
            padx=14,
            pady=10,
            anchor='w',
            cursor='hand2',
            font=('Segoe UI Semibold', 9),
        )
        btn.page_key = page_key  # type: ignore[attr-defined]
        btn.bind('<Enter>', lambda _e, b=btn: self._nav_hover(b, True))
        btn.bind('<Leave>', lambda _e, b=btn: self._nav_hover(b, False))
        self.sidebar_buttons[page_key] = btn
        return btn

    def _nav_hover(self, btn: tk.Button, hover: bool) -> None:
        page = getattr(btn, 'page_key', '')
        if page == self.current_page:
            return
        btn.configure(bg=SURFACE_2 if hover else SIDEBAR_BG, highlightbackground=SURFACE_2 if hover else SIDEBAR_BG)

    def _top_action_button(self, parent: tk.Widget, text: str, command, *, kind: str = 'ghost') -> ttk.Button:
        style = {'accent': 'Accent.TButton', 'danger': 'Danger.TButton'}.get(kind, 'Ghost.TButton')
        prefix = ACTION_ICONS.get(text, '')
        label = f'{prefix}  {text}' if prefix else text
        btn = ttk.Button(parent, text=label, command=command, style=style)
        return btn

    def _page_hero_header(self, parent: tk.Widget, title: str, subtitle: str, *, action_text: str | None = None, command=None, kind: str = 'ghost') -> tk.Frame:
        """Reusable compact page/header block for premium UI pages."""
        wrap = self._card(parent, bg=PANEL_DEEP, padx=16, pady=14)
        wrap.pack(fill='x', pady=(0, 12))
        inner = wrap.inner
        left = tk.Frame(inner, bg=inner.cget('bg'))
        left.pack(side='left', fill='x', expand=True)
        self._label(left, title, bg=left.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(left, subtitle, fg=MUTED, bg=left.cget('bg'), font=('Segoe UI', 9), wraplength=860).pack(anchor='w', pady=(4, 0))
        if action_text and command:
            self._top_action_button(inner, action_text, command, kind=kind).pack(side='right')
        return wrap

    def _severity_badge(self, parent: tk.Widget, text: str, *, level: str = 'info') -> tk.Label:
        """Small consistent severity/status badge."""
        color = {
            'success': SUCCESS,
            'low': SUCCESS,
            'info': INFO,
            'medium': WARNING,
            'moderate': INFO,
            'warning': WARNING,
            'high': WARNING,
            'danger': DANGER,
            'critical': DANGER,
            'planned': MUTED,
        }.get(str(level).lower(), INFO)
        bg = RISK_TAG_BG.get(text, PANEL_DEEP)
        return tk.Label(parent, text=text, bg=bg, fg=color, padx=10, pady=4, font=('Segoe UI Semibold', 8))

    def _mini_stat_card(self, parent: tk.Widget, title: str, value_var: tk.StringVar | str, hint: str = '', *, level: str = 'info', accent: str | None = None, subtitle: str = '', icon: str = '•') -> tk.Frame:
        color = accent or {
            'success': SUCCESS, 'low': SUCCESS, 'info': INFO, 'medium': WARNING,
            'moderate': INFO, 'warning': WARNING, 'high': WARNING, 'danger': DANGER,
            'critical': DANGER, 'planned': MUTED,
        }.get(str(level).lower(), self.accent)
        card = self._glow_card(parent, bg=CARD_BG, accent=color, padx=14, pady=12, height=92 if not hint and not subtitle else None)
        inner = card.inner
        top = tk.Frame(inner, bg=inner.cget('bg'))
        top.pack(fill='x')
        tk.Label(top, text=icon, bg=PANEL_DEEP, fg=color, width=3, pady=3, font=('Segoe UI Semibold', 10), highlightthickness=1, highlightbackground=BORDER_SOFT).pack(side='left')
        self._label(top, title, fg=SUBTEXT, bg=top.cget('bg'), font=('Segoe UI', 9)).pack(side='left', padx=(8, 0))
        if isinstance(value_var, tk.StringVar):
            self._label(inner, textvariable=value_var, bg=inner.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(8, 0))
        else:
            self._label(inner, str(value_var), bg=inner.cget('bg'), font=('Segoe UI Semibold', 18)).pack(anchor='w', pady=(8, 0))
        detail = subtitle or hint
        if detail:
            self._label(inner, detail, fg=MUTED, bg=inner.cget('bg'), font=('Segoe UI', 8), wraplength=230).pack(anchor='w', pady=(4, 0))
        return card

    def _report_option_card(self, parent: tk.Widget, title: str, body: str, button_text: str, command, *, level: str = 'info') -> tk.Frame:
        card = self._card(parent, bg=CARD_BG_2, padx=16, pady=16)
        inner = card.inner
        head = tk.Frame(inner, bg=inner.cget('bg'))
        head.pack(fill='x')
        self._label(head, title, bg=head.cget('bg'), font=('Segoe UI Semibold', 12)).pack(side='left')
        self._severity_badge(head, level.upper() if level != 'info' else 'SAFE', level=level).pack(side='right')
        self._label(inner, body, fg=SUBTEXT, bg=inner.cget('bg'), font=('Segoe UI', 9), wraplength=340).pack(anchor='w', pady=(8, 12))
        self._top_action_button(inner, button_text, command, kind='accent' if level in {'success', 'info'} else 'ghost').pack(anchor='w')
        return card

    def _timeline_step(self, parent: tk.Widget, number: str, title: str, body: str, *, level: str = 'info') -> tk.Frame:
        row = tk.Frame(parent, bg=parent.cget('bg'))
        bubble = tk.Label(row, text=number, bg=LEVEL_COLORS.get(level, INFO), fg=APP_BG, width=3, pady=5, font=('Segoe UI Semibold', 10))
        bubble.pack(side='left', anchor='n')
        text = tk.Frame(row, bg=row.cget('bg'))
        text.pack(side='left', fill='x', expand=True, padx=(10, 0))
        self._label(text, title, bg=text.cget('bg'), font=('Segoe UI Semibold', 10)).pack(anchor='w')
        self._label(text, body, fg=MUTED, bg=text.cget('bg'), font=('Segoe UI', 9), wraplength=430).pack(anchor='w', pady=(2, 0))
        return row

    def _build_quick_actions_button(self, parent: tk.Widget) -> tk.Menubutton:
        btn = tk.Menubutton(
            parent,
            text='⋯  Quick Actions',
            relief='flat',
            bd=0,
            bg=CARD_BG_2,
            fg=TEXT,
            activebackground='#203A5F',
            activeforeground=TEXT,
            padx=12,
            pady=9,
            cursor='hand2',
            font=('Segoe UI Semibold', 10),
            highlightthickness=1,
            highlightbackground=BORDER,
            direction='below',
        )
        menu = tk.Menu(btn, tearoff=False, bg=INPUT_BG, fg=TEXT, activebackground=self.accent, activeforeground=APP_BG)
        menu.add_command(label='Import CSV / Browser Export', command=self.import_csv)
        menu.add_command(label='Open Reports Workspace', command=lambda: self.show_view('reports'))
        menu.add_command(label='Open Backup / Recovery', command=lambda: self.show_view('backup_recovery'))
        menu.add_command(label='Export Report Preview', command=self.export_report)
        menu.add_command(label='Export Backup', command=self.export_backup)
        menu.add_separator()
        menu.add_command(label='Open Isolated Demo Vault', command=self.open_isolated_demo_vault)
        menu.add_command(label='Exit Demo Vault', command=self.exit_demo_vault)
        menu.add_command(label='Create Assessment Workspace', command=self.load_demo_data)
        menu.add_command(label='Full-Screen Focus Mode', command=self.toggle_presentation_mode)
        btn.configure(menu=menu)
        return btn

    def _refresh_nav_styles(self) -> None:
        active_color = PAGE_COLORS.get(self.current_page, self.accent)
        for page, btn in self.sidebar_buttons.items():
            active = page == self.current_page
            page_color = PAGE_COLORS.get(page, active_color)
            btn.configure(
                bg=(page_color if active else SIDEBAR_BG),
                fg=APP_BG if active else TEXT,
                activebackground=(page_color if active else SURFACE_2),
                activeforeground=APP_BG if active else TEXT,
                highlightthickness=1,
                highlightbackground=(page_color if active else SIDEBAR_BG),
                highlightcolor=(page_color if active else SIDEBAR_BG),
            )

    def _install_global_scroll_router(self) -> None:
        """Make mouse wheel scrolling work from anywhere in the active page.

        Tkinter only sends <MouseWheel> to the widget under the cursor; the old
        implementation bound the wheel to the canvas and body only, so hovering
        over cards, labels, text blocks, or tables made the page feel frozen.
        This router fixes that while letting Treeview/Text widgets scroll first.
        """
        if getattr(self, '_global_scroll_router_installed', False):
            return
        self._global_scroll_router_installed = True

        def _route(event):
            try:
                widget = getattr(event, 'widget', None)
                delta = -3 if getattr(event, 'num', None) == 4 else 3 if getattr(event, 'num', None) == 5 else int(-1 * (event.delta / 120)) * 3
                cls = widget.winfo_class() if widget else ''

                if cls in {'Treeview', 'Text', 'Listbox'}:
                    try:
                        first, last = widget.yview()
                        if not (first <= 0.0 and delta < 0) and not (last >= 1.0 and delta > 0):
                            widget.yview_scroll(delta, 'units')
                            return 'break'
                    except Exception:
                        pass

                canvas = getattr(self, '_active_scroll_canvas', None)
                if canvas is None or not canvas.winfo_exists():
                    return None
                bbox = canvas.bbox('all') or (0, 0, 0, 0)
                if (bbox[3] - bbox[1]) <= canvas.winfo_height() + 4:
                    return None
                canvas.yview_scroll(delta, 'units')
                return 'break'
            except Exception:
                return None

        self.bind_all('<MouseWheel>', _route, add='+')
        self.bind_all('<Button-4>', _route, add='+')
        self.bind_all('<Button-5>', _route, add='+')

    def _activate_page_scroll(self, frame: tk.Widget) -> None:
        try:
            canvas = getattr(frame, '_scroll_canvas', None)
            if canvas is not None:
                self._active_scroll_canvas = canvas
                self._install_global_scroll_router()
                canvas.after_idle(lambda c=canvas: c.configure(scrollregion=c.bbox('all') or (0, 0, 0, 0)))
        except Exception:
            pass

    def show_view(self, page_key: str) -> None:
        self.current_page = page_key
        title, subtitle = PAGE_META[page_key]
        self.page_title_var.set(title)
        self.page_subtitle_var.set(subtitle)
        context_title, context_tip = PAGE_CONTEXT.get(page_key, ('Workspace', ''))
        if hasattr(self, 'page_context_var'):
            self.page_context_var.set(context_title)
        if hasattr(self, 'page_tip_var'):
            self.page_tip_var.set(context_tip)
        if hasattr(self, 'page_context_badge'):
            try:
                self.page_context_badge.configure(bg=PAGE_COLORS.get(page_key, self.accent), fg=APP_BG)
            except Exception:
                pass
        active_frame = None
        for key, frame in self.pages.items():
            if key == page_key:
                frame.pack(fill='both', expand=True)
                active_frame = frame
            else:
                frame.pack_forget()
        if active_frame is not None:
            self._activate_page_scroll(active_frame)
        compact_pages = {'generator', 'security', 'ai_guardian', 'trash', 'activity', 'settings', 'system_health', 'about', 'proof', 'reports', 'backup_recovery'}
        if hasattr(self, 'metrics_row'):
            if page_key in compact_pages and self.metrics_row.winfo_manager():
                self.metrics_row.pack_forget()
            elif page_key not in compact_pages and not self.metrics_row.winfo_manager():
                self.metrics_row.pack(fill='x', pady=(12, 0))
        self._refresh_nav_styles()

    def _configure_dashboard_card(self, index: int, *, title: str, body: str, button_text: str, command, style: str = 'Ghost.TButton') -> None:
        if not hasattr(self, 'dashboard_recommendation_cards') or index >= len(self.dashboard_recommendation_cards):
            return
        card = self.dashboard_recommendation_cards[index]
        card['title'].set(title)
        card['body'].set(body)
        card['button_text'].set(button_text)
        card['button'].configure(command=command, style=style)

    def _set_dashboard_actions(self, metrics: dict) -> None:
        total = int(metrics.get('total', 0) or 0)
        weak = int(metrics.get('weak', 0) or 0)
        breached = int(metrics.get('breached', 0) or 0)
        reused = int(metrics.get('reused_passwords', 0) or 0)
        old = int(metrics.get('old', 0) or 0)
        if total == 0:
            self._configure_dashboard_card(0, title='Add your first credential', body='Start with a real account or an assessment entry so the vault can begin scoring health and posture.', button_text='Add Credential', command=self.open_quick_add, style='Accent.TButton')
            self._configure_dashboard_card(1, title='Import browser CSV', body='Bring in Chrome, Edge, or generic CSV exports and encrypt them on save.', button_text='Import CSV', command=self.import_csv)
            self._configure_dashboard_card(2, title='Run security tour', body='Open a guided walkthrough of the vault, Security Center, AI-style Local Security Coach, backups, and proof checks without exposing sample-data controls.', button_text='Quick Tour', command=self.show_quick_tour)
            self.dashboard_priority_var.set('No data yet. Add credentials or import a browser CSV to activate health scoring and breach intelligence.')
            return
        if breached or weak or reused or old:
            self._configure_dashboard_card(0, title='Review findings', body='Open Security Center to inspect breached, weak, reused, or stale credentials and their offline intelligence.', button_text='Open Security Center', command=lambda: self.show_view('security'), style='Accent.TButton')
            self._configure_dashboard_card(1, title='Generate replacements', body='Create unique 16+ character passwords and inject them back into the selected credential editor.', button_text='Open Generator', command=lambda: self.show_view('generator'))
            self._configure_dashboard_card(2, title='Export executive report', body='Generate a polished summary with findings, recommendations, and top-priority remediation items.', button_text='Export Report', command=self.export_report)
            self.dashboard_priority_var.set('Priority focus: review high-risk credentials in Security Center, replace reused/weak passwords, then export the report.')
            return
        self._configure_dashboard_card(0, title='Open vault workspace', body='Browse credentials, profile cards, history, and secure notes from the main encrypted vault view.', button_text='Open Vault', command=lambda: self.show_view('vault'), style='Accent.TButton')
        self._configure_dashboard_card(1, title='Create encrypted backup', body='Capture the current vault state in an encrypted backup before major changes or operational review.', button_text='Export Backup', command=self.export_backup)
        self._configure_dashboard_card(2, title='Generate report', body='Summarize healthy posture, backup status, and recommended maintenance steps in the executive report.', button_text='Export Report', command=self.export_report)
        self.dashboard_priority_var.set('Vault posture is healthy. Keep backups current and rotate older credentials on schedule.')

    def _labeled_entry(self, parent: tk.Widget, label: str, variable: tk.StringVar, show: str = '') -> None:
        self._label(parent, label, bg=parent.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w', pady=(10, 0))
        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=INPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief='flat',
            bd=0,
            highlightthickness=1,
            highlightbackground=INPUT_BORDER,
            highlightcolor=self.accent,
            font=('Segoe UI', 11),
        )
        entry.pack(fill='x', pady=(6, 0), ipady=7)
        try:
            if not hasattr(parent, '_cvx_entries'):
                parent._cvx_entries = []  # type: ignore[attr-defined]
            parent._cvx_entries.append(entry)  # type: ignore[attr-defined]
        except Exception:
            pass

    def _refresh_filter_chips(self) -> None:
        """Make active quick filters obvious without needing custom ttk state hacks."""
        buttons = getattr(self, 'threat_filter_buttons', {})
        current = self.threat_filter_var.get()
        for value, meta in buttons.items():
            label = meta.get('label', value)
            btn = meta.get('button')
            if not btn:
                continue
            try:
                btn.configure(text=(f'✓ {label}' if value == current else label))
            except Exception:
                pass

    def _clear_filters(self) -> None:
        self.search_var.set('')
        self.category_filter_var.set('All')
        self.threat_filter_var.set('All Status')
        self._refresh_filter_chips()
        self.refresh_all()

    def _fmt_dt(self, value: str) -> str:
        if not value:
            return '-'
        try:
            return value.replace('T', ' ')[:19]
        except Exception:
            return value

    def _set_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', value)
        widget.configure(state='disabled')

    def _set_history(self, history: list[dict[str, str]]) -> None:
        if hasattr(self, 'history_tree'):
            self.history_tree.delete(*self.history_tree.get_children())
            if not history:
                self.history_tree.insert('', 'end', iid='empty', values=('-', 'No history', 'No previous passwords'), tags=('oddrow',))
                if hasattr(self, 'history_hint_var'):
                    self.history_hint_var.set('No password history yet. Updating a password will create a masked timeline entry here.')
                return
            for idx, item in enumerate(history, start=1):
                password = item.get('password', '')
                analysis = analyze_password(password)
                masked = '•' * min(12, max(8, len(password)))
                iid = str(idx)
                self.history_tree.insert('', 'end', iid=iid, values=(self._fmt_dt(item.get('changed_at', '')), f"{analysis.label} ({analysis.score}/100)", masked), tags=('evenrow' if idx % 2 == 0 else 'oddrow',))
            if hasattr(self, 'history_hint_var'):
                self.history_hint_var.set('Select a history row to reveal or copy it after master-password re-authentication.')
            return

        # Legacy fallback for older UI builds.
        self.history_list.delete(0, 'end')
        if not history:
            self.history_list.insert('end', 'No password history yet.')
            return
        for item in history:
            masked = '*' * min(8, max(4, len(item['password']) // 2))
            self.history_list.insert('end', f"{self._fmt_dt(item['changed_at'])}  |  {masked}")

    def _set_status(self, message: str, *, level: str = 'info', toast: bool = True) -> None:
        self.status_var.set(message)
        if hasattr(self, 'status_badge'):
            color = LEVEL_COLORS.get(level, self.accent)
            self.status_badge.delete('all')
            self.status_badge.create_oval(2, 2, 12, 12, fill=color, outline=color)
        if toast:
            self._show_toast('CyberVault X', message, kind=level)

    def _show_toast(self, title: str, message: str, *, kind: str = 'info', parent=None) -> None:
        host = parent or self
        if self.toast_window and self.toast_window.winfo_exists():
            try:
                self.toast_window.destroy()
            except Exception:
                pass
        win = tk.Toplevel(host)
        win.overrideredirect(True)
        win.configure(bg='#06101c')
        win.attributes('-topmost', True)
        card = tk.Frame(win, bg='#0d1b2f', padx=14, pady=12, highlightthickness=1, highlightbackground=LEVEL_COLORS.get(kind, self.accent))
        card.pack(fill='both', expand=True)
        self._label(card, title, bg=card.cget('bg'), font=('Segoe UI Semibold', 11)).pack(anchor='w')
        self._label(card, message, fg=SUBTEXT, bg=card.cget('bg'), wraplength=280, font=('Segoe UI', 9)).pack(anchor='w', pady=(4, 0))
        try:
            host.update_idletasks()
            x = host.winfo_rootx() + host.winfo_width() - 330
            y = host.winfo_rooty() + 36
            win.geometry(f'+{x}+{y}')
        except Exception:
            pass
        self.toast_window = win
        if self.toast_after_id:
            try:
                self.after_cancel(self.toast_after_id)
            except Exception:
                pass
        self.toast_after_id = self.after(2400, lambda: win.destroy() if win.winfo_exists() else None)

    def _confirm_action(self, title: str, message: str, *, ok_text: str = 'Confirm', cancel_text: str = 'Cancel', kind: str = 'info') -> bool:
        result = {'value': False}
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry('420x220')
        dialog.resizable(False, False)
        dialog.configure(bg=APP_BG)
        dialog.transient(self)
        dialog.grab_set()
        shell = tk.Frame(dialog, bg=APP_BG, padx=20, pady=20)
        shell.pack(fill='both', expand=True)
        card = self._card(shell, bg=CARD_BG, padx=18, pady=18)
        card.pack(fill='both', expand=True)
        ci = card.inner
        self._label(ci, title, bg=ci.cget('bg'), font=('Segoe UI Semibold', 14)).pack(anchor='w')
        self._label(ci, message, fg=SUBTEXT, bg=ci.cget('bg'), wraplength=340).pack(anchor='w', pady=(10, 0))
        actions = tk.Frame(ci, bg=ci.cget('bg'))
        actions.pack(fill='x', pady=(20, 0))
        def accept():
            result['value'] = True
            dialog.destroy()
        ttk.Button(actions, text=ok_text, command=accept, style='Accent.TButton').pack(side='left')
        ttk.Button(actions, text=cancel_text, command=dialog.destroy, style='Ghost.TButton').pack(side='left', padx=(8, 0))
        self.wait_window(dialog)
        return result['value']

    def _render_credential_badges(self, item: Credential | None) -> None:
        if not hasattr(self, 'credential_badges'):
            return
        for child in self.credential_badges.winfo_children():
            child.destroy()
        if not item:
            for text_value in ('No selection',):
                tk.Label(self.credential_badges, text=text_value, bg='#13243b', fg=TEXT, padx=8, pady=4, font=('Segoe UI Semibold', 9)).pack(side='left', padx=(0, 6))
            return
        intel = self.manager.breach_intelligence_for(item)
        badges = [(intel['label'], self.accent)]
        if intel['breached']:
            badges.append(('Breached', DANGER))
        if intel['reuse_count'] > 1:
            badges.append((f"Reused x{intel['reuse_count']}", WARNING))
        if intel['old_password']:
            badges.append(('Old', WARNING))
        if item.is_favorite:
            badges.append(('Favorite', '#7ea8ff'))
        for label, color in badges[:4]:
            tk.Label(self.credential_badges, text=label, bg=color, fg=APP_BG, padx=8, pady=4, font=('Segoe UI Semibold', 9)).pack(side='left', padx=(0, 6))

    def _draw_generator_meter(self, score: int, entropy_bits: float) -> None:
        c = self.generator_meter_canvas
        c.delete('all')
        width = max(c.winfo_width() or 520, 520) - 20
        x0, y0 = 10, 22
        bar_h = 16
        sections = [('Weak', 25), ('Fair', 50), ('Strong', 75), ('Excellent', 100)]
        start = x0
        for label, endpoint in sections:
            end = x0 + (width * endpoint / 100)
            c.create_rectangle(start, y0, end, y0 + bar_h, fill=CARD_BG_2, outline='')
            c.create_text((start + end) / 2, y0 - 8, text=label, fill=MUTED, font=('Segoe UI', 8))
            start = end
        fill = x0 + (width * max(0, min(score, 100)) / 100)
        c.create_rectangle(x0, y0, fill, y0 + bar_h, fill=self.accent, outline='')
        c.create_rectangle(x0, y0, x0 + width, y0 + bar_h, outline=BORDER, width=1)
        c.create_text(14, 62, text=f'Score {score}/100', anchor='w', fill=TEXT, font=('Segoe UI Semibold', 11))
        c.create_text(150, 62, text=f'Entropy {entropy_bits} bits', anchor='w', fill=SUBTEXT, font=('Segoe UI', 11))

    def _draw_health_score(self, score: int | None) -> None:
        c = self.health_score_canvas
        c.delete('all')
        c.create_rectangle(0, 0, 540, 144, fill=CARD_BG_2, outline=CARD_BG_2)
        x0, y0, x1, y1 = 18, 16, 126, 124
        c.create_oval(x0, y0, x1, y1, outline=PANEL_DEEP, width=12)
        c.create_text(170, 34, text='Vault Health Score', fill=TEXT, font=('Segoe UI Semibold', 16), anchor='w')
        if score is None:
            c.create_text(79, 68, text='—', fill=TEXT, font=('Segoe UI Semibold', 28))
            c.create_text(79, 94, text='no data', fill=SUBTEXT, font=('Segoe UI', 11))
            c.create_text(158, 54, text='The score activates after you add or import credentials into the vault.', fill=SUBTEXT, font=('Segoe UI', 11), anchor='w')
            c.create_rectangle(158, 88, 500, 104, fill=PANEL_DEEP, outline=PANEL_DEEP)
            c.create_text(500, 96, text='awaiting data', fill=SUBTEXT, font=('Segoe UI Semibold', 11), anchor='e')
            return
        extent = max(5, int(360 * score / 100)) if score > 0 else 0
        color = DANGER if score < 50 else WARNING if score < 75 else SUCCESS
        if extent:
            c.create_arc(x0, y0, x1, y1, start=90, extent=-extent, style='arc', outline=color, width=12)
        c.create_text(79, 68, text=f'{score}', fill=TEXT, font=('Segoe UI Semibold', 28))
        c.create_text(79, 94, text='score', fill=SUBTEXT, font=('Segoe UI', 11))
        c.create_text(158, 54, text='Weighted from weak, breached, reused, old, and trashed credentials.', fill=SUBTEXT, font=('Segoe UI', 11), anchor='w')
        c.create_rectangle(158, 88, 500, 104, fill=PANEL_DEEP, outline=PANEL_DEEP)
        fill_color = color if score < 75 else self.accent
        c.create_rectangle(158, 88, 158 + (342 * score / 100), 104, fill=fill_color, outline=fill_color)
        c.create_text(500, 96, text='excellent' if score >= 85 else 'stable' if score >= 70 else 'watch' if score >= 50 else 'critical', fill=SUBTEXT, font=('Segoe UI Semibold', 11), anchor='e')

    def _draw_command_center(self, score: int | None) -> None:
        if not hasattr(self, 'vault_command_canvas'):
            return
        c = self.vault_command_canvas
        c.delete('all')
        c.create_rectangle(0, 0, 500, 126, fill=CARD_BG_2, outline=CARD_BG_2)
        x0, y0, x1, y1 = 18, 16, 106, 104
        c.create_oval(x0, y0, x1, y1, outline=PANEL_DEEP, width=10)
        c.create_text(132, 24, text='Live command center', fill=TEXT, font=('Segoe UI Semibold', 14), anchor='w')
        if score is None:
            c.create_text(62, 56, text='—', fill=TEXT, font=('Segoe UI Semibold', 24))
            c.create_text(62, 78, text='awaiting data', fill=SUBTEXT, font=('Segoe UI', 9))
            c.create_text(132, 46, text='Import/add credentials to activate risk, breach, and backup posture.', fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')
            c.create_text(132, 74, text=self.command_encryption_var.get(), fill=TEXT, font=('Segoe UI Semibold', 11), anchor='w')
            c.create_text(132, 96, text='Accounts at risk: 0', fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')
            c.create_text(132, 116, text=self.command_backup_var.get(), fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')
            return
        extent = max(5, int(360 * score / 100)) if score > 0 else 0
        color = DANGER if score < 50 else WARNING if score < 75 else SUCCESS
        if extent:
            c.create_arc(x0, y0, x1, y1, start=90, extent=-extent, style='arc', outline=color, width=10)
        c.create_text(62, 56, text=f'{score}', fill=TEXT, font=('Segoe UI Semibold', 24))
        c.create_text(62, 78, text='risk score', fill=SUBTEXT, font=('Segoe UI', 9))
        c.create_text(132, 46, text='Risk, breach exposure, and backup posture update live.', fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')
        c.create_text(132, 74, text=self.command_encryption_var.get(), fill=TEXT, font=('Segoe UI Semibold', 11), anchor='w')
        c.create_text(132, 96, text=self.command_exposure_var.get(), fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')
        c.create_text(132, 116, text=self.command_backup_var.get(), fill=SUBTEXT, font=('Segoe UI', 9), anchor='w')

    def _render_breach_intelligence(self, intel: dict) -> None:
        if not hasattr(self, 'breach_intel_text'):
            return
        lines = [
            f"Risk level: {intel.get('risk_level', 'Unknown')} ({intel.get('score', 0)}/100)",
            f"Known leaked/common password: {'Yes' if intel.get('breached') or intel.get('common_password') else 'No'}",
            f"Reuse count: {intel.get('reuse_count', 0)}",
            '',
            'Risk explanation:',
            intel.get('explanation', 'No details available.'),
            '',
            'Why this matters:',
            *[f"• {item}" for item in intel.get('why_matters', [])],
            '',
            'Fix recommendation:',
            *[f"• {item}" for item in intel.get('fix_recommendations', [])],
        ]
        self._set_text(self.breach_intel_text, '\n'.join(lines))

    def _draw_site_badge(self, initials: str) -> None:
        c = self.site_canvas
        c.delete('all')
        c.create_oval(5, 5, 53, 53, fill=self.accent, outline=self.accent)
        c.create_text(29, 29, text=initials[:2].upper(), fill=APP_BG, font=('Segoe UI Semibold', 16))

    def _render_site_visual(self, website: str, title: str, category: str = '') -> None:
        host = normalize_site(website) or title or 'Local item'
        initials = ''.join(part[0] for part in host.replace('.', ' ').split()[:2]).upper() or 'CV'
        self.site_host_var.set(host)
        self._draw_site_badge(initials)
        self.site_image_label.configure(image='')
        self.current_favicon_image = None
        self._favicon_request_host = ''
        sensitive_category = str(category or '').strip().lower() in {'banking', 'crypto', 'servers', 'work'}
        if website and self.favicon_lookup_var.get() and not sensitive_category:
            loaded = self._load_favicon_async(website)
            if not loaded and safe_favicon_host(website) == '':
                self.site_host_var.set(f'{host} · local badge only')
        elif sensitive_category:
            self.site_host_var.set(f'{host} · local badge only')

    def _load_favicon_async(self, website: str) -> bool:
        if not self.favicon_lookup_var.get():
            return False
        host = safe_favicon_host(website)
        if not host:
            return False
        self._favicon_request_host = host
        cache = self.favicon_cache_dir / f'{safe_cache_name(host)}.png'

        def _looks_like_supported_favicon(data: bytes, content_type: str) -> bool:
            lowered = content_type.lower().split(';', 1)[0].strip()
            if lowered and not lowered.startswith('image/'):
                return False
            return data.startswith(b'\x89PNG\r\n\x1a\n') or data.startswith(b'GIF87a') or data.startswith(b'GIF89a')

        def worker() -> None:
            try:
                if not cache.exists():
                    url = f'https://www.google.com/s2/favicons?domain={host}&sz=64'
                    with urllib.request.urlopen(url, timeout=5) as response:
                        content_length = response.headers.get('Content-Length')
                        if content_length and int(content_length) > 128_000:
                            raise ValueError('favicon response is too large')
                        content_type = response.headers.get('Content-Type', '')
                        data = response.read(128_000)
                    if not data or not _looks_like_supported_favicon(data, content_type):
                        raise ValueError('favicon response is not a supported image')
                    atomic_write_bytes(cache, data)
                self.after(0, lambda: self._apply_favicon(cache, expected_host=host))
            except Exception:
                try:
                    if cache.exists() and cache.stat().st_size == 0:
                        cache.unlink()
                except Exception:
                    pass

        threading.Thread(target=worker, daemon=True).start()
        return True

    def _apply_favicon(self, path: Path, *, expected_host: str) -> None:
        if expected_host != getattr(self, '_favicon_request_host', ''):
            return
        try:
            image = tk.PhotoImage(file=str(path))
            if expected_host != getattr(self, '_favicon_request_host', ''):
                return
            self.current_favicon_image = image
            self.site_image_label.configure(image=image)
        except Exception:
            self.site_image_label.configure(image='')
            self.current_favicon_image = None
