"""Pingmaker UI — Tkinter dark-themed interface for packet speed modification."""

import os
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk
from collections import defaultdict

import pydivert
from pydivert import Flag

from skills import SkillData, fuzzy_search, get_resource_path, load_skills
from settings import load_settings, save_settings, get_settings_path
from entities import EntityTracker
from ports import PortTracker
from capture import CaptureEngine
from protocol import encode_varint

HAS_WEAVE = False


# ── Theme ──────────────────────────────────────────────────────

class Style:
    BG = "#0d1b2a"
    BG_LIGHT = "#1b263b"
    BG_CARD = "#1b263b"
    RED = "#c41e3a"
    RED_HOVER = "#e63946"
    BLUE = "#3a86ff"
    YELLOW = "#ffd700"
    TEXT = "#f5f0e6"
    TEXT_DIM = "#a89a80"
    BORDER = "#2d3f5a"


# ── Application ────────────────────────────────────────────────

class PingmakerApp:
    def __init__(self, root: tk.Tk, skill_data: SkillData):
        self.root = root
        self.skill_data = skill_data

        self.root.title("Pingmaker")
        self.root.geometry("380x650")
        self.root.minsize(330, 450)
        self.root.configure(bg=Style.BG)

        try:
            icon_path = get_resource_path("pingmaker.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        # State
        self.selected_skills: dict = {}   # name -> {ids, attack_speed, overflow}
        self._skill_rows: dict = {}       # name -> {frame, speed_entry, overflow_var}
        self.is_running = False
        self._loading_settings = True

        # UI variables
        self.uniform_speed = tk.StringVar(value="")
        self.uniform_break = tk.BooleanVar(value=False)
        self.char_names_var = tk.StringVar()
        self.csv_logging = tk.BooleanVar(value=False)

        # Event queue for capture engine → UI communication
        self._event_queue: queue.Queue = queue.Queue(maxsize=1000)

        # Core components
        self.entity_tracker = EntityTracker()
        self.port_tracker = PortTracker(refresh_interval=2.0)
        self.engine = CaptureEngine(
            skill_data, self.entity_tracker, self.port_tracker, self._event_queue)

        # Build UI
        self._setup_styles()
        self._build_ui()

        # Load settings
        self._load_settings()

        # Start port tracker and capture engine (sniff mode)
        self.port_tracker.start(on_change=self.engine.on_ports_changed)
        self.engine.start()

        # Poll events from capture engine
        self._poll_events()

        # Poll entity status
        self._poll_entity_status()

        # Save on close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.engine.stop()
        self.port_tracker.stop()
        self._save_settings()
        self.root.destroy()

    # ── Styles ─────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background=Style.BG, foreground=Style.TEXT)
        style.configure("TFrame", background=Style.BG)
        style.configure("Card.TFrame", background=Style.BG_CARD)
        style.configure("TLabel", background=Style.BG, foreground=Style.TEXT,
                         font=("Segoe UI", 9))
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"),
                         foreground=Style.RED)
        style.configure("Subtitle.TLabel", foreground=Style.TEXT_DIM,
                         font=("Segoe UI", 8))
        style.configure("Stat.TLabel", font=("Segoe UI", 9))
        style.configure("StatValue.TLabel", font=("Segoe UI", 11, "bold"),
                         foreground=Style.BLUE)
        style.configure("TEntry",
                         fieldbackground=Style.BG_LIGHT,
                         foreground=Style.TEXT,
                         insertcolor=Style.TEXT, borderwidth=0)
        style.configure("TNotebook", background=Style.BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                         background=Style.BG_LIGHT, foreground=Style.TEXT_DIM,
                         font=("Segoe UI", 9, "bold"), padding=(10, 4),
                         borderwidth=0)
        style.map("TNotebook.Tab",
                   background=[("selected", Style.BG_CARD)],
                   foreground=[("selected", Style.TEXT)])

    # ── UI Construction ────────────────────────────────────────

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        self._main_frame = main

        # Header
        header = tk.Frame(main, bg=Style.BG)
        header.pack(fill=tk.X, pady=(0, 5))

        header_row = tk.Frame(header, bg=Style.BG)
        header_row.pack(fill=tk.X)

        try:
            from PIL import Image, ImageTk
            logo_path = get_resource_path("pingmaker.png")
            if os.path.exists(logo_path):
                img = Image.open(logo_path).resize((32, 32), Image.Resampling.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(header_row, image=self._logo_img,
                         bg=Style.BG).pack(side=tk.LEFT, padx=(0, 8))
        except Exception:
            pass

        title_frame = tk.Frame(header_row, bg=Style.BG)
        title_frame.pack(side=tk.LEFT, fill=tk.X)
        tk.Label(title_frame, text="Pingmaker", font=("Segoe UI", 14, "bold"),
                 bg=Style.BG, fg=Style.RED).pack(anchor="w")
        tk.Label(title_frame, text="Latency compensation for Aion 2",
                 font=("Segoe UI", 8), bg=Style.BG,
                 fg=Style.TEXT_DIM).pack(anchor="w")

        # Notebook
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.X, pady=(3, 0))

        tab = tk.Frame(notebook, bg=Style.BG, padx=3, pady=3)
        notebook.add(tab, text="Pingmaker")

        # ── Uniform speed override ──
        uniform_frame = tk.Frame(tab, bg=Style.BG_CARD,
                                 highlightthickness=1,
                                 highlightbackground=Style.BORDER)
        uniform_frame.pack(fill=tk.X, pady=(5, 5))
        uniform_inner = tk.Frame(uniform_frame, bg=Style.BG_CARD, padx=10, pady=5)
        uniform_inner.pack(fill=tk.X)
        tk.Label(uniform_inner, text="Uniform Speed Override",
                 font=("Segoe UI", 9, "bold"), bg=Style.BG_CARD,
                 fg=Style.TEXT).pack(side=tk.LEFT)

        self._uniform_entry = tk.Entry(
            uniform_inner, textvariable=self.uniform_speed, font=("Consolas", 9),
            width=8, bg=Style.BG_LIGHT, fg=Style.TEXT,
            insertbackground=Style.TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=Style.BORDER,
            justify=tk.RIGHT)
        self._uniform_entry.pack(side=tk.RIGHT, padx=(8, 2))
        self._uniform_entry.bind('<FocusOut>', lambda e: self._save_settings())
        self._uniform_entry.bind('<Return>', lambda e: self._save_settings())

        tk.Label(uniform_inner, text="%", font=("Segoe UI", 8),
                 bg=Style.BG_CARD, fg=Style.TEXT_DIM).pack(side=tk.RIGHT)
        tk.Checkbutton(
            uniform_inner, text="Break Packet", font=("Segoe UI", 7),
            variable=self.uniform_break,
            bg=Style.BG_CARD, fg=Style.TEXT_DIM,
            activebackground=Style.BG_CARD, selectcolor=Style.BG_LIGHT,
            command=self._on_setting_changed
        ).pack(side=tk.RIGHT, padx=(6, 0))
        tk.Label(uniform_inner, text="blank=off", font=("Segoe UI", 7),
                 bg=Style.BG_CARD, fg=Style.TEXT_DIM).pack(side=tk.LEFT, padx=(6, 0))

        # ── Skills panel toggle button ──
        self._skills_btn = tk.Button(
            tab, text="Skills & Attack Speed >>", font=("Segoe UI", 9, "bold"),
            bg=Style.BG_CARD, fg=Style.TEXT,
            activebackground=Style.BG_LIGHT, activeforeground=Style.TEXT,
            relief=tk.FLAT, cursor="hand2",
            highlightthickness=1, highlightbackground=Style.BORDER,
            command=self._toggle_skills_panel)
        self._skills_btn.pack(fill=tk.X, ipady=4, pady=(0, 5))
        self._skills_panel_open = False

        # ── Start/Stop ──
        self._start_btn = tk.Button(
            tab, text="Start", font=("Segoe UI", 10, "bold"),
            bg=Style.RED, fg="#ffffff",
            activebackground=Style.RED_HOVER, activeforeground="#ffffff",
            relief=tk.FLAT, cursor="hand2", command=self._toggle_running)
        self._start_btn.pack(fill=tk.X, ipady=6, pady=(0, 5))

        # ── Status ──
        self._status_label = tk.Label(
            tab, text="Ready", font=("Segoe UI", 9),
            bg=Style.BG, fg=Style.TEXT_DIM)
        self._status_label.pack(pady=(0, 5))

        # ── Stats ──
        stats_frame = tk.Frame(tab, bg=Style.BG_CARD,
                               highlightthickness=1,
                               highlightbackground=Style.BORDER)
        stats_frame.pack(fill=tk.X, pady=(0, 5))
        stats_inner = ttk.Frame(stats_frame, style="Card.TFrame", padding=(10, 6))
        stats_inner.pack(fill=tk.X)
        stats_inner.columnconfigure(0, weight=1)
        stats_inner.columnconfigure(1, weight=1)

        left = ttk.Frame(stats_inner, style="Card.TFrame")
        left.grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="Packets Modified", style="Stat.TLabel",
                  background=Style.BG_CARD).pack(anchor="w")
        self._modified_label = ttk.Label(left, text="0", style="StatValue.TLabel",
                                         background=Style.BG_CARD)
        self._modified_label.pack(anchor="w")

        right = ttk.Frame(stats_inner, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="e")
        ttk.Label(right, text="Status", style="Stat.TLabel",
                  background=Style.BG_CARD).pack(anchor="e")
        self._status_label2 = ttk.Label(right, text="Ready", style="StatValue.TLabel",
                                         background=Style.BG_CARD)
        self._status_label2.pack(anchor="e")

        # ── Entity filtering ──
        entity_frame = tk.Frame(tab, bg=Style.BG_CARD,
                                highlightthickness=1,
                                highlightbackground=Style.BORDER)
        entity_frame.pack(fill=tk.X, pady=(0, 5))
        entity_inner = tk.Frame(entity_frame, bg=Style.BG_CARD, padx=10, pady=6)
        entity_inner.pack(fill=tk.X)
        tk.Label(entity_inner, text="Character Names",
                 font=("Segoe UI", 9, "bold"), bg=Style.BG_CARD,
                 fg=Style.TEXT).pack(anchor="w")
        tk.Label(entity_inner, text="comma-separated, for party filtering",
                 font=("Segoe UI", 7), bg=Style.BG_CARD,
                 fg=Style.TEXT_DIM).pack(anchor="w")
        tk.Entry(
            entity_inner, textvariable=self.char_names_var, font=("Segoe UI", 9),
            bg=Style.BG_LIGHT, fg=Style.TEXT, insertbackground=Style.TEXT,
            relief=tk.FLAT, highlightthickness=1, highlightcolor=Style.RED,
            highlightbackground=Style.BORDER
        ).pack(fill=tk.X, ipady=2, pady=(2, 2))
        self.char_names_var.trace('w', self._on_char_names_changed)
        self._entity_status = tk.Label(
            entity_inner, text="No filter active (modifies all players' packets)",
            font=("Segoe UI", 7), bg=Style.BG_CARD, fg=Style.TEXT_DIM)
        self._entity_status.pack(anchor="w")

        # ── Logging checkbox ──
        log_frame = tk.Frame(main, bg=Style.BG)
        log_frame.pack(fill=tk.X, pady=(3, 3))
        tk.Checkbutton(
            log_frame, text="Write tool action logs", variable=self.csv_logging,
            font=("Segoe UI", 8), bg=Style.BG, fg=Style.TEXT,
            activebackground=Style.BG, activeforeground=Style.TEXT,
            selectcolor=Style.BG_LIGHT, command=self._on_setting_changed
        ).pack(side=tk.LEFT)

        # ── Log text ──
        log_outer = ttk.Frame(main)
        log_outer.pack(fill=tk.BOTH, expand=True)
        self._log_text = tk.Text(
            log_outer, font=("Consolas", 8),
            bg=Style.BG_LIGHT, fg=Style.TEXT_DIM,
            relief=tk.FLAT, highlightthickness=1,
            highlightbackground=Style.BORDER, height=5)
        self._log_text.pack(fill=tk.BOTH, expand=True)
        self._log_text.configure(state=tk.DISABLED)

    # ── Skills fold-out panel ─────────────────────────────────

    def _toggle_skills_panel(self):
        if self._skills_panel_open:
            self._close_skills_panel()
        else:
            self._open_skills_panel()

    def _open_skills_panel(self):
        self._skills_panel_open = True
        self._skills_btn.config(text="<< Skills & Attack Speed")

        # Remember base width and expand
        self._base_width = self.root.winfo_width()
        base_h = self.root.winfo_height()
        panel_w = 320
        new_w = self._base_width + panel_w

        # Position the panel to the right of the main window
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{new_w}x{base_h}+{x}+{y}")

        # Create side panel frame
        self._skills_panel = tk.Frame(self.root, bg=Style.BG, width=panel_w)
        self._skills_panel.pack(side=tk.RIGHT, fill=tk.Y, before=self._main_frame)
        self._skills_panel.pack_propagate(False)

        panel_inner = tk.Frame(self._skills_panel, bg=Style.BG, padx=8, pady=8)
        panel_inner.pack(fill=tk.BOTH, expand=True)

        # Search
        search_header = tk.Frame(panel_inner, bg=Style.BG)
        search_header.pack(fill=tk.X, pady=(0, 3))
        tk.Label(search_header, text="Add Skills",
                 font=("Segoe UI", 9, "bold"), bg=Style.BG,
                 fg=Style.TEXT).pack(side=tk.LEFT)

        self._search_var = tk.StringVar()
        self._search_var.trace('w', self._on_search_changed)
        self._search_entry = tk.Entry(
            panel_inner, textvariable=self._search_var, font=("Segoe UI", 9),
            bg=Style.BG_LIGHT, fg=Style.TEXT, insertbackground=Style.TEXT,
            relief=tk.FLAT, highlightthickness=1, highlightcolor=Style.RED,
            highlightbackground=Style.BORDER)
        self._search_entry.pack(fill=tk.X, ipady=4, pady=(0, 3))

        self._results_frame = tk.Frame(panel_inner, bg=Style.BG_CARD)
        self._results_listbox = tk.Listbox(
            self._results_frame, font=("Segoe UI", 9),
            bg=Style.BG_CARD, fg=Style.TEXT,
            selectbackground=Style.RED, selectforeground=Style.TEXT,
            relief=tk.FLAT, highlightthickness=1,
            highlightbackground=Style.BORDER, height=5, activestyle='none')
        self._results_listbox.pack(fill=tk.X)
        self._results_listbox.bind('<Button-1>', self._on_result_click)
        self._results_listbox.bind('<Return>', self._on_result_click)

        # Skills list header
        skills_header = tk.Frame(panel_inner, bg=Style.BG)
        skills_header.pack(fill=tk.X, pady=(5, 3))
        tk.Label(skills_header, text="Skills & Attack Speed (%)",
                 font=("Segoe UI", 9, "bold"), bg=Style.BG,
                 fg=Style.TEXT).pack(side=tk.LEFT)
        tk.Label(skills_header, text="blank=skip", font=("Segoe UI", 7),
                 bg=Style.BG, fg=Style.TEXT_DIM).pack(side=tk.RIGHT)

        # Scrollable skills list
        skills_outer = tk.Frame(panel_inner, bg=Style.BG_CARD,
                                highlightthickness=1,
                                highlightbackground=Style.BORDER)
        skills_outer.pack(fill=tk.BOTH, expand=True)

        self._skills_canvas = tk.Canvas(skills_outer, bg=Style.BG_CARD,
                                        highlightthickness=0, bd=0)
        skills_scroll = tk.Scrollbar(skills_outer, orient=tk.VERTICAL,
                                     command=self._skills_canvas.yview)
        self._skills_inner = tk.Frame(self._skills_canvas, bg=Style.BG_CARD)
        self._skills_inner.bind("<Configure>",
            lambda e: self._skills_canvas.configure(
                scrollregion=self._skills_canvas.bbox("all")))
        self._skills_window = self._skills_canvas.create_window(
            (0, 0), window=self._skills_inner, anchor="nw")
        self._skills_canvas.configure(yscrollcommand=skills_scroll.set)
        self._skills_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        skills_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._skills_canvas.bind("<Configure>", self._on_canvas_resize)
        self._skills_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self._skills_inner.bind("<MouseWheel>", self._on_mousewheel)

        # Rebuild skill rows
        self._refresh_skill_list()

    def _close_skills_panel(self):
        self._skills_panel_open = False
        self._skills_btn.config(text="Skills & Attack Speed >>")

        # Sync speeds before destroying widgets, then clear row refs
        self._sync_speeds_from_ui()
        self._skill_rows.clear()

        if hasattr(self, '_skills_panel'):
            self._skills_panel.destroy()

        # Restore original width
        base_w = getattr(self, '_base_width', 380)
        base_h = self.root.winfo_height()
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{base_w}x{base_h}+{x}+{y}")

    def _on_canvas_resize(self, event):
        self._skills_canvas.itemconfig(self._skills_window, width=event.width)

    def _on_mousewheel(self, event):
        self._skills_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ── Logging ────────────────────────────────────────────────

    def _log(self, message: str):
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, message + "\n")
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _set_status(self, text: str, color: str = None):
        self._status_label.config(text=text, fg=color or Style.TEXT_DIM)

    # ── Event polling ──────────────────────────────────────────

    def _poll_events(self):
        """Process events from capture engine."""
        for _ in range(20):
            try:
                event_type, data = self._event_queue.get_nowait()
            except queue.Empty:
                break

            if event_type == 'log':
                self._log(data)
            elif event_type == 'error':
                self._log(f"ERROR: {data}")
                self._set_status(data, Style.RED)
            elif event_type == 'entity':
                self._update_entity_status()

        # Update stats
        self._modified_label.config(text=str(self.engine.modified_count))
        self._status_label2.config(
            text="Active" if self.is_running else "Ready")

        self.root.after(250, self._poll_events)

    def _poll_entity_status(self):
        self._update_entity_status()
        self.root.after(1000, self._poll_entity_status)

    def _update_entity_status(self):
        t = self.entity_tracker
        if not t.is_configured:
            self._entity_status.config(
                text="No filter active (modifies all players' packets)",
                fg=Style.TEXT_DIM)
        elif not t.has_any_keys():
            self._entity_status.config(
                text="Rezone or wait for name binding...", fg=Style.YELLOW)
        else:
            keys = t.get_keys()
            keys_str = ', '.join(str(k) for k in sorted(keys))
            self._entity_status.config(
                text=f"Filtering active \u2014 key {keys_str}", fg=Style.BLUE)

    # ── Skill search ───────────────────────────────────────────

    def _on_search_changed(self, *args):
        query = self._search_var.get()
        self._results_listbox.delete(0, tk.END)
        if len(query) < 2:
            self._results_frame.pack_forget()
            return
        results = fuzzy_search(query, self.skill_data.skills)
        if results:
            self._results_frame.pack(fill=tk.X, pady=(2, 0))
            for name in results:
                self._results_listbox.insert(tk.END, name)
        else:
            self._results_frame.pack_forget()

    def _on_result_click(self, event):
        sel = self._results_listbox.curselection()
        if sel:
            name = self._results_listbox.get(sel[0])
            self._add_skill(name)
            self._search_var.set("")
            self._results_frame.pack_forget()

    # ── Skill management ──────────────────────────────────────

    def _add_skill(self, name: str):
        if name in self.selected_skills or name not in self.skill_data.skills:
            return
        self.selected_skills[name] = {
            "ids": self.skill_data.skills[name],
            "attack_speed": None,
            "overflow": False,
        }
        self._add_skill_row(name)
        self._save_settings()
        if self.is_running:
            self._hot_reload()

    def _remove_skill(self, name: str):
        if name in self.selected_skills:
            del self.selected_skills[name]
            row = self._skill_rows.pop(name, None)
            if row:
                row['frame'].destroy()
            self._save_settings()
            if self.is_running:
                self._hot_reload()

    def _refresh_skill_list(self):
        if not hasattr(self, '_skills_inner'):
            return
        for row in self._skill_rows.values():
            row['frame'].destroy()
        self._skill_rows.clear()
        for name in self.selected_skills:
            self._add_skill_row(name)

    def _add_skill_row(self, name: str):
        data = self.selected_skills.get(name)
        if not data or not hasattr(self, '_skills_inner'):
            return

        row = tk.Frame(self._skills_inner, bg=Style.BG_CARD)
        row.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(row, text=name, font=("Segoe UI", 8), anchor="w",
                 bg=Style.BG_CARD, fg=Style.TEXT, width=20
                 ).pack(side=tk.LEFT, padx=(4, 6))

        speed_entry = tk.Entry(
            row, font=("Consolas", 8), width=7,
            bg=Style.BG_LIGHT, fg=Style.TEXT, insertbackground=Style.TEXT,
            relief=tk.FLAT, highlightthickness=1,
            highlightbackground=Style.BORDER, justify=tk.RIGHT)
        spd = data.get("attack_speed")
        if spd is not None:
            speed_entry.insert(0, str(spd))
        speed_entry.pack(side=tk.LEFT, padx=(0, 2))
        speed_entry.bind('<FocusOut>', lambda e: self._save_settings())
        speed_entry.bind('<Return>', lambda e: self._save_settings())
        speed_entry.bind("<MouseWheel>", self._on_mousewheel)

        tk.Label(row, text="%", font=("Segoe UI", 8),
                 bg=Style.BG_CARD, fg=Style.TEXT_DIM).pack(side=tk.LEFT)

        overflow_var = tk.BooleanVar(value=data.get("overflow", False))
        tk.Checkbutton(
            row, text="Break Packet", font=("Segoe UI", 7),
            variable=overflow_var,
            bg=Style.BG_CARD, fg=Style.TEXT_DIM,
            activebackground=Style.BG_CARD, selectcolor=Style.BG_LIGHT,
            command=self._on_setting_changed
        ).pack(side=tk.LEFT, padx=(6, 0))

        tk.Button(
            row, text="\u2715", font=("Segoe UI", 8, "bold"),
            bg=Style.BG_CARD, fg=Style.RED,
            activebackground=Style.RED, activeforeground="#ffffff",
            relief=tk.FLAT, width=2, cursor="hand2",
            command=lambda n=name: self._remove_skill(n)
        ).pack(side=tk.RIGHT, padx=4)

        for w in row.winfo_children():
            if w != speed_entry:
                w.bind("<MouseWheel>", self._on_mousewheel)

        self._skill_rows[name] = {
            'frame': row,
            'speed_entry': speed_entry,
            'overflow_var': overflow_var,
        }

    # ── Settings ───────────────────────────────────────────────

    def _on_setting_changed(self, *args):
        self._save_settings()
        if self.is_running:
            self._sync_logging_state()
            self._hot_reload()

    def _sync_logging_state(self):
        logs_dir = os.path.join(os.path.dirname(get_settings_path()), "logs")
        self.engine.set_logging(self.csv_logging.get(), logs_dir)

    def _on_char_names_changed(self, *args):
        names = [n.strip() for n in self.char_names_var.get().split(',')
                 if n.strip()]
        self.entity_tracker.update_names(names)
        self._update_entity_status()
        self._save_settings()

    def _sync_speeds_from_ui(self):
        for name, row in self._skill_rows.items():
            if name not in self.selected_skills:
                continue
            entry = row.get('speed_entry')
            if entry:
                try:
                    text = entry.get().strip()
                except tk.TclError:
                    text = ''
                if text == '':
                    self.selected_skills[name]['attack_speed'] = None
                else:
                    try:
                        self.selected_skills[name]['attack_speed'] = int(text)
                    except ValueError:
                        self.selected_skills[name]['attack_speed'] = None
            ovf = row.get('overflow_var')
            if ovf is not None:
                self.selected_skills[name]['overflow'] = ovf.get()

    def _parse_uniform_speed(self) -> int | None:
        text = self.uniform_speed.get().strip()
        if text == '':
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def _build_speed_lookup(self) -> dict:
        """Build speed lookup: skill_id -> (encoded, length, pct, break)."""
        uniform = self._parse_uniform_speed()
        uniform_brk = self.uniform_break.get()
        lookup = {}

        # Uniform override applies to all known skills
        if uniform is not None and isinstance(uniform, int) and uniform > 0:
            encoded = encode_varint(uniform * 100)
            entry = (encoded, len(encoded), uniform, uniform_brk)
            for sid in self.skill_data.all_ids:
                lookup[sid] = entry

        # Per-skill overrides take precedence
        for name, data in self.selected_skills.items():
            spd = data.get("attack_speed")
            if spd is None or not isinstance(spd, int) or spd < 0:
                continue
            brk = data.get("overflow", False)
            encoded = encode_varint(spd * 100)
            entry = (encoded, len(encoded), spd, brk)
            for sid in data["ids"]:
                lookup[sid] = entry

        return lookup

    def _build_target_ids(self) -> tuple[set, set]:
        """Compute target skill IDs and their first bytes for scanning."""
        uniform = self._parse_uniform_speed()
        if uniform is not None:
            target_ids = set(self.skill_data.all_ids)
        else:
            target_ids = set()
            for data in self.selected_skills.values():
                target_ids.update(data["ids"])

        first_bytes = {sid & 0xFF for sid in target_ids}
        return target_ids, first_bytes

    def _hot_reload(self):
        """Update capture engine speed config without restart."""
        self._sync_speeds_from_ui()
        lookup = self._build_speed_lookup()
        target_ids, first_bytes = self._build_target_ids()
        self.engine.update_speed_lookup(lookup, target_ids, first_bytes)

    def _load_settings(self):
        self._loading_settings = True
        try:
            settings = load_settings()
            saved = settings.get('skills', {})
            if isinstance(saved, dict):
                for name, sdata in saved.items():
                    if name in self.skill_data.skills:
                        if isinstance(sdata, dict):
                            self.selected_skills[name] = {
                                "ids": self.skill_data.skills[name],
                                "attack_speed": sdata.get("attack_speed"),
                                "overflow": bool(sdata.get("overflow", False)),
                            }
                        else:
                            self.selected_skills[name] = {
                                "ids": self.skill_data.skills[name],
                                "attack_speed": None, "overflow": False,
                            }
            self._refresh_skill_list()
            self.csv_logging.set(settings.get('csv_logging_enabled', False))
            self.char_names_var.set(settings.get('character_names', ''))
            uniform = settings.get('uniform_speed')
            self.uniform_speed.set('' if uniform is None else str(uniform))
            self.uniform_break.set(settings.get('uniform_break', False))
        finally:
            self._loading_settings = False

    def _save_settings(self):
        if self._loading_settings:
            return
        try:
            self._sync_speeds_from_ui()
            skills_dict = {}
            for name, data in self.selected_skills.items():
                sd = {"attack_speed": data.get("attack_speed")}
                if data.get("overflow"):
                    sd["overflow"] = True
                skills_dict[name] = sd
            settings = {
                'settings_version': 2,
                'skills': skills_dict,
                'csv_logging_enabled': self.csv_logging.get(),
                'character_names': self.char_names_var.get(),
                'uniform_speed': self._parse_uniform_speed(),
                'uniform_break': self.uniform_break.get(),
            }
            save_settings(settings)
        except Exception as e:
            self._log(f"Settings save error: {e}")

    # ── Capture control ───────────────────────────────────────

    def _toggle_running(self):
        if self.is_running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        self._sync_speeds_from_ui()
        lookup = self._build_speed_lookup()
        target_ids, first_bytes = self._build_target_ids()

        active = sum(1 for d in self.selected_skills.values()
                     if d.get("attack_speed") is not None)
        self._log(f"Starting with {len(self.selected_skills)} skills "
                  f"({active} with speed override)")

        # Start packet logging only when enabled
        self._sync_logging_state()

        # Switch to intercept mode
        self.engine.set_intercepting(True, lookup, target_ids, first_bytes)

        self.is_running = True
        self._start_btn.config(text="Stop", bg=Style.BLUE, fg="#ffffff")
        self._set_status("Active", Style.BLUE)

    def _stop_capture(self):
        self.engine.set_intercepting(False)
        self.engine.set_logging(False)
        self.is_running = False
        self._start_btn.config(text="Start", bg=Style.RED, fg="#ffffff")
        self._set_status("Stopped", Style.TEXT_DIM)
        self._log("Stopped")

