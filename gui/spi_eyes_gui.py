"""SPI-Eyes GUI -- a zero-dependency (tkinter) dashboard over the engine.

Run:  python gui/spi_eyes_gui.py

Design intent: the honesty is the product. Most firmware is unverifiable, so most rows
render as honest GREY (CANNOT-VERIFY) -- earned GREEN is rare and never faked. The UI
must never let a user mistake "we couldn't look" for "you're clean."
"""
from __future__ import annotations

import os
import queue
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from capability_probe.aggregate import compute_ceiling
from capability_probe.inventory import enumerate_components, summarize
from capability_probe.probes import run_all
from corpus.index import CorpusIndex

# Catppuccin-ish dark palette
C = {
    "bg": "#14141b", "panel": "#1e1e2e", "text": "#cdd6f4", "sub": "#a6adc8",
    "accent": "#89b4fa", "green": "#a6e3a1", "red": "#f38ba8", "grey": "#6c7086",
    "dark": "#45475a", "yellow": "#f9e2af", "row": "#181825", "rowalt": "#1e1e2e",
}
VERDICT_COLOR = {
    "CLEAN": C["green"], "CLEAN(Above-SMM)": C["green"], "REF-AVAILABLE": C["accent"],
    "ANOMALOUS": C["red"], "CANNOT-VERIFY": C["grey"], "CANNOT-ENUMERATE": C["dark"],
    "NOT-ASSESSED": C["dark"], "OUT-OF-SCOPE": C["dark"],
}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self.identity = {}
        root.title("SPI-Eyes — Firmware Integrity")
        root.configure(bg=C["bg"])
        root.geometry("980x620")
        self._style()
        self._build()
        root.after(80, self._poll)

    # ---- styling -----------------------------------------------------------------
    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", background=C["row"], fieldbackground=C["row"],
                    foreground=C["text"], rowheight=26, borderwidth=0)
        s.configure("Treeview.Heading", background=C["panel"], foreground=C["accent"],
                    borderwidth=0, font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", C["dark"])])

    def _build(self):
        top = tk.Frame(self.root, bg=C["bg"])
        top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="SPI-Eyes", font=("Segoe UI", 20, "bold"),
                 bg=C["bg"], fg=C["accent"]).pack(side="left")
        tk.Label(top, text="  firmware integrity — honest by design",
                 font=("Segoe UI", 10), bg=C["bg"], fg=C["sub"]).pack(side="left", pady=(8, 0))

        bar = tk.Frame(self.root, bg=C["bg"])
        bar.pack(fill="x", padx=16, pady=4)
        self.buttons = []
        for txt, cmd in [("Scan Machine", self.scan), ("Firmware Surface", self.surface),
                         ("Corpus", self.corpus), ("Check Dump…", self.check)]:
            b = tk.Button(bar, text=txt, command=cmd, bg=C["panel"], fg=C["text"],
                          activebackground=C["dark"], activeforeground=C["text"],
                          relief="flat", padx=14, pady=7, font=("Segoe UI", 10), bd=0,
                          highlightthickness=0, cursor="hand2")
            b.pack(side="left", padx=(0, 8))
            self.buttons.append(b)

        self.summary = tk.Label(self.root, text="Pick an action.", anchor="w", justify="left",
                                bg=C["bg"], fg=C["text"], font=("Segoe UI", 10), wraplength=940)
        self.summary.pack(fill="x", padx=16, pady=(6, 4))

        # legend
        leg = tk.Frame(self.root, bg=C["bg"])
        leg.pack(fill="x", padx=16)
        for label, col in [("earned green (verified)", C["green"]), ("ref-available", C["accent"]),
                           ("ANOMALOUS", C["red"]), ("CANNOT-VERIFY (blind)", C["grey"]),
                           ("CANNOT-ENUMERATE", C["dark"])]:
            f = tk.Frame(leg, bg=C["bg"])
            f.pack(side="left", padx=(0, 14))
            tk.Label(f, text="●", fg=col, bg=C["bg"], font=("Segoe UI", 11)).pack(side="left")
            tk.Label(f, text=label, fg=C["sub"], bg=C["bg"], font=("Segoe UI", 9)).pack(side="left")

        wrap = tk.Frame(self.root, bg=C["bg"])
        wrap.pack(fill="both", expand=True, padx=16, pady=10)
        self.tree = ttk.Treeview(wrap, columns=("c1", "c2", "c3"), show="headings", height=16)
        for cid, w in (("c1", 170), ("c2", 340), ("c3", 430)):
            self.tree.column(cid, width=w, anchor="w")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        for tag, col in VERDICT_COLOR.items():
            self.tree.tag_configure(tag, foreground=col)

        self.status = tk.Label(self.root, text="ready", anchor="w", bg=C["panel"],
                               fg=C["sub"], font=("Segoe UI", 9), padx=10, pady=4)
        self.status.pack(fill="x", side="bottom")

    # ---- async plumbing ----------------------------------------------------------
    def _poll(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _busy(self, on: bool, msg: str = ""):
        for b in self.buttons:
            b.configure(state="disabled" if on else "normal")
        self.status.configure(text=msg or "ready")

    def _run(self, work, done):
        self._busy(True, "working…")
        def bg():
            try:
                res = work()
                self.q.put(lambda: (done(res), self._busy(False, "done")))
            except Exception as e:                                   # noqa: BLE001
                self.q.put(lambda: (self._busy(False, "error"),
                                    messagebox.showerror("SPI-Eyes", str(e))))
        threading.Thread(target=bg, daemon=True).start()

    def _reset(self, headings):
        self.tree.delete(*self.tree.get_children())
        for cid, txt in zip(("c1", "c2", "c3"), headings):
            self.tree.heading(cid, text=txt)

    # ---- actions -----------------------------------------------------------------
    def scan(self):
        def work():
            evs = run_all()
            return evs, compute_ceiling(evs)
        def done(res):
            evs, ceiling = res
            self._reset(("Verdict", "Probe", "Finding"))
            for e in evs:
                v = e.verdict.value
                self.tree.insert("", "end", values=(v, e.probe, e.finding),
                                 tags=(v if v in VERDICT_COLOR else "CANNOT-VERIFY",))
            self.identity = next((e.detail for e in evs if e.probe == "machine_identity"), {})
            self.summary.configure(
                text=f"EVIDENCE CEILING: {ceiling.verdict.value}  —  {ceiling.scope}",
                fg=VERDICT_COLOR.get(ceiling.verdict.value.split("(")[0], C["text"]))
        self._run(work, done)

    def surface(self):
        def work():
            comps = enumerate_components()
            return comps, summarize(comps)
        def done(res):
            comps, s = res
            self._reset(("Coverage", "Store", "Component"))
            for c in comps:
                self.tree.insert("", "end", values=(c.coverage, c.store, c.name),
                                 tags=(c.coverage if c.coverage in VERDICT_COLOR else "CANNOT-VERIFY",))
            self.summary.configure(
                text=(f"{s['total']} firmware-bearing chips — {s['ref_available']} reference-available, "
                      f"{s['cannot_verify']} CANNOT-VERIFY (blind), {s['cannot_enumerate']} "
                      f"CANNOT-ENUMERATE. Fail-closed: nothing silently skipped."), fg=C["text"])
        self._run(work, done)

    def corpus(self):
        def work():
            idx = CorpusIndex()
            return idx.all_entries(), idx.coverage()
        def done(res):
            entries, cov = res
            self._reset(("Tier", "Reference (vendor / model / version)", "Modules"))
            for e in entries:
                what = f"{e.code_modules} modules" if e.kind == "modules" else f"blob [{e.component or 'chip'}]"
                tag = "REF-AVAILABLE" if e.tier in ("vendor-signed", "coreboot-reproducible") else "CANNOT-VERIFY"
                self.tree.insert("", "end", values=(e.tier, f"{e.vendor} / {e.model} / {e.version}", what),
                                 tags=(tag,))
            self.summary.configure(text=f"Corpus: {cov['entries']} references, "
                                        f"{cov['models']} models, {cov['vendors']} vendors.", fg=C["text"])
        self._run(work, done)

    def check(self):
        path = filedialog.askopenfilename(title="Select a firmware image / SPI dump",
                                          filetypes=[("Firmware", "*.bin *.fd *.rom *.cap"), ("All", "*.*")])
        if not path:
            return
        d = self.identity
        vendor = simpledialog.askstring("Check", "Vendor:", initialvalue=d.get("Vendor", ""))
        model = simpledialog.askstring("Check", "Model:", initialvalue=d.get("Model", ""))
        version = simpledialog.askstring("Check", "BIOS version:", initialvalue=d.get("BIOSVersion", ""))
        if not (vendor and model and version):
            return
        read = messagebox.askyesno("Read source",
                                   "Was this an EXTERNAL (off-CPU) read?\n\n"
                                   "Yes = external (trustworthy, CLEAN-capable)\n"
                                   "No  = software/internal (blindable → CANNOT-VERIFY)")

        def work():
            from corpus.manifest import build_image_manifest, load_manifest, match_manifest
            idx = CorpusIndex()
            e = idx.lookup(vendor, model, version)
            if not e:
                return ("no-ref", idx.versions_for(vendor, model))
            with open(path, "rb") as fh:
                data = fh.read()
            r = match_manifest(build_image_manifest(data), load_manifest(e.path))
            return ("result", r, read)
        def done(res):
            if res[0] == "no-ref":
                self.summary.configure(
                    text=f"No reference for {vendor} {model} {version} (have: {res[1] or 'none'}). "
                         f"Verdict: CANNOT-VERIFY — submit this version's manifest.", fg=C["grey"])
                messagebox.showinfo("SPI-Eyes", "No exact-version reference → CANNOT-VERIFY (never a cross-version match).")
                return
            _, r, ext = res
            self._reset(("Result", "Count", "Detail"))
            self.tree.insert("", "end", values=("matched", f"{r.matched}/{r.code_total_ref}", ""), tags=("REF-AVAILABLE",))
            for x in r.mismatched[:50]:
                self.tree.insert("", "end", values=("MISMATCH", "", x["guid"]), tags=("ANOMALOUS",))
            for x in r.missing[:50]:
                self.tree.insert("", "end", values=("MISSING", "", x["guid"]), tags=("ANOMALOUS",))
            for x in r.extra[:50]:
                self.tree.insert("", "end", values=("EXTRA", "", x["guid"]), tags=("ANOMALOUS",))
            if not r.all_code_matched:
                verdict, col = f"ANOMALOUS — {r.anomalies} deviation(s)", C["red"]
            elif ext and r.clean_capable_tier:
                verdict, col = "CLEAN (Above-SMM) — full match, external read, clean-capable reference", C["green"]
            elif ext:
                verdict, col = f"CONTENT-MATCH — full match, but tier '{r.trust_tier}' is not clean-capable", C["yellow"]
            else:
                verdict, col = "CANNOT-VERIFY — content matches, but a software read is blindable", C["grey"]
            self.summary.configure(text="VERDICT: " + verdict, fg=col)
        self._run(work, done)


def main() -> int:
    root = tk.Tk()
    app = App(root)
    if "--smoke" in sys.argv:                # construction test, no mainloop
        root.update()
        root.destroy()
        print("smoke ok")
        return 0
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
