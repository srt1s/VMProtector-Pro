import sys
import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from protector_core import VMProtectorCore

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class VMProtectorGUI(ctk.CTk):
    """
    YATAY BİLGİSAYAR EKRANI DÜZENİ (LANDSCAPE WIDESCREEN 1400 x 650)
    2 Sütunlu Yan Yana Düzen -> Asla Telefon Ekranı Gibi Dikey Olmaz!
    """
    def __init__(self):
        super().__init__()

        self.title("VMProtector Pro - Landscape Widescreen")
        self.geometry("1400 x 650")
        self.resizable(True, True)

        self._anim_running = False
        self._build_ui()

    def _build_ui(self):
        # 1. Header (Üst Geniş Banner)
        header = ctk.CTkFrame(self, fg_color="#1E1E2E", corner_radius=10)
        header.pack(fill="x", padx=20, pady=(15, 10))

        title = ctk.CTkLabel(
            header, 
            text="🛡️ VMPROTECTOR PRO", 
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#89B4FA"
        )
        title.pack(anchor="w", padx=20, pady=12)

        # 2. YATAY 2 SÜTUNLU ANA GÖVDE (YAN YANA DÜZEN)
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # --- SOL KOLON (KONTROL VE AYARLAR) ---
        left_col = ctk.CTkFrame(body, corner_radius=10, width=540)
        left_col.pack(side="left", fill="both", expand=False, padx=(0, 10))

        # Dosya Seçimi
        f_title = ctk.CTkLabel(left_col, text="Dosya Seçimi:", font=ctk.CTkFont(size=14, weight="bold"))
        f_title.pack(anchor="w", padx=15, pady=(15, 5))

        f_box = ctk.CTkFrame(left_col, fg_color="transparent")
        f_box.pack(fill="x", padx=15, pady=5)

        self.file_entry = ctk.CTkEntry(f_box, placeholder_text="Korunacak dosyayı seçiniz...", height=38)
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        browse_btn = ctk.CTkButton(f_box, text="Seç", width=90, height=38, command=self.browse_file)
        browse_btn.pack(side="right")

        # Koruma Seçenekleri
        o_title = ctk.CTkLabel(left_col, text="Seçenekler:", font=ctk.CTkFont(size=14, weight="bold"))
        o_title.pack(anchor="w", padx=15, pady=(15, 5))

        chk_box = ctk.CTkFrame(left_col, fg_color="transparent")
        chk_box.pack(fill="x", padx=15, pady=5)

        self.chk_opcode = ctk.CTkCheckBox(chk_box, text="Dinamik Opcode")
        self.chk_opcode.select()
        self.chk_opcode.pack(anchor="w", pady=5)

        self.chk_antidebug = ctk.CTkCheckBox(chk_box, text="Anti-Debug Koruması")
        self.chk_antidebug.select()
        self.chk_antidebug.pack(anchor="w", pady=5)

        # Başlat Butonu & Animasyonlu Yükleme Barı
        self.action_btn = ctk.CTkButton(
            left_col, 
            text="⚡ DOSYAYI KORU VE DERLE (.EXE)", 
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#A6E3A1",
            hover_color="#94E2D5",
            text_color="#11111B",
            height=45,
            border_width=0,
            corner_radius=8,
            command=self.start_protection_thread
        )
        self.action_btn.pack(fill="x", padx=15, pady=(25, 10))

        self.progress_bar = ctk.CTkProgressBar(left_col, height=10)
        self.progress_bar.set(0.0)
        self.progress_bar.pack(fill="x", padx=15, pady=(0, 15))

        # --- SAĞ KOLON (GENİŞ KONSOL LOG EKRANI) ---
        right_col = ctk.CTkFrame(body, corner_radius=10)
        right_col.pack(side="right", fill="both", expand=True, padx=0)

        l_title = ctk.CTkLabel(right_col, text="İşlem Günlüğü:", font=ctk.CTkFont(size=14, weight="bold"))
        l_title.pack(anchor="w", padx=15, pady=(15, 5))

        self.log_textbox = ctk.CTkTextbox(right_col, font=ctk.CTkFont(family="Consolas", size=13))
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.log("Hazır. Sol taraftan dosyanızı seçip başlatınız.")

    def log(self, msg: str):
        self.log_textbox.insert("end", msg + "\n")
        self.log_textbox.see("end")

    def update_progress(self, val: float):
        """İlerleme çubuğunu günceller"""
        self.progress_bar.set(val)

    def browse_file(self):
        fpath = filedialog.askopenfilename(title="Dosya Seçin")
        if fpath:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, fpath)

    def start_protection_thread(self):
        target_path = self.file_entry.get().strip()
        if not target_path or not os.path.exists(target_path):
            messagebox.showerror("Hata", "Geçerli bir dosya seçiniz!")
            return

        self.action_btn.configure(state="disabled", text="⏳ Korunuyor...")
        self.progress_bar.set(0.0)

        threading.Thread(target=self._protect_process, args=(target_path,), daemon=True).start()

    def _protect_process(self, target_path: str):
        try:
            self.log(f"İşlem Başlatıldı: {os.path.basename(target_path)}")
            output_dir = os.path.dirname(os.path.abspath(target_path))
            base_name, _ = os.path.splitext(os.path.basename(target_path))
            output_path = os.path.join(output_dir, f"{base_name}_protected.exe")

            protector = VMProtectorCore(
                anti_debug=bool(self.chk_antidebug.get()),
                randomize_keys=bool(self.chk_opcode.get())
            )

            # Gerçek zamanlı ilerleme callback'i
            cb = lambda val: self.after(0, lambda: self.update_progress(val))

            res_file = protector.protect_file(target_path, output_path, progress_callback=cb)
            self.log(f"✅ Tamamlandı: {res_file}")
            messagebox.showinfo("Başarılı", f"Korumalı Dosya Oluşturuldu:\n{res_file}")

        except Exception as e:
            self.log(f"❌ Hata: {e}")
            messagebox.showerror("Hata", f"İşlem başarısız:\n{e}")

        finally:
            self.after(0, lambda: self.action_btn.configure(state="normal", text="⚡ DOSYAYI KORU VE DERLE (.EXE)"))

SimpleVMProtectorGUI = VMProtectorGUI

if __name__ == "__main__":
    app = VMProtectorGUI()
    app.mainloop()
