from tkinter import messagebox, filedialog
import customtkinter as ctk
from PIL import Image, ImageTk
import json
import os

from log_parser import parse_log_file
from ip_analyzer import count_check, osint_check, subnet_check
from attack_analysis import detect_sql_injection, brute_force, off_hours

SETTINGS_FILE = "config/settings.json"

class KrosisApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Krosis")
        self.root.geometry("1000x800")
        self.root.config(bg="#1A1A1A")

        self.settings = {
            "ip_count_threshold_5": 5,
            "ip_count_threshold_10": 10,
            "ip_count_threshold_20": 20,
            "abuse_score_threshold": 40,
            "subnet_threshold": 3,
            "brute_force_threshold": 5,
            "work_days_start": 4,
            "work_days_end": 6,
        }

        self.log_data = []
        self.load_settings()
        self.setup_gui()
        self.setup_gif_animation()

    def setup_gui(self):
        #gui settings
        self.tabs = ctk.CTkTabview(self.root, bg_color="#1A1A1A", fg_color="#1A1A1A")
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        #tab creation
        self.setup_home_tab()
        self.setup_ip_analyzer_tab()
        self.setup_attack_analyzer_tab()
        self.setup_config_tab()
        self.tabs.set("Home")

    def setup_home_tab(self):
        #tab settings
        self.tabs.add("Home")
        self.home_tab = self.tabs.tab("Home")

        welcome_message = ctk.CTkLabel(self.home_tab, font=('Hubballi', 80),
                                     text="Welcome to Krosis.")
        welcome_message.pack(pady=(50, 10))

        sub_welcome = ctk.CTkLabel(self.home_tab, font=('Hubballi', 20),
                                 text="Where attackers have no aura.")
        sub_welcome.pack(pady=(0, 30))

    def setup_ip_analyzer_tab(self):
        #tab settings
        self.tabs.add("IP Analyzer")
        self.ip_analyzer_tab = self.tabs.tab("IP Analyzer")

        title = ctk.CTkLabel(self.ip_analyzer_tab, text="IP Analysis Features", 
                           font=('Hubballi', 24))
        title.pack(pady=20)

        #button creations
        button_frame = ctk.CTkFrame(self.ip_analyzer_tab, fg_color="#1A1A1A")
        button_frame.pack(pady=20, padx=20, fill="x")

        count_btn = ctk.CTkButton(button_frame, text="IP Count Analysis",
                                command=self.run_count_check,
                                font=('Hubballi', 16), 
                                height=40, 
                                fg_color="#ACACAC", 
                                text_color="#000000")
        count_btn.pack(pady=10, padx=20, fill="x")

        osint_btn = ctk.CTkButton(button_frame, text="OSINT Analysis",
                                command=self.run_osint_check,
                                font=('Hubballi', 16), height=40, 
                                fg_color="#ACACAC", 
                                text_color="#000000")
        osint_btn.pack(pady=10, padx=20, fill="x")

        subnet_btn = ctk.CTkButton(button_frame, text="Subnet Analysis",
                                 command=self.run_subnet_check,
                                 font=('Hubballi', 16), 
                                 height=40,
                                 fg_color="#ACACAC", 
                                 text_color="#000000")
        subnet_btn.pack(pady=10, padx=20, fill="x")

    def setup_attack_analyzer_tab(self):
        #tab settings
        self.tabs.add("Attack Analyzer")
        self.attack_analyzer_tab = self.tabs.tab("Attack Analyzer")

        title = ctk.CTkLabel(self.attack_analyzer_tab, text="Attack Detection Tools", 
                           font=('Hubballi', 24))
        title.pack(pady=20)

        #button creations
        button_frame = ctk.CTkFrame(self.attack_analyzer_tab, fg_color="#1A1A1A")
        button_frame.pack(pady=20, padx=20, fill="x")

        sql_btn = ctk.CTkButton(button_frame, text="SQL Injection Detection",
                              command=self.run_sql_injection_check,
                              font=('Hubballi', 16), 
                              height=40,
                              fg_color="#ACACAC", 
                              text_color="#000000")
        sql_btn.pack(pady=10, padx=20, fill="x")

        brute_btn = ctk.CTkButton(button_frame, text="Brute Force Detection",
                                command=self.run_brute_force_check,
                                font=('Hubballi', 16), 
                                height=40,
                                fg_color="#ACACAC", 
                                text_color="#000000")
        brute_btn.pack(pady=10, padx=20, fill="x")

        hours_btn = ctk.CTkButton(button_frame, text="Off-Hours Activity Detection",
                                command=self.run_off_hours_check,
                                font=('Hubballi', 16), 
                                height=40,
                                fg_color="#ACACAC", 
                                text_color="#000000")
        hours_btn.pack(pady=10, padx=20, fill="x")

    def setup_config_tab(self):
        #page settings
        self.tabs.add("Config")
        self.config_tab = self.tabs.tab("Config")

        title = ctk.CTkLabel(self.config_tab, text="Configuration Settings", 
                           font=('Hubballi', 24))
        title.pack(pady=20)

        scroll_frame = ctk.CTkScrollableFrame(self.config_tab, width=600, height=500)
        scroll_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ip_frame = ctk.CTkFrame(scroll_frame)
        ip_frame.pack(pady=10, padx=10, fill="x")

        ip_title = ctk.CTkLabel(ip_frame, text="IP Analysis Thresholds", 
                              font=('Hubballi', 18))
        ip_title.pack(pady=10)

        #ip thresholds
        self.create_setting_entry(ip_frame, "IP Count Threshold (Low)", "ip_count_threshold_5")
        self.create_setting_entry(ip_frame, "IP Count Threshold (Medium)", "ip_count_threshold_10")
        self.create_setting_entry(ip_frame, "IP Count Threshold (High)", "ip_count_threshold_20")
        self.create_setting_entry(ip_frame, "Abuse Score Threshold", "abuse_score_threshold")
        self.create_setting_entry(ip_frame, "Subnet Threshold", "subnet_threshold")

        attack_frame = ctk.CTkFrame(scroll_frame)
        attack_frame.pack(pady=10, padx=10, fill="x")

        attack_title = ctk.CTkLabel(attack_frame, text="Attack Detection Thresholds", 
                                  font=('Hubballi', 18))
        attack_title.pack(pady=10)

        #attack analysis thresholds
        self.create_setting_entry(attack_frame, "Brute Force Threshold", "brute_force_threshold")
        self.create_setting_entry(attack_frame, "Work Days Start", "work_days_start")
        self.create_setting_entry(attack_frame, "Work Days End", "work_days_end")

        button_frame = ctk.CTkFrame(scroll_frame)
        button_frame.pack(pady=20, padx=10, fill="x")

        save_btn = ctk.CTkButton(button_frame, text="Save Settings",
                               command=self.save_settings,
                               font=('Hubballi', 16),
                               fg_color="#ACACAC", 
                               text_color="#000000")
        save_btn.pack(side="left", padx=10)

        reset_btn = ctk.CTkButton(button_frame, text="Reset to Defaults",
                                command=self.reset_settings,
                                font=('Hubballi', 16),
                                fg_color="#ACACAC", 
                                text_color="#000000")
        reset_btn.pack(side="right", padx=10)

    def create_setting_entry(self, parent, label_text, setting_key):
        frame = ctk.CTkFrame(parent)
        frame.pack(pady=5, padx=10, fill="x")

        label = ctk.CTkLabel(frame, text=label_text, font=('Hubballi', 14))
        label.pack(side="left", padx=10)

        entry = ctk.CTkEntry(frame, width=100)
        entry.pack(side="right", padx=10)
        entry.insert(0, str(self.settings[setting_key]))

        # Store reference for later access
        if not hasattr(self, 'setting_entries'):
            self.setting_entries = {}
        self.setting_entries[setting_key] = entry
    
    def setup_gif_animation(self):
        self.gif_frames = self.load_gif_frames("/Users/churro/Desktop/python/krosis/data/angy.gif")
        self.current_frame = 0

        self.gif_label = ctk.CTkLabel(self.home_tab, text="")
        self.gif_label.pack(pady=20)

        load_button = ctk.CTkButton(self.home_tab, text="Load Log File", 
                                  command=self.load_log_file,
                                  font=('Hubballi', 16),
                                  fg_color="#ACACAC", 
                                  text_color="#000000")
        load_button.pack(pady=10)

        self.log_status = ctk.CTkLabel(self.home_tab, text="No log file loaded", 
                                     font=('Hubballi', 14))
        self.log_status.pack(pady=5)

        self.animate_gif()

    def load_gif_frames(self, gif_path, size=(200, 200)):
        try:
            gif = Image.open(gif_path)
            frames = []
            try:
                while True:
                    frame = gif.copy()
                    frame = frame.resize(size)
                    frames.append(ctk.CTkImage(light_image=frame, dark_image=frame, size=size))
                    gif.seek(gif.tell() + 1)
            except EOFError:
                pass
            return frames
        except Exception as e:
            print(f"Error loading gif: {e}")
            return []

    def animate_gif(self):
        if self.gif_frames:
            self.gif_label.configure(image=self.gif_frames[self.current_frame])
            self.current_frame = (self.current_frame + 1) % len(self.gif_frames)
        self.root.after(25, self.animate_gif)

    def load_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Apache Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                self.log_data = parse_log_file(file_path)
                self.log_status.configure(text=f"Loaded {len(self.log_data)} log entries")
                messagebox.showinfo("Success", f"Successfully loaded {len(self.log_data)} log entries")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load log file: {str(e)}")

    def show_result_popup(self, title, results):
        popup = ctk.CTkToplevel(self.root)
        popup.title(title)
        popup.geometry("800x600")
        popup.transient(self.root)
        popup.grab_set()

        title_label = ctk.CTkLabel(popup, text=title, font=('Hubballi', 20))
        title_label.pack(pady=10)

        text_box = ctk.CTkTextbox(popup, width=750, height=500)
        text_box.pack(pady=10, padx=20, fill="both", expand=True)

        #this checks the type of data that is being returned from the functions and puts it into the textbox regardless of type (thanks stackoverflow)
        if isinstance(results, dict):
            for key, value in results.items():
                text_box.insert("end", f"{key}: {value}\n")
        elif isinstance(results, list):
            for item in results:
                text_box.insert("end", f"{item}\n")
        else:
            text_box.insert("end", str(results))

        close_btn = ctk.CTkButton(popup, text="Close", command=popup.destroy)
        close_btn.pack(pady=10)

    def run_count_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = count_check(self.log_data, 
                                self.settings["ip_count_threshold_5"],
                                self.settings["ip_count_threshold_10"],
                                self.settings["ip_count_threshold_20"])
            self.show_result_popup("IP Count Analysis Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def run_osint_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = osint_check(self.log_data, self.settings["abuse_score_threshold"])
            self.show_result_popup("OSINT Analysis Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def run_subnet_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = subnet_check(self.log_data, self.settings["subnet_threshold"])
            self.show_result_popup("Subnet Analysis Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def run_sql_injection_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = detect_sql_injection(self.log_data)
            self.show_result_popup("SQL Injection Detection Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def run_brute_force_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = brute_force(self.log_data, self.settings["brute_force_threshold"])
            self.show_result_popup("Brute Force Detection Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def run_off_hours_check(self):
        if not self.log_data:
            messagebox.showwarning("Warning", "Please load a log file first")
            return

        try:
            results = off_hours(self.log_data, 
                                              self.settings["work_days_start"],
                                              self.settings["work_days_end"])
            self.show_result_popup("Off-Hours Activity Detection Results", results)
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")

    def save_settings(self):
        try:
            for key, entry in self.setting_entries.items():
                value = entry.get()
                if value.isdigit():
                    self.settings[key] = int(value)
                else:
                    messagebox.showerror("Error", f"Invalid value for {key}: {value}")
                    return

            with open(SETTINGS_FILE, 'w') as f:
                json.dump(self.settings, f, indent=2)

            messagebox.showinfo("Success", "Settings saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def load_settings(self):
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r') as f:
                    loaded_settings = json.load(f)
                    self.settings.update(loaded_settings)
        except Exception as e:
            print(f"Error loading settings: {e}")

    def reset_settings(self):
        self.settings = {
            "ip_count_threshold_5": 5,
            "ip_count_threshold_10": 10,
            "ip_count_threshold_20": 20,
            "abuse_score_threshold": 40,
            "subnet_threshold": 3,
            "brute_force_threshold": 5,
            "work_days_start": 4,
            "work_days_end": 6,
        }

        for key, entry in self.setting_entries.items():
            entry.delete(0, "end")
            entry.insert(0, str(self.settings[key]))

        messagebox.showinfo("Success", "Settings reset to defaults")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = KrosisApp()
    app.run()