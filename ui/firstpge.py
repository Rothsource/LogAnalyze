import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Calulate.Filter_ip import prepare_logs
from Calulate.totalAttempt_totalFailSuccess import summarize_logs
from Calulate.threat_level import analyze_bruteforce

class LogAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer")
        self.root.geometry("1200x800")  
        self.root.minsize(850, 600)      
        self.root.configure(bg="#0a1628")
        
        self.uploaded_file = None
        self.table_data = []
        self.filtered_data = []
        self.active_filters = {}
        
        self.create_widgets()
        
        self.root.bind("<Configure>", self.on_window_resize)
    
    def create_widgets(self):
        self.header_frame = tk.Frame(self.root, bg="#0a1628")
        self.header_frame.pack(fill="x", padx=30, pady=(20, 10))
        
        title_label = tk.Label(
            self.header_frame, 
            text="Analyzer", 
            font=("Arial", 32, "bold"),
            fg="white",
            bg="#0a1628"
        )
        title_label.pack(side="left")
        
        self.subtitle_label = tk.Label(
            self.header_frame,
            text="Review your Logs File",
            font=("Arial", 13),  
            fg="#7a8ba3",
            bg="#0a1628"
        )
        self.subtitle_label.place(x=30, y=60)
        
        btn_frame = tk.Frame(self.header_frame, bg="#0a1628")
        btn_frame.pack(side="right")
        
        refresh_btn = tk.Button(
            btn_frame,
            text="⟳",
            font=("Arial", 18), 
            fg="white",
            bg="#1e3a5f",
            activebackground="#2d4a6f",
            border=0,
            width=3,
            height=1,
            cursor="hand2",
            command=self.refresh_data
        )
        refresh_btn.pack(side="left", padx=5)
        
        upload_btn = tk.Button(
            btn_frame,
            text="☁",
            font=("Arial", 18),  
            fg="white",
            bg="#1e3a5f",
            activebackground="#2d4a6f",
            border=0,
            width=3,
            height=1,
            cursor="hand2",
            command=self.upload_file
        )
        upload_btn.pack(side="left")
        
        self.search_frame = tk.Frame(self.root, bg="#1e3a5f", height=50)  
        self.search_frame.pack(fill="x", padx=30, pady=(10, 15))
        self.search_frame.pack_propagate(False)
        
        search_icon = tk.Label(
            self.search_frame,
            text="🔍",
            font=("Arial", 16),  
            fg="#7a8ba3",
            bg="#1e3a5f"
        )
        search_icon.pack(side="left", padx=(15, 5), pady=12)
        
        self.search_entry = tk.Entry(
            self.search_frame,
            font=("Arial", 13), 
            fg="white",
            bg="#1e3a5f",
            insertbackground="white",
            border=0,
            highlightthickness=0
        )
        self.search_entry.pack(side="left", fill="both", expand=True, pady=12)
        self.search_entry.insert(0, "Search (e.g., ip:192.168.1.1 or os:Windows)...")
        self.search_entry.bind("<FocusIn>", self.on_entry_click)
        self.search_entry.bind("<FocusOut>", self.on_focus_out)
        self.search_entry.bind("<KeyRelease>", self.search_table)
        self.search_entry.config(fg="#7a8ba3")
        
        self.filter_frame = tk.Frame(self.root, bg="#0a1628")
        self.filter_frame.pack(fill="x", padx=30, pady=(0, 15))
        
        filters = [
            "Total Attempts",
            "Total Fail",
            "Total Success",
            "Operating System",
            "Threat Level"
        ]
        
        for filter_name in filters:
            btn = tk.Button(
                self.filter_frame,
                text=f"{filter_name} ▼",
                font=("Arial", 11), 
                fg="white",
                bg="#1e3a5f",
                activebackground="#2d4a6f",
                border=0,
                padx=18,  
                pady=10,
                cursor="hand2",
                command=lambda f=filter_name: self.show_filter_menu(f)
            )
            btn.pack(side="left", padx=5)
        
        clear_btn = tk.Button(
            self.filter_frame,
            text="Clear Filter",
            font=("Arial", 11),  
            fg="white",
            bg="#1e3a5f",
            activebackground="#2d4a6f",
            border=0,
            padx=18,
            pady=10,
            cursor="hand2",
            command=self.clear_filters
        )
        clear_btn.pack(side="left", padx=5)
        
        self.content_frame = tk.Frame(self.root, bg="#0f2337", highlightbackground="#1e3a5f", highlightthickness=2)
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        
        self.show_upload_screen()
    
    def show_filter_menu(self, filter_name):
        if not self.table_data:
            return
        
        menu = tk.Menu(self.root, tearoff=0, bg="#1e3a5f", fg="white", activebackground="#2d4a6f")
        
        if filter_name == "Total Attempts":
            ranges = [
                ("Less than 10", lambda: self.apply_numeric_filter('total', 0, 9)),
                ("10 - 100", lambda: self.apply_numeric_filter('total', 10, 100)),
                ("100 - 1000", lambda: self.apply_numeric_filter('total', 100, 1000)),
                ("1000+", lambda: self.apply_numeric_filter('total', 1000, float('inf')))
            ]
            for label, command in ranges:
                menu.add_command(label=label, command=command)
        
        elif filter_name == "Total Fail":
            ranges = [
                ("0", lambda: self.apply_numeric_filter('failed', 0, 0)),
                ("1 - 10", lambda: self.apply_numeric_filter('failed', 1, 10)),
                ("10 - 100", lambda: self.apply_numeric_filter('failed', 10, 100)),
                ("100+", lambda: self.apply_numeric_filter('failed', 100, float('inf')))
            ]
            for label, command in ranges:
                menu.add_command(label=label, command=command)
        
        elif filter_name == "Total Success":
            ranges = [
                ("0", lambda: self.apply_numeric_filter('success', 0, 0)),
                ("1 - 10", lambda: self.apply_numeric_filter('success', 1, 10)),
                ("10 - 100", lambda: self.apply_numeric_filter('success', 10, 100)),
                ("100+", lambda: self.apply_numeric_filter('success', 100, float('inf')))
            ]
            for label, command in ranges:
                menu.add_command(label=label, command=command)
        
        elif filter_name == "Operating System":
            os_list = set(row['os'] for row in self.table_data)
            for os_name in sorted(os_list):
                menu.add_command(label=os_name, command=lambda o=os_name: self.apply_value_filter('os', o))
        
        elif filter_name == "Threat Level":
            threat_levels = ['CRITICAL', 'SUSPICIOUS', 'NORMAL']
            for level in threat_levels:
                menu.add_command(label=level, command=lambda l=level: self.apply_value_filter('threat_level', l))
        
        try:
            menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        finally:
            menu.grab_release()
    
    def apply_numeric_filter(self, field, min_val, max_val):
        self.active_filters[field] = {'type': 'range', 'min': min_val, 'max': max_val}
        self.apply_all_filters()
    
    def apply_value_filter(self, field, value):
        self.active_filters[field] = {'type': 'exact', 'value': value}
        self.apply_all_filters()
    
    def apply_all_filters(self):
        if not self.active_filters:
            self.filtered_data = []
            self.show_data_table()
            return
        
        self.filtered_data = []
        
        for row in self.table_data:
            match = True
            
            for field, filter_config in self.active_filters.items():
                if filter_config['type'] == 'range':
                    value = row[field]
                    if not (filter_config['min'] <= value <= filter_config['max']):
                        match = False
                        break
                elif filter_config['type'] == 'exact':
                    if row[field] != filter_config['value']:
                        match = False
                        break
            
            if match:
                self.filtered_data.append(row)
        
        self.show_data_table()
    
    def on_window_resize(self, event):
        if hasattr(self, 'canvas') and self.canvas.winfo_exists():
            new_width = self.content_frame.winfo_width() - 20
            self.canvas.itemconfig(self.canvas_frame, width=new_width)
    
    def show_upload_screen(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        upload_frame = tk.Frame(self.content_frame, bg="#0f2337")
        upload_frame.pack(fill="both", expand=True)
        
        upload_icon = tk.Label(
            upload_frame,
            text="☁↑",
            font=("Arial", 64),  
            fg="#4a5f7f",
            bg="#0f2337"
        )
        upload_icon.pack(pady=(200, 15))
        
        upload_text = tk.Label(
            upload_frame,
            text="Upload file (JSON, CSV, TXT)",
            font=("Arial", 14),  
            fg="#7a8ba3",
            bg="#0f2337"
        )
        upload_text.pack()
        
        upload_frame.bind("<Button-1>", lambda e: self.upload_file())
        upload_icon.bind("<Button-1>", lambda e: self.upload_file())
        upload_text.bind("<Button-1>", lambda e: self.upload_file())
    
    def show_data_table(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        header_row = tk.Frame(self.content_frame, bg="#1a2f47", height=50)  
        header_row.pack(fill="x")
        header_row.pack_propagate(False)
        
        headers = ["IPv4", "TOTAL ATTEMPTS", "TOTAL FAIL", "TOTAL SUCCESS", "OPERATING SYSTEM", "THREAT LEVEL"]
        x_positions = [20, 200, 350, 480, 650, 850] 
        
        for header, x_pos in zip(headers, x_positions):
            label = tk.Label(
                header_row,
                text=header,
                font=("Arial", 10, "bold"), 
                fg="#7a8ba3",
                bg="#1a2f47",
                anchor="w"
            )
            label.place(x=x_pos, y=16)
        
        container = tk.Frame(self.content_frame, bg="#0f2337")
        container.pack(fill="both", expand=True)
        
        self.canvas = tk.Canvas(container, bg="#0f2337", highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=self.canvas.yview, bg="#1e3a5f", troughcolor="#0f2337")
        scrollable_frame = tk.Frame(self.canvas, bg="#0f2337")
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas_frame = self.canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=self.content_frame.winfo_width() - 20)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        display_data = self.filtered_data if self.filtered_data else self.table_data
        
        print(f"Creating {len(display_data)} rows")
        
        for idx, row_data in enumerate(display_data):
            row_frame = tk.Frame(
                scrollable_frame,
                bg="#0f2337" if idx % 2 == 0 else "#0a1a2e",
                height=65 
            )
            row_frame.pack(fill="x", pady=1)
            row_frame.pack_propagate(False)
            
            tk.Label(
                row_frame,
                text=row_data['ip'],
                font=("Arial", 11),  
                fg="white",
                bg=row_frame['bg'],
                anchor="w"
            ).place(x=20, y=22)
            
            tk.Label(
                row_frame,
                text=f"{row_data['total']:,}",
                font=("Arial", 11),
                fg="white",
                bg=row_frame['bg'],
                anchor="w"
            ).place(x=200, y=22)
            
            tk.Label(
                row_frame,
                text=f"{row_data['failed']:,}",
                font=("Arial", 11),
                fg="white",
                bg=row_frame['bg'],
                anchor="w"
            ).place(x=350, y=22)
            
            tk.Label(
                row_frame,
                text=str(row_data['success']),
                font=("Arial", 11),
                fg="white",
                bg=row_frame['bg'],
                anchor="w"
            ).place(x=480, y=22)
            
            tk.Label(
                row_frame,
                text=row_data['os'],
                font=("Arial", 11),
                fg="white",
                bg=row_frame['bg'],
                anchor="w"
            ).place(x=650, y=22)
            
            threat_color = {
                'CRITICAL': '#dc3545',
                'SUSPICIOUS': '#fd7e14',
                'NORMAL': '#6c757d'
            }.get(row_data['threat_level'], '#6c757d')
            
            tk.Label(
                row_frame,
                text=row_data['threat_level'],
                font=("Arial", 9, "bold"),
                fg="white",
                bg=threat_color,
                padx=10,  
                pady=6
            ).place(x=850, y=18)
            
            arrow = tk.Label(
                row_frame,
                text="›",
                font=("Arial", 20), 
                fg="#7a8ba3",
                bg=row_frame['bg'],
                cursor="hand2"
            )
            arrow.place(x=1000, y=16)
            arrow.bind("<Button-1>", lambda e, d=row_data: self.show_details(d))
        
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        
        print("Table displayed - all rows created")
    
    def on_entry_click(self, event):
        placeholder = "Search (e.g., ip:192.168.1.1 or os:Windows)..."
        if self.search_entry.get() == placeholder:
            self.search_entry.delete(0, "end")
            self.search_entry.config(fg="white")
    
    def on_focus_out(self, event):
        if self.search_entry.get() == "":
            self.search_entry.insert(0, "Search (e.g., ip:192.168.1.1 or os:Windows)...")
            self.search_entry.config(fg="#7a8ba3")
    
    def search_table(self, event):
        search_term = self.search_entry.get().strip()
        placeholder = "Search (e.g., ip:192.168.1.1 or os:Windows)..."
        
        if not search_term or search_term == placeholder:
            self.filtered_data = []
            self.show_data_table()
            return
        
        self.filtered_data = []
        
        if ':' in search_term:
            field, value = search_term.split(':', 1)
            field = field.strip().lower()
            value = value.strip().lower()
            
            for row in self.table_data:
                if field == 'ip' and value in row['ip'].lower():
                    self.filtered_data.append(row)
                elif field == 'os' and value in row['os'].lower():
                    self.filtered_data.append(row)
                elif field == 'threat' and value in row['threat_level'].lower():
                    self.filtered_data.append(row)
                elif field == 'status' and value in row['threat_level'].lower():
                    self.filtered_data.append(row)
        else:
            search_lower = search_term.lower()
            for row in self.table_data:
                if (search_lower in row['ip'].lower() or
                    search_lower in row['os'].lower() or
                    search_lower in row['threat_level'].lower()):
                    self.filtered_data.append(row)
        
        self.show_data_table()
    
    def upload_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("All Supported", "*.json *.csv *.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.uploaded_file = file_path
            self.process_file(file_path)
    
    def process_file(self, file_path):
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()
            
            loading_label = tk.Label(
                self.content_frame,
                text="Loading data...",
                font=("Arial", 16),
                fg="#7a8ba3",
                bg="#0f2337"
            )
            loading_label.pack(expand=True)
            self.root.update()
            
            result = prepare_logs(file_path)
            
            if result is None:
                messagebox.showerror("Error", "Failed to load file")
                self.show_upload_screen()
                return
            
            summary = summarize_logs(result)
            bruteforce = analyze_bruteforce(result)
            
            extracted, reverse_map = result
            os_col = reverse_map.get('os')
            ip_col = reverse_map.get('ip')
            
            self.extracted_data = extracted
            self.reverse_map_data = reverse_map
            self.bruteforce_data = bruteforce 
            
            self.table_data = []
            for ip in summary.keys():
                os_name = "Don't know"
                for entry in extracted:
                    entry_ip = entry.get(ip_col, '')
                    if entry_ip == ip:
                        os_name = entry.get(os_col, "Don't know")
                        if os_name and os_name != "Can't Detect":
                            break
                
                self.table_data.append({
                    'ip': ip,
                    'total': summary[ip]['total'],
                    'failed': summary[ip]['failed'],
                    'success': summary[ip]['success'],
                    'os': os_name if os_name != "Can't Detect" else "Don't know",
                    'threat_level': bruteforce.get(ip, {}).get('threat_level', 'NORMAL')
                })
            
            self.filtered_data = []
            self.active_filters = {}
            
            print(f"Prepared {len(self.table_data)} rows")
            
            self.show_data_table()
            
        except Exception as e:
            import traceback
            print(f"Error: {str(e)}")
            print(traceback.format_exc())
            messagebox.showerror("Error", f"Failed to process file:\n{str(e)}")
            self.show_upload_screen()
    
    def refresh_data(self):
        if self.uploaded_file:
            self.process_file(self.uploaded_file)
        else:
            messagebox.showwarning("No File", "Please upload a file first")
    
    def clear_filters(self):
        if self.uploaded_file:
            self.filtered_data = []
            self.active_filters = {}
            self.search_entry.delete(0, "end")
            self.search_entry.insert(0, "Search (e.g., ip:192.168.1.1 or os:Windows)...")
            self.search_entry.config(fg="#7a8ba3")
            self.show_data_table()
    
    def show_details(self, data):
        from ui.detail_page import DetailPage
        
        bruteforce_single = self.bruteforce_data.get(data['ip'], {})
        
        result = (self.extracted_data, self.reverse_map_data)
        
        DetailPage(self.content_frame, data, result, bruteforce_single, self.show_data_table)

def main():
    root = tk.Tk()
    app = LogAnalyzerUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()