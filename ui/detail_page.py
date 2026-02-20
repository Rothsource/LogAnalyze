import tkinter as tk
from tkinter import ttk
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates

class DetailPage:
    def __init__(self, parent_frame, data, result, bruteforce_data, go_back_callback):
        """
        data: single IP data dict with {ip, total, failed, success, os, threat_level}
        result: (extracted, reverse_map) from prepare_logs
        bruteforce_data: data from analyze_bruteforce for this IP
        go_back_callback: function to call when back button is pressed
        """
        self.parent_frame = parent_frame
        self.data = data
        self.extracted, self.reverse_map = result
        self.bruteforce_data = bruteforce_data
        self.go_back = go_back_callback
        
        self.create_detail_view()
    
    def create_detail_view(self):
        # Clear parent frame
        for widget in self.parent_frame.winfo_children():
            widget.destroy()
        
        # Main scrollable container
        main_canvas = tk.Canvas(self.parent_frame, bg="#0a1628", highlightthickness=0)
        scrollbar = tk.Scrollbar(self.parent_frame, orient="vertical", command=main_canvas.yview)
        scrollable_container = tk.Frame(main_canvas, bg="#0a1628")
        
        scrollable_container.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_container, anchor="nw", width=self.parent_frame.winfo_width())
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Top bar with back button and file info
        top_bar = tk.Frame(scrollable_container, bg="#0a1628", height=60)
        top_bar.pack(fill="x", padx=20, pady=(10, 0))
        top_bar.pack_propagate(False)
        
        # Back button
        back_btn = tk.Button(
            top_bar,
            text="‹",
            font=("Arial", 24, "bold"),
            fg="white",
            bg="#1e3a5f",
            activebackground="#2d4a6f",
            border=0,
            width=3,
            cursor="hand2",
            command=self.go_back
        )
        back_btn.pack(side="left", pady=10)
        
        # File label
        file_label = tk.Label(
            top_bar,
            text="File: log.csv",
            font=("Arial", 11),
            fg="white",
            bg="#1e3a5f",
            padx=15,
            pady=8
        )
        file_label.pack(side="right", pady=10)
        
        # Graph section (top)
        graph_frame = tk.Frame(scrollable_container, bg="white", height=400)
        graph_frame.pack(fill="x", padx=20, pady=10)
        graph_frame.pack_propagate(False)
        
        self.create_line_graph(graph_frame)
        
        # Bottom section with 3 columns
        bottom_frame = tk.Frame(scrollable_container, bg="#0a1628", height=500)
        bottom_frame.pack(fill="x", padx=20, pady=10)
        bottom_frame.pack_propagate(False)
        
        # Configure grid weights for equal distribution
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)
        bottom_frame.grid_columnconfigure(2, weight=1)
        bottom_frame.grid_rowconfigure(0, weight=1)
        
        # Left: IP Info
        self.create_ip_info_section(bottom_frame)
        
        # Middle: Attempt pie chart
        self.create_attempt_pie_chart(bottom_frame)
        
        # Right: Brute force pie chart
        self.create_bruteforce_pie_chart(bottom_frame)
    
    def create_line_graph(self, parent):
        """Create timeline graph using data from prepare_logs"""
        
        # Get data for this specific IP
        ip_col = self.reverse_map.get('ip')
        timestamp_col = self.reverse_map.get('timestamp')
        status_col = self.reverse_map.get('status')
        
        if not ip_col or not timestamp_col:
            tk.Label(parent, text="Timeline data not available", 
                    font=("Arial", 14), fg="#666", bg="white").pack(expand=True)
            return
        
        # Filter entries for this IP
        timeline_data = []
        for entry in self.extracted:
            if entry.get(ip_col) == self.data['ip']:
                timestamp_str = entry.get(timestamp_col)
                status = entry.get(status_col, 'Unknown').upper()
                if timestamp_str:
                    timeline_data.append({
                        'timestamp': timestamp_str,
                        'status': status
                    })
        
        if not timeline_data:
            tk.Label(parent, text="No timeline data", 
                    font=("Arial", 14), fg="#666", bg="white").pack(expand=True)
            return
        
        # Parse timestamps
        TIMESTAMP_FORMATS = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]
        
        times = []
        for item in timeline_data:
            for fmt in TIMESTAMP_FORMATS:
                try:
                    times.append(datetime.strptime(item['timestamp'].strip(), fmt))
                    break
                except ValueError:
                    continue
        
        if not times:
            tk.Label(parent, text="Could not parse timestamps", 
                    font=("Arial", 14), fg="#666", bg="white").pack(expand=True)
            return
        
        times.sort()
        attempts = list(range(1, len(times) + 1))
        
        # Calculate rate
        if len(times) >= 2:
            duration = (times[-1] - times[0]).total_seconds()
            rate = len(times) / duration if duration > 0 else len(times)
        else:
            rate = 0
        
        # Create matplotlib figure
        fig = Figure(figsize=(12, 4), facecolor='white')
        ax = fig.add_subplot(111)
        
        # Plot line (similar to create_line_graph in LineGraph.py)
        ax.plot(times, attempts, '-o', color='#5b7ba8', linewidth=2.5, markersize=6)
        
        # Styling
        ax.set_xlabel('Timestamp', fontsize=12, fontweight='bold')
        ax.set_ylabel('Number of Attempts', fontsize=12, fontweight='bold')
        ax.set_title(f'Login Attempts Timeline - Rate: {rate:.2f} attempts/sec', fontsize=13, fontweight='bold')
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        fig.autofmt_xdate(rotation=45)
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
    
    def create_ip_info_section(self, parent):
        """Left section with IP details from prepare_logs result"""
        
        info_frame = tk.Frame(parent, bg="#0f2337", highlightbackground="#1e3a5f", highlightthickness=2)
        info_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Get additional info from extracted data
        ip_col = self.reverse_map.get('ip')
        timestamp_col = self.reverse_map.get('timestamp')
        ipv6_col = self.reverse_map.get('ipv6')
        
        # Find first and last timestamps, and ipv6
        timestamps = []
        ipv6 = "None"
        
        for entry in self.extracted:
            if entry.get(ip_col) == self.data['ip']:
                ts = entry.get(timestamp_col)
                if ts:
                    timestamps.append(ts)
                if ipv6_col and entry.get(ipv6_col) and entry.get(ipv6_col) != "Can't Detect":
                    ipv6 = entry.get(ipv6_col)
        
        timestamps.sort()
        started = timestamps[0] if timestamps else "Unknown"
        finished = timestamps[-1] if timestamps else "Unknown"
        
        # Title
        tk.Label(
            info_frame,
            text=f"IPv4: {self.data['ip']}",
            font=("Arial", 14, "bold"),
            fg="white",
            bg="#0f2337",
            anchor="w"
        ).pack(fill="x", padx=20, pady=(20, 15))
        
        # Info fields
        info_items = [
            ("IPv6:", ipv6),
            ("Started:", started),
            ("Finished:", finished),
            ("OS:", self.data['os']),
            ("Country:", "Unknown")
        ]
        
        for label, value in info_items:
            row = tk.Frame(info_frame, bg="#0f2337")
            row.pack(fill="x", padx=20, pady=8)
            
            tk.Label(
                row,
                text=label,
                font=("Arial", 11),
                fg="#7a8ba3",
                bg="#0f2337",
                anchor="w",
                width=12
            ).pack(side="left")
            
            tk.Label(
                row,
                text=value,
                font=("Arial", 11),
                fg="white",
                bg="#0f2337",
                anchor="w"
            ).pack(side="left", padx=(5, 0))
    
    def create_attempt_pie_chart(self, parent):
        """Middle section - uses data from summarize_logs"""
        
        chart_frame = tk.Frame(parent, bg="#0f2337", highlightbackground="#1e3a5f", highlightthickness=2)
        chart_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        
        # Title and stats
        header = tk.Frame(chart_frame, bg="#0f2337")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        stats_text = f"Attempt: {self.data['total']:,}\nFail: {self.data['failed']:,}\nSuccess: {self.data['success']}"
        
        tk.Label(
            header,
            text=stats_text,
            font=("Arial", 12, "bold"),
            fg="white",
            bg="#0f2337",
            anchor="w",
            justify="left"
        ).pack(side="left")
        
        # Pie chart (similar to create_pie_chart in PieChart.py)
        fig = Figure(figsize=(5, 5), facecolor='#0f2337')
        ax = fig.add_subplot(111)
        
        sizes = []
        labels = []
        colors = []
        
        if self.data['success'] > 0:
            sizes.append(self.data['success'])
            labels.append(f"Success\n({self.data['success']})")
            colors.append('#2ecc71')
        
        if self.data['failed'] > 0:
            sizes.append(self.data['failed'])
            labels.append(f"Failed\n({self.data['failed']})")
            colors.append('#e74c3c')
        
        if self.data['total'] > self.data['success'] + self.data['failed']:
            other = self.data['total'] - self.data['success'] - self.data['failed']
            sizes.append(other)
            labels.append(f'Other\n({other})')
            colors.append('#95a5a6')
        
        if sizes:
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 10, 'weight': 'bold'})
            ax.axis('equal')
        
        canvas = FigureCanvasTkAgg(fig, chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
    
    def create_bruteforce_pie_chart(self, parent):
        """Right section - uses data from analyze_bruteforce"""
        
        chart_frame = tk.Frame(parent, bg="#0f2337", highlightbackground="#1e3a5f", highlightthickness=2)
        chart_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        
        # Get actual likelihood from bruteforce analysis
        threat_level = self.data['threat_level']
        likelihood = float(self.bruteforce_data.get('likelihood', 10)) if self.bruteforce_data else 10
        
        # Title
        header = tk.Frame(chart_frame, bg="#0f2337")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        stats_text = f"Brute Force: {likelihood}%\nNormal: {100-likelihood:.1f}%\nStatus: {threat_level}"
        
        tk.Label(
            header,
            text=stats_text,
            font=("Arial", 12, "bold"),
            fg="white",
            bg="#0f2337",
            anchor="w",
            justify="left"
        ).pack(side="left")
        
        # Pie chart (similar to create_bruteforce_chart in PieChart.py)
        fig = Figure(figsize=(5, 5), facecolor='#0f2337')
        ax = fig.add_subplot(111)
        
        threat_color = {
            'CRITICAL': '#e74c3c',
            'SUSPICIOUS': '#f39c12',
            'NORMAL': '#2ecc71'
        }.get(threat_level, '#95a5a6')
        
        sizes = [likelihood, 100 - likelihood]
        labels = [f'Threat\n({likelihood}%)', f'Safe\n({100-likelihood:.1f}%)']
        colors = [threat_color, '#95a5a6']
        
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 10, 'weight': 'bold'})
        ax.axis('equal')
        
        canvas = FigureCanvasTkAgg(fig, chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)