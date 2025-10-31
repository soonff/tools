import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk 
import dns.resolver
import dns.exception

# --- Core DNS Lookup Functions ---

def get_a_records(domain):
    """Retrieves A records (Host IP addresses)."""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [f"IPv4 Address: {rdata.address}" for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No IPv4 A records found."]
    except dns.resolver.NXDOMAIN:
        return ["Domain does not exist (NXDOMAIN)."]
    except Exception as e:
        return [f"Error fetching A records: {e}"]

def get_aaaa_records(domain):
    """Retrieves AAAA records (IPv6 Host addresses)."""
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        return [f"IPv6 Address: {rdata.address}" for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No IPv6 AAAA records found."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching AAAA records: {e}"]

def get_ns_records(domain):
    """Retrieves NS records (Name Servers)."""
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [f"Name Server: {rdata.target}" for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No NS records found."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching NS records: {e}"]

def get_mx_records(domain):
    """Retrieves MX records (Mail Servers) with preference values."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        # MX records have a preference value and the server hostname
        records = [f"Preference: {rdata.preference}, Mail Server: {rdata.exchange}" for rdata in answers]
        return records if records else ["No MX records found."]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No MX records found."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching MX records: {e}"]

def get_cname_records(domain):
    """Retrieves CNAME records (Canonical Name/Alias)."""
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return [f"Alias for: {rdata.target}" for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NotAbsolute):
        # NotAbsolute error is common when CNAME is tried on the root domain
        return ["No CNAME records found (often expected on root domains)."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching CNAME records: {e}"]

def get_txt_records(domain):
    """Retrieves TXT records (Text data, e.g., SPF/DKIM)."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        # TXT records can contain multiple strings, we join them and decode
        records = []
        for rdata in answers:
            text_data = b"".join(rdata.strings).decode('utf-8')
            records.append(f"TXT Data: {text_data}")
        return records if records else ["No TXT records found."]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No TXT records found."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching TXT records: {e}"]

def get_soa_record(domain):
    """Retrieves the SOA record (Start of Authority)."""
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        if not answers:
            return ["No SOA record found."]

        rdata = answers[0]
        # Format the SOA fields for display
        return [
            f"Primary NS: {rdata.mname}",
            f"Responsible Mailbox: {rdata.rname}",
            f"Serial: {rdata.serial}",
            f"Refresh: {rdata.refresh} seconds",
            f"Retry: {rdata.retry} seconds",
            f"Expire: {rdata.expire} seconds",
            f"Min TTL: {rdata.minimum} seconds"
        ]
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No SOA record found."]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Error fetching SOA record: {e}"]

# --- GUI Application Class (Cyber Dark Theme) ---

class DomainInfoApp:
    def __init__(self, master):
        self.master = master
        master.title("Ethical Domain Reconnaissance Tool")
        
        # 1. Apply TTK Style (Modern Dark Theme)
        # Define the custom color variables for better readability
        BG_DARK = '#1E1E1E'
        FIELD_DARK = '#2D2D2D'
        CYBER_TEAL = '#00CED1'
        ACCENT_GOLD = '#FFD700'
        SUCCESS_GREEN = '#2ecc71'

        style = ttk.Style()
        style.theme_create("cyber_dark", parent="alt", settings={
            "TFrame": {"configure": {"background": BG_DARK}},
            "TLabel": {"configure": {"background": BG_DARK, "foreground": "#FFFFFF", "font": ('Arial', 10)}},
            "TEntry": {"configure": {"fieldbackground": FIELD_DARK, "foreground": CYBER_TEAL, "font": ('Consolas', 12)}},
            "TButton": {"configure": {"background": CYBER_TEAL, "foreground": BG_DARK, "font": ('Arial', 14, 'bold'), "padding": 10},
                        "map": {"background": [('active', '#00A9A9')]}}
        })
        style.theme_use("cyber_dark")
        master.config(bg=BG_DARK) 
        
        # Configure grid for responsiveness (if maximizing/resizing the Tkinter window)
        master.grid_rowconfigure(3, weight=1)
        master.grid_columnconfigure(0, weight=1)
        
        # --- Title Banner ---
        tk.Label(master, text="🌐 Domain Lookup Utility", font=('Arial', 18, 'bold'), 
                 fg=CYBER_TEAL, bg=BG_DARK).grid(row=0, column=0, pady=(15, 5), sticky='ew')


        # 1. Domain Input Frame
        input_frame = ttk.Frame(master, padding="10 10 10 10")
        input_frame.grid(row=1, column=0, sticky='ew', padx=20, pady=10)

        ttk.Label(input_frame, text="Enter Domain Name:", 
                 font=('Arial', 12, 'bold'), foreground='#FFFFFF').pack(pady=5)
        
        self.domain_entry = ttk.Entry(input_frame, width=50, font=('Consolas', 12))
        self.domain_entry.pack(pady=5, padx=10, ipady=4)
        self.domain_entry.bind('<Return>', lambda event: self.start_lookup())

        # 2. Lookup Button
        ttk.Button(input_frame, text="RUN DNS SCAN", command=self.start_lookup, 
                   style='TButton').pack(pady=15, padx=20)


        # 3. Status Label
        self.status_label = tk.Label(master, text="Ready.", font=('Arial', 10, 'italic'), 
                                     fg=ACCENT_GOLD, bg=BG_DARK)
        self.status_label.grid(row=2, column=0, sticky='ew', padx=20)

        # 4. Results Display (ScrolledText)
        self.results_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=20, 
                                                     font=('Consolas', 10), 
                                                     bg=FIELD_DARK, # Slightly lighter dark gray for the text area
                                                     fg='#F0F0F0', # Off-white text for readability
                                                     insertbackground='white', # White cursor
                                                     bd=0, padx=10, pady=10, relief='sunken')
        self.results_text.grid(row=3, column=0, sticky='nsew', padx=20, pady=(5, 20))
        
        # Add custom tags for highlighting section headers (Tkinter Text widget styling)
        self.results_text.tag_config('header', foreground=CYBER_TEAL, font=('Consolas', 12, 'bold'))
        self.results_text.tag_config('success', foreground=SUCCESS_GREEN, font=('Consolas', 12, 'bold'))
        self.results_text.tag_config('warning', foreground='#E74C3C', font=('Consolas', 10, 'italic'))


    def start_lookup(self):
        """Main function to trigger all lookups."""
        domain = self.domain_entry.get().strip()
        
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return

        # Clear previous results and set status
        self.results_text.delete('1.0', tk.END)
        self.status_label.config(text=f"Searching for {domain}...", fg='#FFD700')
        self.master.update_idletasks() # Force GUI update

        results = {}
        
        # Basic Host Information
        results["Host Address (A Records)"] = get_a_records(domain)
        results["Host Address (AAAA Records - IPv6)"] = get_aaaa_records(domain)
        
        # Name Server Infrastructure
        results["Name Servers (NS Records)"] = get_ns_records(domain)
        results["Start of Authority (SOA Record)"] = get_soa_record(domain)
        
        # Mail and Aliases
        results["Mail Servers (MX Records)"] = get_mx_records(domain)
        results["Canonical Name (CNAME Records)"] = get_cname_records(domain)
        
        # Verification and Security
        results["Text Records (TXT Records - SPF/DKIM/Verification)"] = get_txt_records(domain)
        
        # Placeholder for Restricted Actions
        results["Intrusive Actions (Blocked)"] = [
            "Zone Transfer (AXFR) attempts and Bind Version enumeration are excluded for ethical and security reasons.",
            "Always ensure you have explicit, written permission to perform advanced reconnaissance against a target."
        ]


        # Format and display results
        self.display_results(domain, results)
        self.status_label.config(text=f"Lookup for {domain} completed.", fg='#2ecc71')

    def display_results(self, domain, results):
        """Inserts the gathered information into the ScrolledText widget with styling."""
        
        self.results_text.insert(tk.END, f"--- Domain Lookup Results for: {domain} ---\n\n", 'header')
        
        for title, data_list in results.items():
            
            # Use 'success' tag for the main headers and 'warning' for the blocked section header
            header_tag = 'success' if "Intrusive Actions" not in title else 'warning'
            self.results_text.insert(tk.END, f"== {title} ==\n", header_tag)
            
            for item in data_list:
                # Apply special tag for the restricted actions content
                if "Intrusive Actions" in title:
                    self.results_text.insert(tk.END, f"- {item}\n", 'warning')
                else:
                    self.results_text.insert(tk.END, f"- {item}\n")
            self.results_text.insert(tk.END, "\n")

# --- Check and Run ---
if __name__ == '__main__':
    try:
        # Check for dnspython installation
        import dns.resolver 
    except ImportError:
        # If dnspython is missing, guide the user to install it
        root = tk.Tk()
        root.withdraw() # Hide the main window
        messagebox.showerror(
            "Dependency Error", 
            "The 'dnspython' library is required. Please install it using your terminal:\n\n"
            "pip install dnspython\n\n"
            "Then run the script again."
        )
        root.destroy()
    else:
        # Run the GUI application
        root = tk.Tk()
        app = DomainInfoApp(root)
        root.mainloop()

