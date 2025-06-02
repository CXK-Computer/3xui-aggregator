import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import subprocess
import platform
import threading
import concurrent.futures
import locale # For system default encoding
import requests # Import the requests library

# --- Global list to store successfully pinged IPs for export ---
successful_ips_to_export = [] # Based on ICMP Ping success

# --- Configuration for HTTP Check ---
HTTP_TIMEOUT = 3 # Timeout in seconds for HTTP requests
USER_AGENT = "IPStatusChecker/1.0" # Optional: Set a user-agent

def icmp_ping(ip_address):
    """
    Performs an ICMP ping to the given IP address.
    Returns: (bool: success, str: message)
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    if platform.system().lower() == 'windows':
        command = ['ping', param, '1', '-w', '1000', ip_address] # 1000ms timeout
    else:
        command = ['ping', param, '1', '-W', '1', ip_address] # 1s timeout

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_bytes, stderr_bytes = process.communicate(timeout=2)

        stdout_decoded, stderr_decoded = "", ""
        encodings_to_try = ['utf-8', locale.getpreferredencoding(False), 'gbk']
        for enc in encodings_to_try:
            try:
                stdout_decoded = stdout_bytes.decode(enc).strip()
                stderr_decoded = stderr_bytes.decode(enc).strip()
                break
            except UnicodeDecodeError:
                continue
        else:
            stdout_decoded = stdout_bytes.decode('latin-1', errors='ignore').strip()
            stderr_decoded = stderr_bytes.decode('latin-1', errors='ignore').strip()

        if process.returncode == 0:
            return True, f"Ping OK"
        else:
            error_message = stderr_decoded or stdout_decoded
            return False, f"Ping Failed: {error_message.splitlines()[0] if error_message else 'Unknown ICMP error'}"
    except subprocess.TimeoutExpired:
        return False, "Ping Timed Out"
    except Exception as e:
        return False, f"Ping Error: {e}"

def check_web_server(ip_address):
    """
    Checks for a web server on HTTP (port 80) and HTTPS (port 443).
    Returns: (bool: success, str: message, str: url_checked)
    """
    urls_to_try = [f"http://{ip_address}", f"https://{ip_address}"]
    headers = {'User-Agent': USER_AGENT}

    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers=headers, allow_redirects=True, verify=False) # verify=False for self-signed certs, use with caution
            # Consider any 2xx or 3xx status code as success for reachability
            if response.ok or response.is_redirect:
                return True, f"HTTP {response.status_code}", url
        except requests.exceptions.Timeout:
            # Continue to next URL if timeout on one (e.g. http timeout, try https)
            continue
        except requests.exceptions.ConnectionError:
            # Continue, this often means port not open or host not resolving for this protocol
            continue
        except requests.exceptions.RequestException as e:
            # For other requests errors, we might stop for this IP
            return False, f"HTTP Error: {type(e).__name__}", url
    return False, "No HTTP/S Response", urls_to_try[0].split("://")[0] # Report on protocol type if both fail

def get_host_status(ip_address):
    """
    Gets ICMP ping status and web server status for an IP address.
    Returns: (ip, icmp_success, icmp_msg, http_success, http_msg, http_url_protocol)
    """
    icmp_success, icmp_msg = icmp_ping(ip_address)
    http_success, http_msg, http_url_protocol = check_web_server(ip_address)
    if http_url_protocol.startswith("https://"):
        protocol_display = "HTTPS"
    elif http_url_protocol.startswith("http://"):
        protocol_display = "HTTP"
    else: # When check_web_server returns a generic protocol string like "http"
        protocol_display = http_url_protocol.upper()

    return ip_address, icmp_success, icmp_msg, http_success, http_msg, protocol_display


def update_results_text(message, scroll=True):
    if results_text.winfo_exists():
        results_text.config(state=tk.NORMAL)
        results_text.insert(tk.END, message)
        if scroll: results_text.see(tk.END)
        results_text.config(state=tk.DISABLED)
    if app.winfo_exists(): app.update_idletasks()

def process_host_status_result(future):
    """Callback function executed when a host status check completes."""
    global successful_ips_to_export
    try:
        ip, icmp_ok, icmp_msg, http_ok, http_msg, http_protocol = future.result()

        icmp_status_icon = "✅" if icmp_ok else "❌"
        http_status_icon = "🌐" # General web icon
        http_result_color = "green" if http_ok else "orange" # Orange for non-critical failures or no response

        if icmp_ok:
            successful_ips_to_export.append(ip) # Still based on ICMP success

        # Constructing the display line
        # Example: 8.8.8.8 ... [Ping ✅ OK] | [HTTP 🌐 OK (200)]
        line = f"{ip:<20} ... [{icmp_status_icon} {icmp_msg}] | [{http_status_icon} {http_protocol}: {http_msg}]\n"
        
        # Update text area - direct update (ensure it's safe or marshal to main thread if complex)
        results_text.config(state=tk.NORMAL)
        results_text.insert(tk.END, line)
        # Apply color tag for HTTP status (optional, makes it more complex)
        # For simplicity, we'll skip direct color tagging in the ScrolledText per line here.
        results_text.see(tk.END)
        results_text.config(state=tk.DISABLED)

    except Exception as e:
        # ip_future = future_to_ip_map.get(future, "Unknown IP") # Requires passing map or ip
        update_results_text(f"Error processing result for an IP: {e}\n")


def perform_threaded_host_checks(ip_addresses):
    global successful_ips_to_export
    successful_ips_to_export.clear()
    if export_button.winfo_exists(): export_button.config(state=tk.DISABLED)

    num_total = len(ip_addresses)
    update_results_text(f"Checking {num_total} IP addresses (ICMP & HTTP)...\n\n")
    update_results_text(f"{'IP Address':<20} ... {'ICMP Status':<20} | {'Web Status'}\n")
    update_results_text("-" * 80 + "\n")


    max_workers = min(30, num_total + 4) # HTTP requests can be slow, adjust workers
    # future_to_ip_map = {} # To map future back to IP in case of error in process_host_status_result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(get_host_status, ip) for ip in ip_addresses]
        # for i, ip in enumerate(ip_addresses):
        #     future = executor.submit(get_host_status, ip)
        #     future_to_ip_map[future] = ip # Store mapping

        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            process_host_status_result(future) # This function will update the GUI
            processed_count += 1
            if ping_status_label.winfo_exists():
                ping_status_label.config(text=f"Processing... ({processed_count}/{num_total})")
            if app.winfo_exists(): app.update_idletasks()

    num_icmp_successful = len(successful_ips_to_export)
    # Note: http success count is not explicitly tracked for summary here, but visible in lines

    summary_message = f"\n--- Check Results Summary ---\n"
    summary_message += f"Total IPs Checked: {num_total}\n"
    summary_message += f"ICMP Ping Successful: {num_icmp_successful} ✅\n"
    summary_message += f"(Web status displayed per IP above)\n"
    update_results_text(summary_message)

    if ping_status_label.winfo_exists():
        if successful_ips_to_export: # Based on ICMP
            if export_button.winfo_exists(): export_button.config(state=tk.NORMAL)
            ping_status_label.config(text="Checks complete. Export for ICMP valid IPs available.")
        else:
            ping_status_label.config(text="Checks complete. No IPs responded to ICMP ping.")

    if browse_button.winfo_exists(): browse_button.config(state=tk.NORMAL)


def load_ips_and_start_checks():
    filepath = filedialog.askopenfilename(
        title="Open TXT File with IP Addresses",
        filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
    )
    if not filepath: return

    if results_text.winfo_exists():
        results_text.config(state=tk.NORMAL)
        results_text.delete(1.0, tk.END)
        results_text.config(state=tk.DISABLED)
    update_results_text(f"Loading IPs from: {filepath}\n")

    raw_lines = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
        update_results_text("File read successfully using UTF-8 encoding.\n")
    except UnicodeDecodeError:
        update_results_text("UTF-8 decoding failed. Trying system default encoding...\n")
        try:
            with open(filepath, 'r', encoding=locale.getpreferredencoding(False)) as f:
                raw_lines = f.readlines()
            update_results_text(f"File read using system default: {locale.getpreferredencoding(False)}.\n")
        except Exception as e_fallback:
            update_results_text(f"Error reading file with fallback encoding: {e_fallback}\n")
            if browse_button.winfo_exists(): browse_button.config(state=tk.NORMAL)
            return
    except Exception as e_initial:
        update_results_text(f"Error reading file: {e_initial}\n")
        if browse_button.winfo_exists(): browse_button.config(state=tk.NORMAL)
        return

    ip_addresses = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith('#')]
    if not ip_addresses:
        update_results_text("No processable IP addresses found.\n")
        if browse_button.winfo_exists(): browse_button.config(state=tk.NORMAL)
        return

    if browse_button.winfo_exists(): browse_button.config(state=tk.DISABLED)
    if export_button.winfo_exists(): export_button.config(state=tk.DISABLED)
    if ping_status_label.winfo_exists(): ping_status_label.config(text="Starting checks...")

    main_check_thread = threading.Thread(target=perform_threaded_host_checks, args=(ip_addresses,))
    main_check_thread.daemon = True
    main_check_thread.start()

def export_successful_ips():
    if not successful_ips_to_export:
        messagebox.showinfo("Export IPs", "No ICMP successful IPs to export.")
        return
    filepath = filedialog.asksaveasfilename(
        title="Save ICMP Successful IPs As",
        defaultextension=".txt",
        filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        initialfile="icmp_successful_ips.txt"
    )
    if not filepath: return
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for ip in successful_ips_to_export:
                f.write(ip + "\n")
        messagebox.showinfo("Export Successful", f"Successfully exported {len(successful_ips_to_export)} IPs to:\n{filepath}")
        if ping_status_label.winfo_exists():
            ping_status_label.config(text=f"Exported {len(successful_ips_to_export)} IPs to {filepath}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export IPs: {e}")
        if ping_status_label.winfo_exists(): ping_status_label.config(text="Export failed.")

# --- GUI Setup ---
app = tk.Tk()
app.title("IP & Web Status Checker (requests integrated)")
app.geometry("900x650") # Wider for more info

# --- Warning for `requests` library ---
try:
    import requests
except ImportError:
    messagebox.showwarning("Library Missing", "The 'requests' library is not installed. HTTP checking will fail. Please install it by running: pip install requests")
    # Optionally, disable HTTP checking features if requests is not found,
    # or let it fail gracefully in the check_web_server function.
    # For now, it will show an error when check_web_server is called.

top_frame = tk.Frame(app, pady=10)
top_frame.pack(fill=tk.X)
results_frame = tk.Frame(app, padx=10, pady=5)
results_frame.pack(fill=tk.BOTH, expand=True)
status_frame = tk.Frame(app, pady=5)
status_frame.pack(fill=tk.X)

browse_button = tk.Button(top_frame, text="📂 Select IP List (.txt)", command=load_ips_and_start_checks, font=("Arial", 12), width=22)
browse_button.pack(side=tk.LEFT, padx=(10,5), pady=5)
export_button = tk.Button(top_frame, text="💾 Export (ICMP OK)", command=export_successful_ips, font=("Arial", 12), width=20, state=tk.DISABLED)
export_button.pack(side=tk.LEFT, padx=5, pady=5)

results_label = tk.Label(results_frame, text="Host Status (ICMP & HTTP/S):", font=("Arial", 12, "bold"))
results_label.pack(anchor=tk.W)
results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, state=tk.DISABLED, height=25, font=("Courier New", 9)) # Smaller font for more info
results_text.pack(fill=tk.BOTH, expand=True, pady=5)

ping_status_label = tk.Label(status_frame, text="Select a .txt file to start.", font=("Arial", 10), fg="blue", anchor=tk.W)
ping_status_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

if __name__ == "__main__":
    # Added a check and warning for the requests library
    try:
        import requests
    except ImportError:
        # This initial check is good, but actual error handling is within functions
        pass # GUI will show a messagebox when app starts if it's missing
    app.mainloop()