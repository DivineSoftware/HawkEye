import tkinter
import tkinter.messagebox
import tkinter.filedialog
import customtkinter
from tkinter import ttk
from PIL import Image, ImageTk
import os, subprocess, sys, psutil
import threading, time
import platform, winreg
import requests, json, zipfile
import vt, yara, hashlib
import webbrowser

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")
if getattr(sys, 'frozen', False):
    PATH = os.path.dirname(sys.executable)
else:
    PATH = os.path.dirname(os.path.abspath(__file__))

os.chdir(PATH)

class App(customtkinter.CTk):
    #HELPER FUNCTIONS CODE
    def download_file(self, url, local_filename):
      with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192): 
                f.write(chunk)
      return local_filename
    
    def checksum(self, file_path):
      hash = hashlib.sha256()
      with open('filename', 'rb') as f:
        for chunk in iter(lambda: f.read(128 * hash.block_size), b''):
            hash.update(chunk)
      return hash.hexdigest()

    def check_internet():
        try:
            requests.get('https://example.com')
            return True
        except: return False

    def install_loki():
      if os.name == 'nt':
        #ToDo: themed messagebox using new frame
        #self.create_toplevel("Please wait for system scanner to install")
        tkinter.messagebox.showinfo("Installer is running", "Please wait for the system scanner to install")
        os.mkdir('scanners/loki')
        latest_scanner = requests.get("https://api.github.com/repos/Neo23x0/Loki/releases/latest").json()['url']
        release_scanner = requests.get(latest_scanner).json()[0]['browser_download_url']
        self.download_file(release_scanner)
        latest_sigs = requests.get("https://api.github.com/repos/Neo23x0/signature-base/releases/latest").json()['url']
        release_sigs = requests.get(latest_sigs).json()[0]['browser_download_url']
        self.download_file(release_sigs)

        with zipfile.ZipFile(launch_exe.replace('.exe','.zip'), 'r') as zip_ref:
            zip_ref.extractall('scanners')
        with zipfile.ZipFile('scanners/loki/signature_base.zip', 'r') as zip_ref:
            zip_ref.extractall('scanners/loki')
        os.rename("scanners/loki/signature-base-2.0","scanners/loki/signature-base")

    #MAIN BODY CODE
    def scan_file(self):
     if self.picked_file.split("/")[-1] == "": return
     self.result_label.configure(fg="white")
     self.result_label.configure(text="Scanning...")
     if self.virustotal_key != "" and self.check_internet():
      client = vt.Client(self.virustotal_key)
      file = client.get_object('files/'+self.checksum(self.picked_file))
      if not file.times_submitted > 1:
        if self.settings['submit']:
            with open(self.picked_file, 'rb') as f:
                 analysis = client.scan_file(f, wait_for_completion=True)
            if analysis.last_analysis_stats['malicious'] > self.settings['detection_rate']:
                self.result_label.configure(text="Malicious | Detected by "+str(analysis.last_analysis_stats['malicious'])+" engines")
            else:
                self.result_label.configure(text="Clean")
      else:
        if file.last_analysis_stats['malicious'] > self.settings['detection_rate']:
            self.result_label.configure(fg="red")
            self.result_label.configure(text="Malicious\nDetected by "+str(file.last_analysis_stats['malicious'])+" engines")
        else:
            self.result_label.configure(fg="green")
            self.result_label.configure(text="Clean")
     else:
      sig_dir = 'scanners/loki/signature-base'
      if not os.path.exists(sig_dir):
          self.install_loki()
      for signature in os.listdir(sig_dir+'/yara'):
        try:
            rule = yara.compile(sig_dir+'/yara/'+signature)
            matches = rule.match(self.picked_file)
            self.result_label.configure(text="Detected\nRule: "+matches[0].rule)
            self.result_label.configure(fg="red")
        except Exception as e: print(e)
      if self.result_label.text == "Scanning...":
          self.result_label.configure(fg="green")
          self.result_label.configure(text="Clean")
   
    def scan_thread(self):
      threading.Thread(target=self.scan_file).start()
   
    def whitelist_editor(self):
      os.system('whitelist.txt')
    
    def delete_file(self):
      for sel in self.quarantine_treeview.selection():
          os.remove(self.quarantine_treeview.item(sel)['values'][1]+'.infected')
          del self.quarantine[self.quarantine_treeview.item(sel)['values'][1]]
          with open('quarantine.json','w') as blacklist:
              blacklist.write(json.dumps(self.quarantine)) 
          self.quarantine_treeview.delete(sel)
          
    def add_quarantine(self, file, path, scan):
        if self.settings['quarantinemalware']:
          if scan in ['System Scanner', 'Runtime Scanner']:
            #if not path in self.exceptions:
            for item in self.quarantine_treeview.get_children():
              try:
                if item['values'][1] == path:
                    return
              except: pass
            #ToDo: encoding/encrypting file might be safer
            os.rename(path, path+'.infected')
            self.quarantine[path] = [file, path, scan]
            with open('quarantine.json','w') as blacklist:
                blacklist.write(json.dumps(self.quarantine)) 
            self.quarantine_treeview.insert("", 'end', values=(file, path, scan))

    def remove_quarantine(self):
      for sel in self.quarantine_treeview.selection():
          os.rename(self.quarantine_treeview.item(sel)['values'][1]+'.infected', self.quarantine_treeview.item(sel)['values'][1])
          del self.quarantine[self.quarantine_treeview.item(sel)['values'][1]]
          with open('quarantine.json','w') as blacklist:
              blacklist.write(json.dumps(self.quarantine)) 
          self.quarantine_treeview.delete(sel)
          
    def scan_button_event(self):
      self.picked_file = tkinter.filedialog.askopenfilename(initialdir = "/", title = "Select a File")
      if self.picked_file.split("/")[-1] != "":
           self.scan_label.configure(text = self.picked_file.split("/")[-1])
    
    def open_explorer(self):
      for sel in self.quarantine_treeview.selection():
        if os.name == 'nt':
          os.startfile(os.path.dirname(self.quarantine_treeview.item(sel)['values'][1]+'.infected'))
    
    def run_cmd(self, cmd, elem, var):
      p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT, shell = True)
      while True:
          line = p.stdout.readline().decode()
          print(line)
          if not line: p.kill(); break
          if not var: p.kill(); break
          if line.startswith("FILE: "):
              if not self.drive_scan: p.kill();break
              elem.insert("", 0, values=(line.split("TYPE: ")[1].split(" ")[0], line.split("FILE: ")[1].split(" ")[0], line.split("SCORE: ")[1].split(" ")[0]))
              self.add_quarantine(line.split("TYPE: ")[1].split(" ")[0], line.split("FILE: ")[1].split(" ")[0], "System Scanner")
          elif line.startswith(">> Scanning PID: "):
            if not self.proc_scan: p.kill();break
            if line.split(" ")[3] != "":
               elem.insert("", 0, values=(line.split(" ")[3], line.split(" ")[5], "Clean"))
          elif line.startswith(">> Detected: "):
               if not self.proc_scan: p.kill();break
               for each in self.tab3_treeview.get_children():
                   if self.tab3_treeview.item(each)['values'][0] == line.split(" ")[2]:
                       self.tab3_treeview.item(each, values=(self.tab3_treeview.item(each)['values'][0], self.tab3_treeview.item(each)['values'][1], "Detected"))
                       p = psutil.Process(7055)
                       self.add_quarantine(line.split(" ")[2], p.exe(), "Runtime Scanner")
                       if self.settings['kill']:
                           p.kill()
                             
    def system_protection(self):
     if self.drive_scan:
      self.drive_scan = False
      self.tab2_button.configure(text = "Start")
     else:
      '''#CLAMAV alt code, ToDo: linux version
      if os.name == 'nt':
          clampath = 'scanners/clamav/clamd.exe'
          scanpath = 'scanners/clamav/clamdscan.exe'
      else:
          clampath = 'clamd'
          scanpath = 'clamdscan'
      os.system(clampath)
      '''
      launch_exe = 'scanners/loki/loki.exe'
      launch_args = ' --noprocscan'
      if self.tab2_1_checkbox.get():
          launch_args += ' --allhds'
      if not os.path.exists(launch_exe):
          self.install_loki()
      self.drive_scan = True
      self.tab2_button.configure(text = "Stop")
      #os.chdir(os.path.abspath('scanners'))
      threading.Thread(target=self.run_cmd, args=(os.path.abspath(launch_exe)+launch_args, self.tab2_treeview, self.drive_scan)).start()    
    
    def runtime_scanner(self):
     if self.proc_scan:
      self.proc_scan = False
      self.tab3_button.configure(text = "Start")
     else:
      launch_exe = 'scanners/hollows_hunter.exe'
      launch_args = '' #/quiet
      if self.settings['kill']:
          launch_args += ' /kill'
      if self.tab3_1_checkbox.get():
          launch_args += ' /shellc'
      if self.tab3_2_checkbox.get():
          launch_args += ' /hooks' #/iat
      if self.tab3_3_checkbox.get():
          launch_args += ' /data'
      if not os.path.exists(launch_exe):
        self.create_toplevel("Please wait for runtime scanner to install")
        if platform.architecture()[0] == '64bit':
          if os.name == 'nt':
             #latest_scanner = requests.get("https://api.github.com/repos/hasherezade/hollows_hunter/releases/latest").json()['url']
             #release_scanner = requests.get(latest_scanner).json()[3]['browser_download_url']
             #self.download_file(release_scanner)
            self.download_file('https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.4/hollows_hunter64.exe', launch_exe)
        else:
          if os.name == 'nt':
             #latest_scanner = requests.get("https://api.github.com/repos/hasherezade/hollows_hunter/releases/latest").json()['url']
             #release_scanner = requests.get(latest_scanner).json()[0a]['browser_download_url']
             #self.download_file(release_scanner)
            self.download_file('https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.4/hollows_hunter32.exe', launch_exe)
      self.proc_scan = True
      self.tab3_button.configure(text = "Stop")
      #os.chdir(os.path.abspath('scanners/loki'))
      threading.Thread(target=self.run_cmd, args=(os.path.abspath(launch_exe)+launch_args, self.tab3_treeview, self.proc_scan)).start()    
      
    def set_var(self, elem, setting):
        self.settings[setting] = elem.get()
        with open('settings.json', 'w') as config:
            config.write(json.dumps(self.settings))
    
    def create_toplevel(self, text):
        window = customtkinter.CTkToplevel(self)
        window.geometry("250x50")
        label = customtkinter.CTkLabel(window, text=text)
        label.pack(side="left", expand=False, padx=5, pady=0)
    
    def persistence(self):
      if os.name == 'nt':
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, 'HawkEye AntiMalware', 0, winreg.REG_SZ, os.path.abspath(sys.argv[0]))
        winreg.CloseKey(registry_key)

    def update(self):
        #ToDo: autoupdate like the engines
        try:
          version = requests.get("https://raw.githubusercontent.com/DivineSoftware/HawkEye/main/version").text
          if float(version)>float(self.VERSION):
            if tkinter.messagebox.askquestion("Update available", "Update HawkEye to the latest version?") == "yes":
                webbrowser.open("https://github.com/DivineSoftware/HawkEye/tags")
          else:
            if not self.settings['autoupdate']:
                tkinter.messagebox.showinfo("Latest version", "HawkEye antivirus is up to date")
        except Exception as e:
              print(e)
              if not self.settings['autoupdate']:
                tkinter.messagebox.showinfo("Failed to check for updates", "Please check your internet connection")

    '''
    def tab_changed(self, event):
        selection = event.widget.select()
        tab = event.widget.tab(selection, 'text')
    '''    
    def __init__(self):
        super().__init__()
        
        self.iconbitmap(os.path.abspath('assets/logo.ico'))
        self.VERSION = "1.0"
        self.picked_file = ""
        self.drive_scan = False
        self.proc_scan = False
        
        self.exceptions = [] #whitelisted file paths
        self.settings = {'submit':True, 'kill':True, 'detection_rate':4, 'autoupdate':True, 'persist':True, 'quarantinemalware':True} #json with settings
        self.quarantine = {} #blacklisted file paths

        self.virustotal_key = ""

        #PERSISTENCE/CONFIG CODE
        if not os.path.exists('whitelist.txt'):
            with open('whitelist.txt', 'w') as whitelist:
                whitelist.write('\n'.join(self.exceptions))
        else:
            with open('whitelist.txt', 'r') as whitelist:
              exceptions = whitelist.read().split('\n').remove('')
              if exceptions:
                self.exceptions = exceptions

        if not os.path.exists('quarantine.json'):
            with open('quarantine.json', 'w') as blacklist:
                blacklist.write('{}')
        else:
            with open('quarantine.json', 'r') as blacklist:
                self.quarantine = json.loads(blacklist.read())

        if not os.path.exists('settings.json'):
            with open('settings.json', 'w') as config:
                config.write(json.dumps(self.settings))
            if self.settings['autoupdate']:
                self.update()
            if self.settings['persist']:
                self.persistence()
        else:
            with open('settings.json', 'r') as config:
                self.settings = json.loads(config.read())
        if not os.path.exists('scanners'):
            os.mkdir('scanners')


        self.tk.call('lappend', 'auto_path', './theme/awdark')
        self.tk.call('package', 'require', 'awdark')

        self.title("HawkEye AntiMalware")
        self.geometry(f"{515}x{400}")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)  # call .on_closing() when app gets closed

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.style = ttk.Style()
        self.style.theme_use("awdark")
        self.style.configure("Notebook", font=("Roboto Medium", 11))

        self.logo_image = self.load_image("/assets/logo.png", 90, 90)
        self.logo_label = customtkinter.CTkLabel(master=self, image=self.logo_image)
        self.logo_label.grid(row=0, column=0, padx=(30, 0), pady=(15, 15))

        self.logo_text_image = self.load_image("/assets/logo_text.png", 300, 70)
        self.logo_text_label = customtkinter.CTkLabel(master=self, image=self.logo_text_image)
        self.logo_text_label.grid(row=0, column=1, padx=(0, 30), pady=(15, 15))

        self.tabControl = ttk.Notebook(self)
        #self.tabControl.bind("<<NotebookTabChanged>>", tab_changed)
        #customtkinter.CTkNotebook(root)
        self.tab1 = customtkinter.CTkFrame(self.tabControl)
        self.tab2 = customtkinter.CTkFrame(self.tabControl)
        self.tab3 = customtkinter.CTkFrame(self.tabControl)
        self.tab4 = customtkinter.CTkFrame(self.tabControl)
        self.tab5 = customtkinter.CTkFrame(self.tabControl)
        self.tabControl.add(self.tab1, text='File Scanner')
        self.scan_label = customtkinter.CTkLabel(master=self.tab1, text="Select a file to scan", text_font=("Roboto", -12))
        self.scan_label.grid(row=0, column=0, pady=(20, 0))

        self.find_image = self.load_image("/assets/search.png", 100, 100)
        self.find_button = customtkinter.CTkButton(master=self.tab1, image=self.find_image,
                                                   text="", fg_color="#2a2d2e",
                                                   hover_color="#2a2d2e", width=50, command=self.scan_button_event)
        #self.tab1.grid(row=0, column=0, sticky="NESW")
        self.tab1.grid_rowconfigure(2, weight=1)
        self.tab1.grid_columnconfigure(0, weight=1)
        self.find_button.grid(row=1, column=0) #, sticky="NESW"

        self.scan_button = customtkinter.CTkButton(master=self.tab1, text="Scan", height=32,
                                                   compound="right", command=self.scan_thread)
        self.scan_button.grid(row=2, column=0)
        
        self.result_label = customtkinter.CTkLabel(master=self.tab1, text="", text_font=("Roboto", -16))
        self.result_label.grid(row=3, column=0, pady=(20, 10), columnspan=3, sticky='NESW')
        
        try:
            VERSION = requests.get("https://github.com/DivineSoftware/HawkEye/raw/main/version", timeout=3).text
            if VERSION != self.VERSION and len(VERSION) == 3:
                self.statusbar = ttk.Label(self.tab1, text="Please update the program from https://github.com/DivineSoftware/HawkEye")
            else: self.statusbar = ttk.Label(self.tab1, text="You are using the latest version of HawkEye. Enjoy your security.")
        except:
            self.statusbar = ttk.Label(self.tab1, text="You are using the latest version of HawkEye. Enjoy your security.")
        self.statusbar.grid(row=4, column=0, sticky="NESW")

        self.tabControl.add(self.tab2, text='System Protection')
        self.tab2.grid_rowconfigure(0, weight=0)
        self.tab2.grid_rowconfigure(1, weight=0)
        self.tab2.grid_rowconfigure(2, weight=3)
        self.tab2.grid_columnconfigure((0, 1, 2), weight=1)

        self.tab2_1_checkbox = customtkinter.CTkCheckBox(master=self.tab2,
                                                         text="Scan all drives \n(Default - Only user C: drive)")
        self.tab2_1_checkbox.grid(row=0, column=0, columnspan=2, pady=(5, 5), padx=10, sticky="we")

        self.tab2_button = customtkinter.CTkButton(self.tab2, text="Start", fg_color=None, border_width=2, command=self.system_protection)
        self.tab2_button.grid(row=1, column=0, columnspan=3, pady=10, padx=10, sticky="sew")

        self.tab2_columns = ('file', 'path', 'scan')
        self.tab2_treeview = ttk.Treeview(master=self.tab2, columns=self.tab2_columns, show='headings')
        self.tab2_treeview.heading('file', text="Type")
        self.tab2_treeview.heading('path', text="File Path")
        self.tab2_treeview.heading('scan', text="Score")
        self.tab2_treeview.column('file', width=40, anchor=tkinter.CENTER)
        self.tab2_treeview.column('path', width=70, anchor=tkinter.CENTER)
        self.tab2_treeview.column('scan', width=40, anchor=tkinter.CENTER)
        self.tab2_treeview.grid(row=2, column=0, columnspan=3, sticky='nswe')
        
        #self.tab2_scrollbar = ttk.Scrollbar(master=self.tab2, orient="vertical", command=self.tab2_treeview.yview)
        #self.tab2_scrollbar.grid(row=2, column=3)
        #self.tab2_treeview.configure(yscrollcommand=self.tab2_scrollbar.set)
        
        self.tabControl.add(self.tab3, text='Runtime Scanner')
        self.tab3.grid_rowconfigure(0, weight=0)
        self.tab3.grid_rowconfigure(1, weight=0)
        self.tab3.grid_rowconfigure(2, weight=3)
        self.tab3.grid_columnconfigure((0, 1, 2), weight=1)

        self.tab3_1_checkbox = customtkinter.CTkCheckBox(master=self.tab3, text="Scan non executable memory")
        self.tab3_1_checkbox.grid(row=0, column=0, pady=10, padx=10, sticky="w")
        
        self.tab3_2_checkbox = customtkinter.CTkCheckBox(master=self.tab3, text="Detect hooks")
        self.tab3_2_checkbox.grid(row=0, column=1, pady=10, padx=10, sticky="we")

        self.tab3_3_checkbox = customtkinter.CTkCheckBox(master=self.tab3, text="Detect shellcode")
        #self.tab3_3_checkbox.grid(row=0, column=2, pady=10, padx=10, sticky="e")

        self.tab3_button = customtkinter.CTkButton(self.tab3, text="Start", fg_color=None, border_width=2, command=self.runtime_scanner)
        self.tab3_button.grid(row=1, column=0, columnspan=3, pady=10, padx=10, sticky="we")

        self.tab3_columns = ('file', 'path', 'scan')
        self.tab3_treeview = ttk.Treeview(master=self.tab3, columns=self.tab3_columns, show='headings')
        self.tab3_treeview.heading('file', text="File/Process Name")
        self.tab3_treeview.heading('path', text="File Path")
        self.tab3_treeview.heading('scan', text="Scan result")
        self.tab3_treeview.column('file', width=40, anchor=tkinter.CENTER)
        self.tab3_treeview.column('path', width=70, anchor=tkinter.CENTER)
        self.tab3_treeview.column('scan', width=40, anchor=tkinter.CENTER)
        self.tab3_treeview.grid(row=2, column=0, columnspan=3, sticky='nswe')

        self.tabControl.add(self.tab4, text='Quarantine')
        self.tab4.grid_columnconfigure(1, weight=1)
        self.tab4.grid_rowconfigure(2, weight=1)

        self.style.configure("Treeview.Heading", font=("Roboto Medium", 11))

        self.columns = ('file', 'path', 'scan')
        self.quarantine_treeview = ttk.Treeview(master=self.tab4, columns=self.columns, show='headings')
        self.quarantine_treeview.heading('file', text="File/Process Name")
        self.quarantine_treeview.heading('path', text="File Path")
        self.quarantine_treeview.heading('scan', text="Origin")
        self.quarantine_treeview.column('file', width=40, anchor=tkinter.CENTER)
        self.quarantine_treeview.column('path', width=70, anchor=tkinter.CENTER)
        self.quarantine_treeview.column('scan', width=40, anchor=tkinter.CENTER)
        self.quarantine_treeview.grid(row=0, column=0, columnspan=2, rowspan=3, sticky='nswe')

        for key, item in self.quarantine.items():
            self.quarantine_treeview.insert("", 'end', values=(item[0], item[1], item[2]))

        self.menu = tkinter.Menu(tearoff=False)
        #ToDo: dialog with file info
        #self.menu.add_command(label="Show info", command=self.show_info)
        self.menu.add_command(label="Open file location", command=self.open_explorer)
        self.menu.add_command(label="Allow file", command=self.remove_quarantine)
        self.menu.add_separator()
        self.menu.add_command(label="Delete from computer", command=self.delete_file)

        self.quarantine_treeview.bind("<Button-3>", self.menu_popup)


        self.tabControl.add(self.tab5, text='Settings')
        #self.tab5.grid_rowconfigure(0, weight=1)
        #self.tab5.grid_rowconfigure(1, weight=0)
        self.tab5.grid_columnconfigure((0, 1), weight=1)

        self.tab5_1_checkbox = customtkinter.CTkCheckBox(master=self.tab5, text="Auto kill malicious process", command=lambda:self.set_var(self.tab5_1_checkbox, 'kill'))
        self.tab5_1_checkbox.grid(row=1, column=0, pady=10, padx=10, sticky="we") 

        self.tab5_2_checkbox = customtkinter.CTkCheckBox(master=self.tab5, text="Submit samples to VirusTotal", command=lambda:self.set_var(self.tab5_2_checkbox, 'submit'))
        self.tab5_2_checkbox.grid(row=1, column=1, pady=10, padx=10, sticky="we")
        
        self.tab5_3_checkbox = customtkinter.CTkCheckBox(master=self.tab5, text="Start on boot", command=lambda:self.set_var(self.tab5_3_checkbox, 'persist'))
        self.tab5_3_checkbox.grid(row=2, column=0, pady=10, padx=10, sticky="we")
        
        self.tab5_4_checkbox = customtkinter.CTkCheckBox(master=self.tab5, text="Auto quarantine malware", command=lambda:self.set_var(self.tab5_4_checkbox, 'quarantinemalware'))
        self.tab5_4_checkbox.grid(row=3, column=0, columnspan=3, pady=10, padx=10, sticky="we")

        self.tab5_5_checkbox = customtkinter.CTkCheckBox(master=self.tab5, text="Auto update", command=lambda:self.set_var(self.tab5_5_checkbox, 'autoupdate'))
        self.tab5_5_checkbox.grid(row=2, column=1, pady=10, padx=10, sticky="we")
        
        #ToDo: write a log file option
        
        if self.settings['kill']:
            self.tab5_1_checkbox.select()
        if self.settings['submit']:
            self.tab5_2_checkbox.select()
        if self.settings['persist']:
            self.tab5_3_checkbox.select()
        if self.settings['quarantinemalware']:
            self.tab5_4_checkbox.select()
        if self.settings['autoupdate']:
            self.tab5_5_checkbox.select()

        self.tab5_button = customtkinter.CTkButton(self.tab5, text="Edit whitelist", fg_color=None, border_width=2, command=self.whitelist_editor)
        self.tab5_button.grid(row=0, column=0, columnspan=3, pady=10, padx=10, sticky="sew")

        self.tab5_1_button = customtkinter.CTkButton(self.tab5, text="Update", command=self.update)
        self.tab5_1_button.grid(row=4, column=0, columnspan=3, pady=10, padx=10, sticky="sew")

        self.tabControl.grid(row=1, column=0, rowspan=2, columnspan=2, sticky="nsew")
            
    def menu_popup(self, e):
            #if len(self.quarantine_treeview.selection()) > 1:
            #self.menu.tk_popup(e.x_root, e.y_root)
            #else:
            iid = self.quarantine_treeview.identify_row(e.y)
            if iid:
                self.quarantine_treeview.selection_set(iid)
                self.menu.tk_popup(e.x_root, e.y_root)
            else:
                pass

    def load_image(self, path, width, height):
        """ load rectangular image with path relative to PATH """
        return ImageTk.PhotoImage(Image.open(PATH + path).resize((width, height)))

    def on_closing(self, event=0):
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()