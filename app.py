import tkinter as tk
from tkinter import scrolledtext, messagebox
import sys
import threading
from main import process_vulnerabilities, validate_vuln_id

class StdoutRedirect:
    def __init__(self, widget):
        self.widget = widget
        self.original_stdout = sys.stdout

    def write(self, text):
        def append():
            self.widget.configure(state='normal')
            self.widget.insert(tk.END, text)
            self.widget.configure(state='disabled')
            self.widget.yview(tk.END)
        self.widget.after(0, append)

    def flush(self):
        pass

def start_process():
    start_id = entry.get().strip()
    if not validate_vuln_id(start_id):
        messagebox.showerror('Invalid Input', 'Некорректный формат ID. Пример: 2025-00000')
        return

    enable_logs = log_var.get()

    output_text.configure(state='normal')
    output_text.delete(1.0, tk.END)
    output_text.configure(state='disabled')

    # Перенаправление stdout в text_widget
    redirector = StdoutRedirect(output_text)
    sys.stdout = redirector

    # Запуск в фоне
    thread = threading.Thread(target=run_process, args=(start_id, enable_logs))
    thread.start()

def run_process(start_id, enable_logs):
    process_vulnerabilities(start_id, enable_logs)
    sys.stdout = sys.stdout.original_stdout

# Настройка GUI
root = tk.Tk()
root.title('Парсер ФСТЭК')
root.geometry('800x400')

tk.Label(root, text='Введите начальный ID уязвимости (например, 2025-00000):').pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

log_var = tk.BooleanVar()
tk.Checkbutton(root, text='Включить логирование в файл', variable=log_var).pack(pady=5)

tk.Button(root, text='Start', command=start_process).pack(pady=10)

output_text = scrolledtext.ScrolledText(root, state='disabled', height=15, font=('Courier', 10))
output_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

root.mainloop()
