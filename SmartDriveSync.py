import queue, os, shutil, threading, ctypes, hashlib, xxhash, time, psutil, win32api, win32con, aiofiles as aiofiles, tkinter as tk
from tkinter import filedialog, messagebox, Tk, Button, Label, Entry, StringVar, Text, Scrollbar, END, N, S, E, W, CENTER, Frame, LEFT, Checkbutton, BooleanVar
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor
from tkinter.ttk import Sizegrip
from hashlib import md5
from collections import defaultdict
from DriveWatch import DriveWatch

root = Tk()

src_folder_path = StringVar()
src_folder_path.set("")
dest_folder_path = StringVar()
dest_folder_path.set("")

current_file_var = StringVar()

mainframe = ttk.Frame(root, padding="12 12 12 12")
mainframe.grid(column=0, row=0, sticky=(N, S, E, W))

class SmartDriveSyncApp:
    def __init__(self, master, drive_watch, update_interval=5):
        super().__init__()
        self.master = master
        self.update_queue = queue.Queue()
        self.update_label_from_queue()
        self.is_closed = False
        self.drive_watch = drive_watch
        self.is_running = True
        self.master = master
        self.stop_event = threading.Event()
        self.partition_info = {}
        self.src_folder_path = StringVar()
        self.dest_folder_path = StringVar()
        self.stop_sync_flag = False
        self.use_hash = BooleanVar()
        self.remove_excess = BooleanVar()
        self.current_src_file_path = StringVar()
        self.sync_thread = None
        self.compare_mod_date = BooleanVar()
        self.compare_mod_date.set(True)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.drive_letters = self.extract_drive_letters(drive_watch.partition_info)
        self.drive_labels = {}
        self.drive_letters = {'src': None, 'dest': None}

        self.speed_frame = ttk.Frame(master)
        self.speed_frame.grid(column=3, row=0, rowspan=4, sticky=(N, S, E, W))

        self.speed_label = Label(self.speed_frame, text="", justify=LEFT, font=("Courier", 10))
        self.speed_label.grid(column=0, row=0, sticky=(N, S, E, W), pady=10)

        self.speed_info_vars = {}

        self.sizegrip = ttk.Sizegrip(self.speed_frame)
        self.sizegrip.grid(column=2, row=6, sticky=(S, E))

        self.drive_watch.register_callback(self.update_speed_label)


    def update_disk_speed_info(self, speed_info):
        for partition_index, (read_speed, write_speed) in speed_info.items():
            if partition_index in self.speed_info_vars:
                total_speed = read_speed + write_speed
                speed_var = self.speed_info_vars[partition_index]
                drive_letter = self.drive_watch.partition_info[partition_index].split()[0]
                speed_var.set(f"{drive_letter}: {total_speed:.2f} MB/s")

    def extract_drive_letters(self, partition_info):
        drive_letters = []
        for partitions in partition_info.values():
            for partition in partitions:
                drive_letter = partition[0].split(" ")[0]
                drive_letters.append(drive_letter)
        return drive_letters

    def get_drive_from_path(self, path):
        if not path:
            return None
        return path[0].upper() + ':'

    def update_partition_info(self, new_partition_info):
        self.partition_info = new_partition_info

    def on_closing(self):
        self.stop_sync_threads()
        drive_watch.stop()
        self.is_closed = True
        self.stop_event.set()
        self.master.destroy()

    def stop_sync_threads(self):
        if self.sync_thread is not None and self.sync_thread.is_alive():
            self.stop_sync_flag = True
            self.sync_thread.join()

    def browse_src_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.src_folder_path.set(directory)
            src_folder_entry.delete(0, END)
            src_folder_entry.insert(0, directory)
            src_drive_letter = self.get_drive_from_path(directory)
            if src_drive_letter:
                self.drive_letters['src'] = src_drive_letter
        self.update_disk_speed_info(self.drive_watch.get_speed_info())

    def browse_dest_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dest_folder_path.set(directory)
            dest_folder_entry.delete(0, END)
            dest_folder_entry.insert(0, directory)
            dest_drive_letter = self.get_drive_from_path(directory)
            if dest_drive_letter:
                self.drive_letters['dest'] = dest_drive_letter
        self.update_disk_speed_info(self.drive_watch.get_speed_info())

    def update_speed_label(self, speed_info):
        self.update_speed_label_ui(speed_info)
        drive_letters = app.drive_letters
        partition_info = app.partition_info
        speed_text = ""
        for key, drive_letter in drive_letters.items():
            if drive_letter:
                partition_index = app.drive_watch.extract_partition_index(drive_letter)
                read_speed_mb, write_speed_mb = speed_info.get(partition_index, (0, 0))
                speed_text += f"{drive_letter} Read: {read_speed_mb:.2f} MB/s, Write: {write_speed_mb:.2f} MB/s\n"
        if self.speed_label is not None:
            self.update_queue.put(speed_text)

    def update_speed_label_ui(self, speed_info):
        if self.is_closed:
            return
        drive_letters = app.drive_letters
        partition_info = app.partition_info
        speed_text = ""
        for key, drive_letter in drive_letters.items():
            if drive_letter:
                partition_index = app.drive_watch.extract_partition_index(drive_letter)
                read_speed_mb, write_speed_mb = speed_info.get(partition_index, (0, 0))
                speed_text += f"{drive_letter} Read: {read_speed_mb:.2f} MB/s, Write: {write_speed_mb:.2f} MB/s\n"
        if self.speed_label is not None:
            self.speed_label['text'] = speed_text

    def update_label_from_queue(self):
        try:
            speed_text = self.update_queue.get_nowait()
            self.speed_label['text'] = speed_text
        except queue.Empty:
            pass
        self.master.after(100, self.update_label_from_queue)

    def set_speed_label_text(self, text):
        self.speed_label['text'] = text

    def initialize_paths(self):
        src_directory = src_folder_path.get()
        dest_directory = dest_folder_path.get()
        if src_directory:
            self.src_folder_path.set(src_directory)
            src_folder_entry.delete(0, END)
            src_folder_entry.insert(0, src_directory)
            src_drive_letter = self.get_drive_from_path(src_directory)
            if src_drive_letter:
                self.drive_letters['src'] = src_drive_letter
        if dest_directory:
            self.dest_folder_path.set(dest_directory)
            dest_folder_entry.delete(0, END)
            dest_folder_entry.insert(0, dest_directory)
            dest_drive_letter = self.get_drive_from_path(dest_directory)
            if dest_drive_letter:
                self.drive_letters['dest'] = dest_drive_letter
        self.update_disk_speed_info(self.drive_watch.get_speed_info())

def set_file_to_normal(file_path):
    try:
        win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
        return True
    except BaseException:
        return False

thread_limiter = threading.Semaphore(2)

def start_sync_thread():
    if not thread_limiter.acquire(blocking=False):
        messagebox.showerror("Error", "There are already two synchronization processes running.")
        return
    SmartDriveSyncApp.stop_sync_flag = False
    progress_bar.grid(column=1, row=4, sticky=(E, W))
    progress_bar.start()
    app.initialize_paths()

    def sync_thread_wrapper():
        try:
            start_sync()
        except Exception as e:
            print(f"Error in sync_thread_wrapper: {e}")
        finally:
            thread_limiter.release()

    SmartDriveSyncApp.sync_thread = threading.Thread(target=sync_thread_wrapper)
    SmartDriveSyncApp.sync_thread.start()
    print("Sync thread started")

def has_admin_permission(folder_path):
    try:
        return os.access(folder_path, os.W_OK)
    except BaseException:
        return False

def update_progress_bar(progress_bar):
    if SmartDriveSyncApp.stop_sync_flag:
        progress_bar.stop()
        progress_bar.grid_remove()
        return
    progress_bar.step(1)
    root.after(300, lambda: update_progress_bar(progress_bar))

def hash_file(file_path, block_size=65536, sample_size=65536, num_samples=3):
    hasher = xxhash.xxh64()
    try:
        with open(file_path, "rb") as f:
            file_size = os.path.getsize(file_path)
            if file_size < sample_size * num_samples:
                for block in iter(lambda: f.read(block_size), b""):
                    hasher.update(block)
            else:
                step = (file_size - sample_size) // (num_samples - 1)
                for i in range(num_samples):
                    f.seek(i * step)
                    block = f.read(sample_size)
                    hasher.update(block)
    except PermissionError:
        return None
    return hasher.hexdigest()

def should_copy(src_file_path, dest_file_path, use_hash, compare_mod_date):
    if not os.path.exists(dest_file_path):
        return True
    if not use_hash and not compare_mod_date:
        return False
    if os.path.getsize(src_file_path) != os.path.getsize(dest_file_path):
        return True
    if compare_mod_date:
        src_mod_time = os.path.getmtime(src_file_path)
        dest_mod_time = os.path.getmtime(dest_file_path)
        return src_mod_time > dest_mod_time
    if use_hash:
        src_hash = hash_file(src_file_path)
        dest_hash = hash_file(dest_file_path)
        return src_hash != dest_hash

def is_system_directory(folder_path):
    return os.path.isdir(folder_path) and ctypes.windll.kernel32.GetFileAttributesW(folder_path) & 0x4 == 0x4

def copy_file(src_file_path, dest_file_path, status_text, root):
    try:
        shutil.copy2(src_file_path, dest_file_path)
        global copied_count
        copied_count += 1
        root.after(0, status_text.insert, END, f"Copied: {src_file_path} -> {dest_file_path}\nCurrent working path: {os.getcwd()}\n")
    except Exception as e:
        root.after(0, status_text.insert, END, f"Error copying file {src_file_path} to {dest_file_path}: {e}\n")

def remove_excess_files_and_dirs(src, dest, status_text, remove_excess, current_src_file_path, handled_dest_files):
    deleted_count = 0
    ignored_directories = {"System Volume Information", "$RECYCLE.BIN"}

    for dest_root, dest_dirs, dest_files in os.walk(dest, topdown=False):
        src_root = os.path.join(src, os.path.relpath(dest_root, dest))
        current_src_file_path.set(f"Current working path: {dest_root}")

        for dest_file in dest_files:
            src_file_path = os.path.join(src_root, dest_file)
            dest_file_path = os.path.join(dest_root, dest_file)

            if dest_file_path not in handled_dest_files and not os.path.exists(src_file_path) and not is_system_file(dest_file_path) and has_admin_permission(dest_file_path):
                try:
                    set_file_to_normal(dest_file_path)
                    os.remove(dest_file_path)
                    deleted_count += 1
                except Exception as e:
                    status_text.insert(END, f"Error removing excess file {dest_file_path}: {e}\n")
                    status_text.see(END)
                    status_text.update()

        for dest_dir in dest_dirs:
            src_dir_path = os.path.join(src_root, dest_dir)
            dest_dir_path = os.path.join(dest_root, dest_dir)

            if dest_dir_path not in handled_dest_files and not os.path.exists(src_dir_path) and not is_system_directory(dest_dir_path) and has_admin_permission(dest_dir_path) and dest_dir not in ignored_directories:
                try:
                    shutil.rmtree(dest_dir_path, ignore_errors=True)
                    deleted_count += 1
                    status_text.insert(END, f"Moved excess directory: {dest_dir_path}\n")
                    status_text.see(END)
                    status_text.update()
                except Exception as e:
                    status_text.insert(END, f"Error removing excess directory {dest_dir_path}: {e}\n")
                    status_text.see(END)
                    status_text.update()

    return deleted_count

def file_exists_in_dest(src_file_path, dest, src):
    src_rel_path = os.path.relpath(src_file_path, src)
    dest_file_path = os.path.join(dest, src_rel_path)
    if os.path.exists(dest_file_path):
        return dest_file_path
    for root, _, files in os.walk(dest):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.exists(dest_file_path) and os.path.basename(src_file_path) == os.path.basename(file_path):
                return file_path
    return None

def update_status_text(text):
    status_text.insert(END, text)
    status_text.yview(END)

def is_system_file(file_path):
    try:
        FILE_ATTRIBUTE_SYSTEM = 0x4
        file_attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        return file_attrs & FILE_ATTRIBUTE_SYSTEM == FILE_ATTRIBUTE_SYSTEM
    except Exception:
        return False
def sync_directories(src, dest, status_text, progress_bar, use_hash, remove_excess, root, compare_mod_date):
#def sync_directories(src, dest, status_text, progress_bar, use_hash, remove_excess, SmartDriveSyncApp, compare_mod_date):
    global renamed_count, moved_count, copied_count

    def init_counts():
        global copied_count, deleted_count, renamed_count, moved_count
        copied_count = 0
        deleted_count = 0
        renamed_count = 0
        moved_count = 0

    init_counts()

    def get_hash(file_path, hashes_cache={}):
        if file_path not in hashes_cache:
            hashes_cache[file_path] = hash_file(file_path)
        return hashes_cache[file_path]

    if not os.path.exists(src) or not os.path.exists(dest):
        messagebox.showerror("Error", "Both source and destination directories must exist.")
        return 0, 0, 0, 0

    src_folders = [src]
    current_src_file_path.set(f"Current working path: {src}")
    hashes_cache = {}

    handled_dest_files = set()
    for src_root, src_dirs, src_files_list in os.walk(src):
        for src_file in src_files_list:
            src_file_path = os.path.join(src_root, src_file)
            existing_dest_file_path = file_exists_in_dest(src_file_path, dest, src)
            if existing_dest_file_path:
                handled_dest_files.add(existing_dest_file_path)

        src_folder = src_folders.pop(0)

        if not os.path.exists(src) or not os.path.exists(dest):
            messagebox.showerror("Error", "Both source and destination directories must exist.")
            return copied_count, deleted_count, renamed_count, moved_count

        try:
            src_files = {}
            dest_files = {}

            for src_root, src_dirs, src_files_list in os.walk(src):
                if SmartDriveSyncApp.stop_sync_flag:
                    break
                for src_file in src_files_list:
                    src_file_path = os.path.join(src_root, src_file)
                    src_files[src_file] = src_file_path

                root.after(0, update_status_text, f"Current working path: {src_root}\n")
                status_text.see(END)
                status_text.update()

            for dest_root, dest_dirs, dest_files_list in os.walk(dest):
                if SmartDriveSyncApp.stop_sync_flag:
                    break
                for dest_file in dest_files_list:
                    dest_file_path = os.path.join(dest_root, dest_file)
                    dest_files[dest_file] = dest_file_path

            for src_file, src_file_path in src_files.items():
                if SmartDriveSyncApp.stop_sync_flag:
                    break

                src_rel_path = os.path.relpath(src_file_path, src)
                dest_file_path = os.path.join(dest, src_rel_path)
                handled_dest_files.add(dest_file_path)
                if dest_file_path not in dest_files.values():
                    src_hash = get_hash(src_file_path, hashes_cache)
                    if src_hash is None:
                        continue
                    found_match = False

                    for dest_file, dest_file_path in dest_files.items():
                        if SmartDriveSyncApp.stop_sync_flag:
                            break

                        dest_hash = get_hash(dest_file_path, hashes_cache)
                        if dest_hash is None:
                            continue

                        if src_hash == dest_hash:
                            found_match = True

                            if src_file != dest_file:
                                new_dest_file_path = os.path.join(os.path.dirname(dest_file_path), src_file)
                                os.rename(dest_file_path, new_dest_file_path)
                                renamed_count += 1
                                status_text.insert(END, f"Renamed: {dest_file_path} -> {new_dest_file_path}\nCurrent working path: {os.getcwd()}\n")
                                status_text.see(END)
                                status_text.update()
                                dest_file_path = new_dest_file_path

                            correct_dest_path = os.path.join(dest, os.path.relpath(os.path.dirname(src_file_path), src))
                            correct_dest_path = os.path.abspath(correct_dest_path)

                            if os.path.normpath(os.path.dirname(dest_file_path)) != os.path.normpath(correct_dest_path):
                                if not os.path.exists(correct_dest_path):
                                    os.makedirs(correct_dest_path)
                                    status_text.insert(END, f"Created directory: {correct_dest_path}\n")
                                    status_text.see(END)
                                    status_text.update()

                                shutil.move(dest_file_path, os.path.join(correct_dest_path, src_file))
                                moved_count += 1
                                status_text.insert(END, f"Moved: {dest_file_path} -> {os.path.join(correct_dest_path, src_file)}\n")
                                status_text.see(END)
                                status_text.update()

                            del dest_files[dest_file]
                            break

                    if not found_match:
                        if SmartDriveSyncApp.stop_sync_flag:
                            break

                        dest_file_path = os.path.join(dest, os.path.relpath(src_file_path, src))
                        dest_dir = os.path.dirname(dest_file_path)

                        if not os.path.exists(dest_dir):
                            os.makedirs(dest_dir)
                            status_text.insert(END, f"Created directory: {dest_dir}\n")
                            status_text.see(END)
                            status_text.update()

                        copy_file(src_file_path, dest_file_path, status_text, root)

            for src_root, src_dirs, src_files_list in os.walk(src):
                if SmartDriveSyncApp.stop_sync_flag:
                    break

                dest_root = os.path.join(dest, os.path.normpath(os.path.relpath(src_root, src)))
                if not os.path.exists(dest_root):
                    os.makedirs(dest_root)
                    status_text.insert(END, f"Created directory: {dest_root}\nCurrent working path: {dest_root}\n")
                    status_text.see(END)
                    status_text.update()
                for src_file in src_files_list:
                    src_file_path = os.path.join(src_root, src_file)
                    dest_file_path = os.path.join(dest_root, src_file)
                    existing_dest_file_path = file_exists_in_dest(src_file_path, dest, src)
                    if existing_dest_file_path:
                        if should_copy(src_file_path, existing_dest_file_path, use_hash, compare_mod_date):
                            if os.path.normpath(dest_file_path) != os.path.normpath(existing_dest_file_path):
                                correct_dest_path = os.path.join(dest, os.path.relpath(os.path.dirname(src_file_path), src))
                                if not os.path.exists(correct_dest_path):
                                    os.makedirs(correct_dest_path)
                                    status_text.insert(END, f"Created directory: {correct_dest_path}\n")
                                    status_text.see(END)
                                    status_text.update()
                                shutil.move(existing_dest_file_path, os.path.join(correct_dest_path, src_file))
                                moved_count += 1
                                status_text.insert(END, f"Moved: {existing_dest_file_path} -> {os.path.join(correct_dest_path, src_file)}\n")
                                status_text.see(END)
                                status_text.update()
                            else:
                                copy_file(src_file_path, dest_file_path, status_text, root)
                    elif not existing_dest_file_path:
                        copy_file(src_file_path, dest_file_path, status_text, root)

            if remove_excess.get():
                deleted_count = remove_excess_files_and_dirs(src, dest, status_text, remove_excess.get(), current_src_file_path, handled_dest_files)
            else:
                deleted_count = 0

        finally:
            progress_bar.stop()
            progress_bar.grid_forget()

            return copied_count, deleted_count, renamed_count, moved_count

def start_sync():
    src = src_folder_path.get()
    dest = dest_folder_path.get()

    if not src or not dest:
        messagebox.showerror("Error", "Both source and destination directories must be specified.")
        return

    global stop_sync_flag
    stop_sync_flag = False

    status_text.delete(1.0, END)
    status_text.insert(END, "Synchronization started...\n")
    status_text.see(END)
    status_text.update()

    progress_bar.grid(column=1, row=4, sticky=(E, W))
    root.after(100, lambda: update_progress_bar(progress_bar))
    update_progress_bar(progress_bar)

    copied_count, deleted_count, renamed_count, moved_count = sync_directories(src, dest, status_text, progress_bar, use_hash, remove_excess, root, compare_mod_date.get())
    status_text.insert(END, f"Synchronization completed.\n"
                        f"Files copied: {copied_count}\n"
                        f"Files renamed: {renamed_count}\n"
                        f"Files moved: {moved_count}\n"
                        f"Files deleted: {deleted_count}\n")
    status_text.see(END)

    
def stop_sync():
    SmartDriveSyncApp.stop_sync_flag = True
    global stop_sync_flag
    stop_sync_flag = True

def update_status_and_stop_progress_bar(status_text, progress_bar, copied_count, deleted_count, renamed_count, moved_count):
    status_text.insert(END, f"Synchronization finished. {copied_count} items copied, {deleted_count} items removed, {renamed_count} items renamed, {moved_count} items moved.\n")
    status_text.see(END)
    progress_bar.stop()

root.title("Directory Synchronization")

drive_watch = DriveWatch()

app = SmartDriveSyncApp(root, drive_watch)
drive_watch.start()

app.update_disk_speed_info(drive_watch.get_speed_info())

current_file_var = StringVar()

use_hash = BooleanVar(value=False)
remove_excess = BooleanVar(value=False)
compare_mod_date = BooleanVar(value=True)

ttk.Label(mainframe, text="Source directory:").grid(column=0, row=0, sticky=W)
src_folder_entry = ttk.Entry(mainframe, width=50, textvariable=src_folder_path)
src_folder_entry.grid(column=1, row=0, sticky=(E, W))
ttk.Button(mainframe, text="Browse", command=app.browse_src_directory).grid(column=2, row=0, sticky=W)

ttk.Label(mainframe, text="Destination directory:").grid(column=0, row=1, sticky=W)
dest_folder_entry = ttk.Entry(mainframe, width=50, textvariable=dest_folder_path)
dest_folder_entry.grid(column=1, row=1, sticky=(E, W))
ttk.Button(mainframe, text="Browse", command=app.browse_dest_directory).grid(column=2, row=1, sticky=W)
ttk.Checkbutton(mainframe, text="Remove excess files and directories at the destination", variable=remove_excess).grid(column=1, row=2, sticky=W)
ttk.Checkbutton(mainframe, text="Compare and copy files by modified date", variable=compare_mod_date).grid(column=1, row=3, sticky=W)

start_button = ttk.Button(mainframe, text="Start", command=start_sync_thread)
start_button.grid(column=0, row=4, sticky=W)

progress_bar = ttk.Progressbar(mainframe, mode='indeterminate')
progress_bar.grid(column=1, row=4, sticky=(E, W))
progress_bar.grid_remove()

stop_button = ttk.Button(mainframe, text="Stop", command=stop_sync)
stop_button.grid(column=2, row=4, sticky=W)

current_file_label = ttk.Label(mainframe, textvariable=current_file_var)
current_file_label.grid(column=1, row=6, sticky=W)

mainframe.rowconfigure(4, weight=1)
app.speed_frame.grid(column=0, row=4, columnspan=3, sticky=(N, S, E, W))

app.speed_frame.columnconfigure(0, weight=1)
app.speed_frame.rowconfigure(0, weight=1)
app.speed_label.grid(column=0, row=0, sticky=(N, S, E, W))

current_src_file_path = StringVar()
current_src_file_label = ttk.Label(mainframe, textvariable=current_src_file_path)

status_text = Text(mainframe, wrap="word", width=50, height=10)
status_text.grid(column=1, row=5, sticky=(N, S, E, W))
status_scroll = ttk.Scrollbar(mainframe, orient="vertical", command=status_text.yview)
status_scroll.grid(column=2, row=5, sticky=(N, S, W))
status_text["yscrollcommand"] = status_scroll.set

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)
mainframe.rowconfigure(5, weight=1)

root.mainloop()

 
