from threading import Event
import os
import psutil
import time
import threading
import wmi
import ctypes
import win32api


class DriveWatch:
    def __init__(self, num_drives=26, update_interval=1):
        self.update_interval = update_interval
        self.partition_info = self.get_partition_info()
        self.callbacks = []
        self.monitor_thread = None
        self.stop_event = threading.Event()
        self.speed_info = {}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def get_speed_info(self, drive_name=None):
        if drive_name is None:
            return self.speed_info
        else:
            return self.speed_info.get(drive_name, (0, 0))

    def update_speed_info(self):
        try:
            raw_speed_info = self.perf_counters.get_speed_info()
            speed_info = {}

            for drive_number, speed in raw_speed_info.items():
                drive_letter = self.get_drive_letter_by_physical_drive(drive_number)
                if drive_letter:
                    speed_info[drive_letter] = speed

            self.speed_info_lock.acquire()
            self.speed_info = speed_info
            self.speed_info_lock.release()
        except Exception as e:
            print("Exception in update_speed_info:", e)

    def get_drive_letter_by_physical_drive(self, physical_drive_number):
        for drive_letter, drive_info in self.drive_info.items():
            if drive_info['physical_drive_number'] == physical_drive_number:
                return drive_letter
        return None

    @staticmethod
    def get_drive_from_path(path):
        return os.path.splitdrive(os.path.abspath(path))[0]

    @staticmethod
    def get_physical_drives():
        return win32api.GetLogicalDriveStrings().split('\x00')[:-1]

    def get_volume_label(self, drive_letter):
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        buf = ctypes.create_unicode_buffer(1024)
        n = kernel32.GetVolumeInformationW(
            drive_letter + "\\", buf, 1024, None, None, None, None, 0)

        if n == 0:
            return ""

        return buf.value
        
    def is_cdrom_drive(self, drive_letter):
        c = wmi.WMI()
        cdrom_drives = [cdrom.Drive for cdrom in c.Win32_CDROMDrive()]
        return drive_letter in cdrom_drives

    def get_partition_info(self):
        partition_info_physical = {}
        partition_info_logical = {}
        partition_info_combined = {}
        c = wmi.WMI()
        existing_indices = set()
        existing_drive_letters = set()

        for disk in c.Win32_DiskDrive():
            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    partition_letter = logical_disk.DeviceID
                    if self.is_cdrom_drive(partition_letter):
                        continue
                    volume_label = self.get_volume_label(partition_letter)
                    partition_info_physical.setdefault(disk.Index, []).append(f"{partition_letter} ({volume_label})")
                    existing_drive_letters.add(partition_letter.split(":")[0])
                    existing_indices.add(disk.Index)

        next_available_index = 0
        for drive in c.Win32_LogicalDisk():
            drive_letter = drive.DeviceID.split(":")[0]
            if drive_letter not in existing_drive_letters and not self.is_cdrom_drive(drive.DeviceID):
                while next_available_index in existing_indices:
                    next_available_index += 1
                volume_label = self.get_volume_label(drive.DeviceID)
                partition_info_logical[next_available_index] = [f"{drive.DeviceID} ({volume_label})"]
                existing_indices.add(next_available_index)

        partition_info_combined = partition_info_physical.copy()
        for key, value in partition_info_logical.items():
            partition_info_combined[key] = value

        return partition_info_combined


    def register_callback(self, callback):
        self.callbacks.append(callback)

    def unregister_callback(self, callback):
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def start(self):
        self.stop_event.clear()
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(
                target=self.monitor_disk_speed, args=(
                    self.partition_info,))
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

    def stop(self):
        print("Stopping monitor thread")
        self.stop_event.set()

    def monitor_disk_speed(self, partition_info):

        def get_disk_io_counters():
            disk_io_counters = psutil.disk_io_counters(perdisk=True)
            return {k: (v.read_bytes, v.write_bytes)
                    for k, v in disk_io_counters.items()}

        prev_disk_io_counters = get_disk_io_counters()

        while not self.stop_event.is_set():
            time.sleep(self.update_interval)
            current_disk_io_counters = get_disk_io_counters()

            speed_info = {}
            for disk_name, (read_bytes,
                            write_bytes) in current_disk_io_counters.items():
                if disk_name in prev_disk_io_counters:
                    prev_read_bytes, prev_write_bytes = prev_disk_io_counters[disk_name]
                    read_speed = (read_bytes - prev_read_bytes) / \
                        (1024 * 1024) / self.update_interval
                    write_speed = (write_bytes - prev_write_bytes) / \
                        (1024 * 1024) / self.update_interval
                    speed_info[disk_name] = (read_speed, write_speed)

            corrected_speed_info = {}
            for partition_index, drive_info in self.partition_info.items():
                # Get the drive letter, e.g., 'C:' from 'C: (System)'
                drive_letter = drive_info[0]
                drive_name = f"PhysicalDrive{partition_index}"
                if drive_name in speed_info:
                    corrected_speed_info[partition_index] = speed_info[drive_name]

            self.speed_info = corrected_speed_info

            for callback in self.callbacks:
                callback(self.speed_info)
            prev_disk_io_counters.update(current_disk_io_counters)


    def extract_drive_letters(self, partition_info):
        drive_letters = []
        for partitions in partition_info.values():
            for partition in partitions:
                drive_letter = partition[0].split(" ")[0]
                drive_letters.append(drive_letter)
        return drive_letters

    def extract_partition_index(self, drive_letter):
        for partition_index, partition_list in self.partition_info.items():
            for partition in partition_list:
                if partition.startswith(drive_letter):
                    return partition_index
        return None
