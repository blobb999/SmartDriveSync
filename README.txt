Directory Synchronization Tool

The Directory Synchronization Tool is a Python application for synchronizing the contents of two directories. The tool allows the user to select a source directory and a destination directory and synchronize them by copying files and directories that are missing in either directory, updating files that have changed, and optionally removing files and directories from the destination directory that are not present in the source directory.
Features

1.    Synchronizes the contents of two directories
2.    Copies missing files and directories from source to destination
3.    Updates files that have changed (optionally by comparing modification dates or using xxHash)
4.    Removes excess files and directories from the destination directory (optional)
5.    Renames and moves files in the destination directory to match the filenames and directory 
      structure in the source directory
6.    Shows progress using a progress bar and updates a status log with details of each operation
7.    Allows the user to stop the synchronization process at any time
8.    Monitoring disk speeds and activity

Compared to SimpleDriveSync, this version does not simply copy "missing" files to the target location. Instead, if the missing files still exist elsewhere, they are renamed and moved to the target location, regardless of their name or path.

