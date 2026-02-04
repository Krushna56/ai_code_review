"""
Quick diagnostic script to check folder size
"""
import os
import sys

def get_folder_size(folder_path):
    total_size = 0
    file_count = 0
    
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                total_size += os.path.getsize(filepath)
                file_count += 1
            except:
                pass
    
    return total_size, file_count

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_folder_size.py <folder_path>")
        sys.exit(1)
    
    folder = sys.argv[1]
    if not os.path.exists(folder):
        print(f"Error: Folder '{folder}' does not exist")
        sys.exit(1)
    
    size_bytes, count = get_folder_size(folder)
    size_mb = size_bytes / (1024 * 1024)
    size_gb = size_bytes / (1024 * 1024 * 1024)
    
    print(f"\nFolder: {folder}")
    print(f"Total files: {count:,}")
    print(f"Total size: {size_bytes:,} bytes")
    print(f"           {size_mb:.2f} MB")
    print(f"           {size_gb:.2f} GB")
    print(f"\nCurrent limit: 21,474,836,480 bytes (20 GB)")
    
    if size_bytes > 21474836480:
        print(f"⚠️  WARNING: Folder exceeds 20GB limit!")
        print(f"   Excess: {(size_bytes - 21474836480) / (1024*1024):.2f} MB")
    else:
        print(f"✅ Folder is within 20GB limit")
