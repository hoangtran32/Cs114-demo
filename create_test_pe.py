import pefile
import os
import random
import shutil

def create_mock_malware(source_exe="C:\\Windows\\System32\\calc.exe", output_exe="mock_malware_test.exe"):
    print(f"[*] Đang sao chép {source_exe} thành {output_exe}...")
    try:
        shutil.copy2(source_exe, output_exe)
    except Exception as e:
        print(f"[!] Lỗi copy file: {e}")
        return

    print("[*] Đang dùng pefile để sửa đổi các đặc trưng PE nhằm đánh lừa Model...")
    try:
        pe = pefile.PE(source_exe)
        
        # 1. Xóa chữ ký số (Security Directory) để giống Malware
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
        
        # 2. Đổi TimeDateStamp (F638) thành một thời gian bất thường trong quá khứ hoặc tương lai
        pe.FILE_HEADER.TimeDateStamp = 0x50000000 
        
        # Lưu thay đổi ra file mới trước để tránh lỗi file lock trên Windows
        pe.write(filename=output_exe)
        
        # 3. Ghi một đoạn byte ngẫu nhiên (Entropy cực cao) vào cuối file (Overlay)
        print("[*] Đang chèn 5MB dữ liệu nhiễu (High Entropy) vào tệp...")
        with open(output_exe, 'ab') as f:
            f.write(os.urandom(5 * 1024 * 1024))
            
        print(f"[+] THÀNH CÔNG! Đã tạo ra file {output_exe}.")
        print(f"[+] File này có cấu trúc PE hợp lệ 100%, không chứa mã độc thật, nhưng có đặc trưng giống Malware.")
        print(f"[+] Bạn có thể upload file {output_exe} lên Web để test!")
        
    except Exception as e:
        print(f"[!] Lỗi khi xử lý PE: {e}")

if __name__ == "__main__":
    create_mock_malware()
