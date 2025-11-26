import os
import math
import zipfile
import argparse

def proses_script(nama_file_input, nama_file_zip, nama_file_loader, jumlah_baris):
    print(f"Membaca script sumber: {nama_file_input}...")

    if not os.path.exists(nama_file_input):
        print(f"Error: File '{nama_file_input}' tidak ditemukan!")
        return

    # Baca semua baris dari file sumber
    with open(nama_file_input, 'r', encoding="utf-8") as f:
        lines = f.readlines()

    total_baris = len(lines)
    jumlah_file = math.ceil(total_baris / jumlah_baris)
    print(f"Total {total_baris} baris akan dipecah menjadi {jumlah_file} file dalam ZIP.")

    # Pastikan nama file zip ada ekstensi .zip
    if not nama_file_zip.lower().endswith(".zip"):
        nama_file_zip += ".zip"

    # Buat ZIP
    with zipfile.ZipFile(nama_file_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for i in range(jumlah_file):
            start_index = i * jumlah_baris
            end_index = start_index + jumlah_baris
            chunk_lines = lines[start_index:end_index]

            nama_file_pecahan = f"bagian_{i+1}.php"
            isi_file = "".join(chunk_lines)

            zipf.writestr(nama_file_pecahan, isi_file)
            print(f" -> '{nama_file_pecahan}' ditambahkan ke {nama_file_zip}")

    # Buat loader.php
    with open(nama_file_loader, 'w', encoding="utf-8") as loader_f:
        loader_f.write("<?php\n")
        loader_f.write("// Loader otomatis untuk menggabungkan & mengeksekusi file-file dari ZIP\n")
        loader_f.write("$zip = new ZipArchive;\n")
        loader_f.write(f"if ($zip->open('{nama_file_zip}') === TRUE) {{\n")
        loader_f.write(f"    $script = '';\n")
        loader_f.write(f"    for ($i = 0; $i < $zip->numFiles; $i++) {{\n")
        loader_f.write(f"        $script .= $zip->getFromIndex($i);\n")
        loader_f.write(f"    }}\n")
        loader_f.write(f"    eval('?>'.$script);\n")
        loader_f.write(f"    $zip->close();\n")
        loader_f.write("} else {\n")
        loader_f.write("    echo 'Gagal membuka arsip ZIP';\n")
        loader_f.write("}\n")
        loader_f.write("?>")

    print(f"\nFile ZIP '{nama_file_zip}' dan loader '{nama_file_loader}' berhasil dibuat.")
    print("Proses selesai!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pecah file PHP jadi bagian, simpan ke ZIP, dan buat loader penggabung.")
    parser.add_argument("--input", required=True, help="File input (contoh: abc.php)")
    parser.add_argument("--zip", required=True, help="Nama file ZIP output (contoh: parts.zip)")
    parser.add_argument("--loader", required=True, help="Nama file loader (contoh: loader.php)")
    parser.add_argument("--lines", type=int, default=10, help="Jumlah baris per file pecahan (default: 10)")

    args = parser.parse_args()
    proses_script(args.input, args.zip, args.loader, args.lines)
