# Tools
This is some tools :)

=================================================================================
**Pecah.py**

Tools untuk memecah 1 file menjadi beberapa file dan dijadikan ZIP, lalu akan memberikan script PHP untuk pemanggilan.

how to use :

	 python3 pecah.py --input (File Awal) --zip (Nama File Zip) --loader (Nama File Pemanggil) --lines (Jumlah Baris dalam 1 File)

Example :

	 python pecah.py --input rs.php --zip rs2.zip --loader rs2.php --lines 5

==================================================================================


**Shell_scanner/scan.php**

Script ini untuk melihat file php, phtml, php5 etc dalam rentan waktu tertentu. lengkap dengan path

note : Kekurangannya untuk deteksi low, medium, risk masih belom karena webshell masih dianggap low risk
