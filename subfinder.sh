#!/bin/bash
# =============================================
# BULK SUBDOMAIN FINDER - 2 THREADS VERSION
# =============================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fungsi untuk log
log() {
    local timestamp=$(date '+%H:%M:%S')
    local message="$1"
    local show="$2"

    # Selalu tulis ke file log
    echo "[$timestamp] $message" >> "$PROGRESS_FILE"

    # Tampilkan ke layar jika diperlukan
    if [ "$show" = "true" ]; then
        echo -e "$message"
    fi
}

# Input dari user
echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║      BULK SUBDOMAIN FINDER v3.0      ║"
echo "║      Ghostpels == heheheheheheh      ║"
echo "║          (2 THREADS MODE)            ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}[?] Masukkan list domain:${NC} "
read -r INPUT_FILE

echo -e "${BLUE}[?] Masukkan file result:${NC} "
read -r OUTPUT_FILE

# Konfigurasi
PROGRESS_FILE="${OUTPUT_FILE%.*}_progress.log"
FAILED_FILE="${OUTPUT_FILE%.*}_failed.txt"
TIMEOUT=45  # Sedikit lebih lama untuk stabilitas
THREADS=2   # Hanya 2 threads seperti permintaan
BATCH_SIZE=100  # Proses dalam batch

# Cek file input
if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[ERROR] File $INPUT_FILE tidak ditemukan!${NC}"
    exit 1
fi

# Hitung total domain
TOTAL_DOMAINS=$(wc -l < "$INPUT_FILE" | tr -d ' ')
echo -e "${GREEN}[✓] Ditemukan $TOTAL_DOMAINS domain${NC}"

# Bersihkan file output
> "$OUTPUT_FILE"
> "$FAILED_FILE"
> "$PROGRESS_FILE"

echo -e "${YELLOW}[!] Konfigurasi:${NC}"
echo -e "    • Threads: $THREADS"
echo -e "    • Timeout: ${TIMEOUT}s"
echo -e "    • Input: $INPUT_FILE"
echo -e "    • Output: $OUTPUT_FILE"
echo -e "    • Progress: $PROGRESS_FILE"
echo ""

# Fungsi untuk scan domain dengan retry
scan_domain() {
    local domain="$1"
    local domain_clean=$(echo "$domain" | tr -cd '[:alnum:]._-')
    local temp_file="/tmp/sub_${domain_clean}_$$.txt"
    local found=false
    local attempt=1

    # Coba maksimal 2 kali
    while [ $attempt -le 2 ]; do
        # Gunakan subfinder dengan timeout dan rate limiting
        timeout $TIMEOUT subfinder -d "$domain" -silent -timeout $TIMEOUT -t 2 2>/dev/null > "$temp_file"
        local exit_code=$?

        if [ $exit_code -eq 0 ] && [ -s "$temp_file" ]; then
            local count=$(wc -l < "$temp_file" 2>/dev/null || echo 0)

            if [ "$count" -gt 0 ]; then
                # Simpan hasil
                echo "#=== $domain ($count subdomains) ===" >> "$OUTPUT_FILE"
                cat "$temp_file" >> "$OUTPUT_FILE"
                echo "" >> "$OUTPUT_FILE"

                # Log progress
                echo "[$(date '+%H:%M:%S')] [SUCCESS] $domain: $count subdomains" >> "$PROGRESS_FILE"
                found=true
                break
            fi
        elif [ $exit_code -eq 124 ]; then
            echo "[$(date '+%H:%M:%S')] [TIMEOUT] $domain: Attempt $attempt" >> "$PROGRESS_FILE"
        else
            echo "[$(date '+%H:%M:%S')] [ERROR] $domain: Code $exit_code (Attempt $attempt)" >> "$PROGRESS_FILE"
        fi

        attempt=$((attempt + 1))
        sleep 1  # Jeda antara retry
    done

    # Jika gagal semua percobaan
    if [ "$found" = false ]; then
        echo "$domain" >> "$FAILED_FILE"
        echo "[$(date '+%H:%M:%S')] [FAILED] $domain: All attempts failed" >> "$PROGRESS_FILE"
    fi

    rm -f "$temp_file"
}

# Fungsi untuk menampilkan progress
show_progress() {
    local processed=$1
    local success=$2
    local failed=$3
    local percentage=$((processed * 100 / TOTAL_DOMAINS))

    echo -ne "\r${CYAN}[PROGRESS]${NC} "
    echo -ne "${GREEN}✓ $success${NC} | "
    echo -ne "${RED}✗ $failed${NC} | "
    echo -ne "${YELLOW}⏳ $processed/$TOTAL_DOMAINS${NC} "
    echo -ne "(${BLUE}${percentage}%${NC})"
}

# Main process
echo -e "${GREEN}[▶] Memulai proses scanning...${NC}"
echo ""

# Variable untuk tracking
PROCESSED=0
SUCCESS=0
FAILED=0
START_TIME=$(date +%s)

# Baca semua domain ke array
mapfile -t domains_array < "$INPUT_FILE"

# Proses dengan parallel limited to 2 jobs
for i in "${!domains_array[@]}"; do
    domain="${domains_array[$i]}"

    # Skip jika kosong
    [ -z "$domain" ] && continue

    # Scan domain (background process)
    scan_domain "$domain" &

    # Update counter
    PROCESSED=$((PROCESSED + 1))

    # Update stats dari progress file
    SUCCESS=$(grep -c "\[SUCCESS\]" "$PROGRESS_FILE" 2>/dev/null || echo 0)
    FAILED=$(grep -c "\[FAILED\]" "$PROGRESS_FILE" 2>/dev/null || echo 0)

    # Tampilkan progress setiap 10 domain atau setiap detik
    if (( i % 10 == 0 )) || (( i == ${#domains_array[@]} - 1 )); then
        show_progress $PROCESSED $SUCCESS $FAILED
    fi

    # Jika sudah mencapai limit threads, tunggu
    running_jobs=$(jobs -rp | wc -l)
    while [ $running_jobs -ge $THREADS ]; do
        sleep 0.5
        running_jobs=$(jobs -rp | wc -l)
    done
done

# Tunggu semua background jobs selesai
echo -e "\n${YELLOW}[!] Menunggu proses selesai...${NC}"
wait

END_TIME=$(date +%s)
ELAPSED_TIME=$((END_TIME - START_TIME))

# Hapus duplikat hasil akhir
echo -e "${YELLOW}[!] Membersihkan hasil...${NC}"
if [ -f "$OUTPUT_FILE" ]; then
    # Ekstrak hanya subdomain (bukan komentar)
    grep -v "^#" "$OUTPUT_FILE" | grep -v "^$" | sort -u > "${OUTPUT_FILE}.tmp"
    mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

    FINAL_COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
else
    FINAL_COUNT=0
fi

# Hitung failed domains
FAILED_COUNT=$(wc -l < "$FAILED_FILE" 2>/dev/null || echo 0)

# Tampilkan summary
echo -e "\n${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] SCAN SELESAI!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${CYAN}📊 STATISTIK:${NC}"
echo -e "  • Total domain   : ${YELLOW}$TOTAL_DOMAINS${NC}"
echo -e "  • Sukses         : ${GREEN}$SUCCESS${NC}"
echo -e "  • Gagal          : ${RED}$FAILED_COUNT${NC}"
echo -e "  • Subdomain unik : ${BLUE}$FINAL_COUNT${NC}"
echo -e "  • Waktu eksekusi : ${YELLOW}$ELAPSED_TIME detik${NC}"
echo ""
echo -e "${CYAN}📁 FILE HASIL:${NC}"
echo -e "  • Hasil subdomain : ${GREEN}$OUTPUT_FILE${NC}"
echo -e "  • Log progress    : ${YELLOW}$PROGRESS_FILE${NC}"
if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "  • Domain gagal    : ${RED}$FAILED_FILE${NC}"
fi
echo -e "${GREEN}════════════════════════════════════════${NC}"

# Tampilkan 5 domain pertama yang berhasil
if [ $FINAL_COUNT -gt 0 ]; then
    echo -e "\n${CYAN}🔍 Contoh subdomain yang ditemukan:${NC}"
    grep -v "^#" "$OUTPUT_FILE" | head -5 | while read -r subdomain; do
        echo -e "  • ${GREEN}$subdomain${NC}"
    done
fi
