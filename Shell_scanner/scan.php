<?php
/**
 * PHP File Monitor untuk Deteksi WebShell
 * Dengan Bulk Delete, State Preservation, dan Open Basedir Handling
 */

class PHPFileMonitor {
    private $logFile = 'php_monitor.log';
    private $quarantineDir = 'quarantine/';
    private $targetDirectory;
    private $startDate;
    private $endDate;
    
    // Daftar ekstensi PHP yang umum digunakan webshell
    private $phpExtensions = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
        'phar', 'phps', 'pht', 'inc', 'php.txt', 'php.gif', 'php.jpg',
        'php.png', 'php.bak', 'php.swp', 'php.save', 'php.old', 'php.backup'
    ];
    
    public function __construct($directory, $startDate, $endDate = null) {
        $this->targetDirectory = rtrim($directory, '/') . '/';
        $this->startDate = new DateTime($startDate);
        $this->endDate = $endDate ? new DateTime($endDate) : new DateTime();
        
        // Buat quarantine directory jika belum ada
        if (!is_dir($this->quarantineDir)) {
            mkdir($this->quarantineDir, 0755, true);
        }
    }
    
    /**
     * Cek apakah directory dapat diakses (handle open_basedir)
     */
    private function isDirectoryAccessible($directory) {
        // Cek open_basedir restrictions
        $open_basedir = ini_get('open_basedir');
        if (!empty($open_basedir)) {
            $allowed_paths = explode(PATH_SEPARATOR, $open_basedir);
            $is_allowed = false;
            
            foreach ($allowed_paths as $allowed_path) {
                // Normalize paths
                $allowed_path = rtrim($allowed_path, '/') . '/';
                $check_path = rtrim($directory, '/') . '/';
                
                if (strpos($check_path, $allowed_path) === 0) {
                    $is_allowed = true;
                    break;
                }
            }
            
            if (!$is_allowed) {
                throw new Exception("Directory '$directory' tidak diizinkan oleh open_basedir restriction.<br>" .
                                  "Allowed paths: " . $open_basedir);
            }
        }
        
        if (!is_dir($directory)) {
            throw new Exception("Directory tidak ditemukan: " . $directory);
        }
        
        if (!is_readable($directory)) {
            throw new Exception("Directory tidak dapat dibaca: " . $directory);
        }
        
        return true;
    }
    
    /**
     * Scan file PHP dalam rentang waktu
     */
    public function scanPHPFilesInRange() {
        // Cek apakah directory dapat diakses
        $this->isDirectoryAccessible($this->targetDirectory);
        
        $suspiciousFiles = [];
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->targetDirectory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $scannedCount = 0;
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $extension = strtolower($file->getExtension());
                
                // Cek apakah ekstensi termasuk dalam daftar PHP
                if (in_array($extension, $this->phpExtensions) || 
                    $this->isPHPFileByName($file->getFilename())) {
                    
                    $scannedCount++;
                    
                    $fileCreationTime = new DateTime();
                    $fileCreationTime->setTimestamp($file->getCTime());
                    
                    // Cek apakah file dibuat dalam rentang waktu
                    if ($fileCreationTime >= $this->startDate && 
                        $fileCreationTime <= $this->endDate) {
                        
                        $fileModificationTime = new DateTime();
                        $fileModificationTime->setTimestamp($file->getMTime());
                        
                        $filePath = $file->getPathname();
                        
                        $suspiciousFiles[] = [
                            'path' => $filePath,
                            'relative_path' => str_replace($this->targetDirectory, '', $filePath),
                            'filename' => $file->getFilename(),
                            'extension' => $extension,
                            'created' => $fileCreationTime->format('Y-m-d H:i:s'),
                            'modified' => $fileModificationTime->format('Y-m-d H:i:s'),
                            'size' => $this->formatBytes($file->getSize()),
                            'permissions' => substr(sprintf('%o', $file->getPerms()), -4),
                            'owner' => function_exists('posix_getpwuid') ? 
                                       @posix_getpwuid($file->getOwner())['name'] : 'N/A',
                            'is_writable' => $file->isWritable(),
                            'risk_level' => $this->assessRiskLevel($file->getFilename(), $extension),
                            'file_exists' => file_exists($filePath),
                            'encoded_path' => base64_encode($filePath)
                        ];
                    }
                }
            }
        }
        
        // Urutkan berdasarkan tanggal pembuatan (terbaru dulu)
        usort($suspiciousFiles, function($a, $b) {
            return strtotime($b['created']) - strtotime($a['created']);
        });
        
        return [
            'files' => $suspiciousFiles,
            'scanned_count' => $scannedCount
        ];
    }
    
    /**
     * Deteksi file PHP berdasarkan nama (untuk file dengan ekstensi ganda)
     */
    private function isPHPFileByName($filename) {
        $filename = strtolower($filename);
        
        // Pattern untuk file dengan ekstensi ganda seperti .php.gif, .php.jpg
        $patterns = [
            '/\.php\.([a-z0-9]+)$/i',
            '/\.phtml\.([a-z0-9]+)$/i',
            '/\.phps\.([a-z0-9]+)$/i',
            '/^.*\.php$/i',
            '/^.*\.phtml$/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $filename)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Tentukan level risiko berdasarkan nama file dan ekstensi
     */
    private function assessRiskLevel($filename, $extension) {
        $filename = strtolower($filename);
        $riskScore = 0;
        
        // Ekstensi berbahaya
        if (in_array($extension, ['phtml', 'phps', 'php.gif', 'php.jpg', 'php.png'])) {
            $riskScore += 3;
        }
        
        // Nama file mencurigakan
        $suspiciousNames = [
            'shell', 'backdoor', 'cmd', 'c99', 'r57', 'wso', 'b374k',
            'adminer', 'phpmyadmin', 'config', 'setup', 'install',
            'upload', 'filemanager', 'mini', 'tiny', 'cgi', 'temp',
            'test', 'debug', 'eval', 'exec', 'system', 'passthru'
        ];
        
        foreach ($suspiciousNames as $name) {
            if (strpos($filename, $name) !== false) {
                $riskScore += 2;
            }
        }
        
        if ($riskScore >= 5) {
            return 'HIGH';
        } elseif ($riskScore >= 3) {
            return 'MEDIUM';
        } else {
            return 'LOW';
        }
    }
    
    /**
     * Download file untuk inspeksi
     */
    public function downloadFile($filePath) {
        // Cek open_basedir untuk file ini
        $this->checkFileAccessible($filePath);
        
        if (!file_exists($filePath)) {
            throw new Exception("File tidak ditemukan: " . $filePath);
        }
        
        $filename = basename($filePath);
        $content = file_get_contents($filePath);
        
        return [
            'filename' => $filename,
            'path' => $filePath,
            'size' => filesize($filePath),
            'md5' => md5($content),
            'content' => $content
        ];
    }
    
    /**
     * Cek apakah file dapat diakses
     */
    private function checkFileAccessible($filePath) {
        $open_basedir = ini_get('open_basedir');
        if (!empty($open_basedir)) {
            $allowed_paths = explode(PATH_SEPARATOR, $open_basedir);
            $is_allowed = false;
            
            foreach ($allowed_paths as $allowed_path) {
                if (strpos($filePath, $allowed_path) === 0) {
                    $is_allowed = true;
                    break;
                }
            }
            
            if (!$is_allowed) {
                throw new Exception("File '$filePath' tidak diizinkan oleh open_basedir restriction.");
            }
        }
        
        return true;
    }
    
    /**
     * Hapus file (pindahkan ke quarantine)
     */
    public function deleteFile($filePath) {
        // Cek apakah file dapat diakses
        $this->checkFileAccessible($filePath);
        
        if (!file_exists($filePath)) {
            return [
                'success' => false,
                'message' => 'File tidak ditemukan: ' . $filePath,
                'path' => $filePath
            ];
        }
        
        $filename = basename($filePath);
        $timestamp = date('Y-m-d_His');
        $quarantinePath = $this->quarantineDir . $timestamp . '_' . $filename;
        
        // Backup metadata
        $metadata = [
            'original_path' => $filePath,
            'original_size' => filesize($filePath),
            'original_md5' => md5_file($filePath),
            'quarantine_date' => date('Y-m-d H:i:s'),
            'quarantine_path' => $quarantinePath,
            'backup_timestamp' => $timestamp
        ];
        
        // Pindahkan file
        if (rename($filePath, $quarantinePath)) {
            // Simpan metadata
            file_put_contents($quarantinePath . '.meta.json', json_encode($metadata, JSON_PRETTY_PRINT));
            
            return [
                'success' => true,
                'message' => 'File berhasil dihapus (dipindahkan ke karantina)',
                'original_path' => $filePath,
                'quarantine_path' => $quarantinePath,
                'metadata_file' => $quarantinePath . '.meta.json',
                'filename' => $filename
            ];
        } else {
            return [
                'success' => false,
                'message' => 'Gagal memindahkan file ke karantina',
                'path' => $filePath
            ];
        }
    }
    
    /**
     * Bulk delete multiple files
     */
    public function bulkDeleteFiles($filePaths) {
        $results = [];
        $successCount = 0;
        $errorCount = 0;
        
        foreach ($filePaths as $encodedPath) {
            $filePath = base64_decode($encodedPath);
            
            try {
                // Cek apakah file dapat diakses
                $this->checkFileAccessible($filePath);
                
                $result = $this->deleteFile($filePath);
                $results[] = $result;
                
                if ($result['success']) {
                    $successCount++;
                } else {
                    $errorCount++;
                }
            } catch (Exception $e) {
                $results[] = [
                    'success' => false,
                    'message' => 'Error: ' . $e->getMessage(),
                    'path' => $filePath
                ];
                $errorCount++;
            }
        }
        
        return [
            'results' => $results,
            'success_count' => $successCount,
            'error_count' => $errorCount,
            'total' => count($filePaths)
        ];
    }
    
    /**
     * Preview konten file
     */
    public function previewFile($filePath, $maxLines = 100) {
        // Cek apakah file dapat diakses
        $this->checkFileAccessible($filePath);
        
        if (!file_exists($filePath)) {
            throw new Exception("File tidak ditemukan: " . $filePath);
        }
        
        $content = file_get_contents($filePath);
        $lines = explode("\n", $content);
        $totalLines = count($lines);
        
        // Ambil beberapa baris pertama dan terakhir
        $previewLines = array_slice($lines, 0, $maxLines);
        
        if ($totalLines > $maxLines) {
            $previewLines[] = "\n... [" . ($totalLines - $maxLines) . " lines truncated] ...\n";
        }
        
        return [
            'path' => $filePath,
            'total_lines' => $totalLines,
            'total_size' => strlen($content),
            'md5' => md5($content),
            'preview' => implode("\n", $previewLines),
            'is_binary' => $this->isBinary($content)
        ];
    }
    
    /**
     * Cek apakah file binary
     */
    private function isBinary($content) {
        if (preg_match('~[^\x20-\x7E\t\r\n]~', $content) > 0) {
            return true;
        }
        return false;
    }
    
    /**
     * Generate URL untuk akses file
     */
    public function generateFileUrl($filePath) {
        $baseUrl = isset($_SERVER['HTTP_HOST']) ? 
                  'http://' . $_SERVER['HTTP_HOST'] : '';
        
        // Remove document root untuk mendapatkan path relatif
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
        if ($docRoot && strpos($filePath, $docRoot) === 0) {
            $relativePath = str_replace($docRoot, '', $filePath);
            return $baseUrl . $relativePath;
        }
        
        return null;
    }
    
    /**
     * Simpan hasil scan ke log
     */
    public function saveScanResults($files) {
        $logContent = "=== Scan WebShell - " . date('Y-m-d H:i:s') . " ===\n";
        $logContent .= "Directory: " . $this->targetDirectory . "\n";
        $logContent .= "Rentang Waktu: " . $this->startDate->format('Y-m-d') . 
                      " hingga " . $this->endDate->format('Y-m-d') . "\n";
        $logContent .= "Total File Ditemukan: " . count($files) . "\n\n";
        
        foreach ($files as $index => $file) {
            $logContent .= ($index + 1) . ". [" . $file['risk_level'] . "] " . $file['path'] . "\n";
            $logContent .= "   Ekstensi: " . $file['extension'] . "\n";
            $logContent .= "   Dibuat: " . $file['created'] . "\n";
            $logContent .= "   Dimodifikasi: " . $file['modified'] . "\n";
            $logContent .= "   Ukuran: " . $file['size'] . "\n";
            $logContent .= "   Permissions: " . $file['permissions'] . "\n";
            $logContent .= "   URL: " . ($this->generateFileUrl($file['path']) ?: 'N/A') . "\n\n";
        }
        
        if (empty($files)) {
            $logContent .= "Tidak ada file PHP yang ditemukan dalam rentang waktu tersebut.\n";
        }
        
        $logContent .= "=========================================\n\n";
        
        file_put_contents($this->logFile, $logContent, FILE_APPEND);
        
        return $this->logFile;
    }
    
    /**
     * Format bytes
     */
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
    
    /**
     * Tampilkan form scan awal
     */
    public static function displayInitialForm($defaultDir = '', $defaultStartDate = '', $defaultEndDate = '') {
        if (empty($defaultStartDate)) {
            $defaultStartDate = '2023-05-11';
        }
        if (empty($defaultEndDate)) {
            $defaultEndDate = date('Y-m-d');
        }
        
        // Dapatkan allowed paths dari open_basedir
        $open_basedir = ini_get('open_basedir');
        $allowed_paths = $open_basedir ? explode(PATH_SEPARATOR, $open_basedir) : [];
        
        ?>
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WebShell Detector - Setup Scan</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    min-height: 100vh; 
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                
                .container { 
                    max-width: 800px; 
                    width: 100%;
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 15px 40px rgba(0,0,0,0.2);
                    overflow: hidden;
                }
                
                .header { 
                    background: linear-gradient(to right, #4A00E0, #8E2DE2);
                    color: white;
                    padding: 40px 30px;
                    text-align: center;
                }
                
                .header h1 { 
                    font-size: 2.5rem; 
                    margin-bottom: 10px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 15px;
                }
                
                .header .subtitle { 
                    font-size: 1.1rem;
                    opacity: 0.9;
                }
                
                .content { 
                    padding: 40px;
                }
                
                .form-group { 
                    margin-bottom: 25px; 
                }
                
                .form-group label { 
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 600;
                    color: #333;
                    font-size: 1rem;
                }
                
                .form-group input, 
                .form-group select { 
                    width: 100%;
                    padding: 14px;
                    border: 2px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 1rem;
                    transition: border-color 0.3s;
                }
                
                .form-group input:focus, 
                .form-group select:focus { 
                    outline: none;
                    border-color: #8E2DE2;
                }
                
                .form-row { 
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }
                
                .btn { 
                    width: 100%;
                    padding: 16px;
                    background: linear-gradient(to right, #4A00E0, #8E2DE2);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1.1rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.3s, box-shadow 0.3s;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 10px;
                }
                
                .btn:hover { 
                    transform: translateY(-3px);
                    box-shadow: 0 10px 20px rgba(142, 45, 226, 0.3);
                }
                
                .btn:active { 
                    transform: translateY(-1px);
                }
                
                .server-info { 
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-top: 30px;
                    border-left: 4px solid #4A00E0;
                }
                
                .server-info h3 { 
                    color: #333;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                
                .server-info ul { 
                    list-style: none;
                }
                
                .server-info li { 
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                    display: flex;
                    justify-content: space-between;
                }
                
                .server-info li:last-child { 
                    border-bottom: none;
                }
                
                .info-label { 
                    font-weight: 600;
                    color: #555;
                }
                
                .info-value { 
                    color: #333;
                    font-family: monospace;
                }
                
                .allowed-paths { 
                    max-height: 150px;
                    overflow-y: auto;
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 10px;
                    margin-top: 10px;
                }
                
                .path-item { 
                    padding: 5px;
                    border-bottom: 1px solid #eee;
                    font-family: monospace;
                    font-size: 0.9rem;
                }
                
                .path-item:last-child { 
                    border-bottom: none;
                }
                
                .error-box { 
                    background: #ffebee;
                    border: 1px solid #ffcdd2;
                    color: #c62828;
                    padding: 15px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }
                
                @media (max-width: 768px) {
                    .form-row { 
                        grid-template-columns: 1fr;
                    }
                    
                    .content { 
                        padding: 25px;
                    }
                    
                    .header h1 { 
                        font-size: 2rem;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1><i class="fas fa-shield-alt"></i> WebShell Detector</h1>
                    <p class="subtitle">Deteksi file PHP mencurigakan dalam rentang waktu tertentu</p>
                </div>
                
                <div class="content">
                    <?php if (isset($_GET['error'])): ?>
                        <div class="error-box">
                            <strong><i class="fas fa-exclamation-triangle"></i> Error:</strong>
                            <?php echo htmlspecialchars(urldecode($_GET['error'])); ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="GET" action="">
                        <input type="hidden" name="scan" value="1">
                        
                        <div class="form-group">
                            <label for="directory">
                                <i class="fas fa-folder-open"></i> Directory Path
                            </label>
                            <input type="text" 
                                   id="directory" 
                                   name="dir" 
                                   value="<?php echo htmlspecialchars($defaultDir); ?>" 
                                   placeholder="Contoh: /var/www/html atau /home/user/public_html"
                                   required>
                            <small style="color: #666; margin-top: 5px; display: block;">
                                Masukkan path lengkap directory yang ingin di-scan
                            </small>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="start_date">
                                    <i class="fas fa-calendar-alt"></i> Start Date
                                </label>
                                <input type="date" 
                                       id="start_date" 
                                       name="start_date" 
                                       value="<?php echo htmlspecialchars($defaultStartDate); ?>"
                                       required>
                            </div>
                            
                            <div class="form-group">
                                <label for="end_date">
                                    <i class="fas fa-calendar-check"></i> End Date
                                </label>
                                <input type="date" 
                                       id="end_date" 
                                       name="end_date" 
                                       value="<?php echo htmlspecialchars($defaultEndDate); ?>"
                                       required>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" class="btn">
                                <i class="fas fa-search"></i> Mulai Scanning
                            </button>
                        </div>
                    </form>
                    
                    <div class="server-info">
                        <h3><i class="fas fa-server"></i> Informasi Server</h3>
                        <ul>
                            <li>
                                <span class="info-label">Document Root:</span>
                                <span class="info-value"><?php echo $_SERVER['DOCUMENT_ROOT'] ?? 'N/A'; ?></span>
                            </li>
                            <li>
                                <span class="info-label">Script Path:</span>
                                <span class="info-value"><?php echo __FILE__; ?></span>
                            </li>
                            <li>
                                <span class="info-label">Open Basedir:</span>
                                <span class="info-value"><?php echo $open_basedir ?: 'No restriction'; ?></span>
                            </li>
                            <?php if (!empty($allowed_paths)): ?>
                            <li>
                                <span class="info-label">Allowed Paths:</span>
                                <div class="allowed-paths">
                                    <?php foreach ($allowed_paths as $path): ?>
                                        <div class="path-item"><?php echo htmlspecialchars($path); ?></div>
                                    <?php endforeach; ?>
                                </div>
                            </li>
                            <?php endif; ?>
                        </ul>
                    </div>
                    
                    <div style="margin-top: 25px; text-align: center; color: #666; font-size: 0.9rem;">
                        <p><i class="fas fa-lightbulb"></i> Tips: Gunakan directory yang diizinkan oleh open_basedir restriction</p>
                    </div>
                </div>
            </div>
            
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    // Set default values jika kosong
                    const directoryInput = document.getElementById('directory');
                    if (!directoryInput.value && document.referrer === '') {
                        // Coba dapatkan document root sebagai default
                        directoryInput.value = '<?php echo $_SERVER["DOCUMENT_ROOT"] ?? ""; ?>';
                    }
                    
                    // Validasi tanggal
                    const endDateInput = document.getElementById('end_date');
                    const startDateInput = document.getElementById('start_date');
                    
                    endDateInput.max = new Date().toISOString().split('T')[0];
                    
                    endDateInput.addEventListener('change', function() {
                        startDateInput.max = this.value;
                    });
                    
                    startDateInput.addEventListener('change', function() {
                        endDateInput.min = this.value;
                    });
                });
            </script>
        </body>
        </html>
        <?php
    }
    
    /**
     * Tampilkan dashboard web dengan AJAX untuk tetap di state yang sama
     */
    public function displayDashboard($scanResult) {
        $files = $scanResult['files'];
        $totalFiles = count($files);
        $highRisk = count(array_filter($files, fn($f) => $f['risk_level'] === 'HIGH'));
        $mediumRisk = count(array_filter($files, fn($f) => $f['risk_level'] === 'MEDIUM'));
        $scannedCount = $scanResult['scanned_count'];
        
        // Simpan state di session untuk AJAX operations
        $_SESSION['scan_state'] = [
            'directory' => $this->targetDirectory,
            'start_date' => $this->startDate->format('Y-m-d'),
            'end_date' => $this->endDate->format('Y-m-d'),
            'files' => $files
        ];
        
        ?>
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WebShell Detector - Results</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       min-height: 100vh; padding: 20px; }
                
                .container { max-width: 1400px; margin: 0 auto; }
                
                .header { background: white; padding: 25px; border-radius: 10px; 
                         box-shadow: 0 10px 30px rgba(0,0,0,0.1); margin-bottom: 25px; }
                .header h1 { color: #333; margin-bottom: 10px; }
                .header .subtitle { color: #666; }
                
                .stats-container { display: flex; gap: 20px; margin-bottom: 25px; }
                .stat-card { flex: 1; background: white; padding: 25px; border-radius: 10px; 
                            box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; }
                .stat-card.total { border-top: 5px solid #3498db; }
                .stat-card.high { border-top: 5px solid #e74c3c; }
                .stat-card.medium { border-top: 5px solid #f39c12; }
                .stat-card.low { border-top: 5px solid #2ecc71; }
                .stat-card.scanned { border-top: 5px solid #9b59b6; }
                .stat-number { font-size: 36px; font-weight: bold; }
                .stat-label { color: #666; margin-top: 10px; }
                
                .control-panel { background: white; padding: 20px; border-radius: 10px; 
                                margin-bottom: 25px; display: flex; gap: 15px; 
                                align-items: center; flex-wrap: wrap; }
                .control-panel input, .control-panel select { padding: 10px; border: 1px solid #ddd; 
                                                             border-radius: 5px; }
                .btn { padding: 10px 20px; border: none; border-radius: 5px; 
                      cursor: pointer; font-weight: bold; transition: 0.3s; display: inline-flex;
                      align-items: center; gap: 8px; }
                .btn-primary { background: #3498db; color: white; }
                .btn-danger { background: #e74c3c; color: white; }
                .btn-warning { background: #f39c12; color: white; }
                .btn-success { background: #2ecc71; color: white; }
                .btn-info { background: #17a2b8; color: white; }
                .btn-secondary { background: #6c757d; color: white; }
                .btn:hover { opacity: 0.9; transform: translateY(-2px); }
                .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
                
                .bulk-actions { background: #fff3cd; border: 1px solid #ffeaa7; 
                                padding: 15px; border-radius: 8px; margin-bottom: 20px;
                                display: none; }
                .bulk-actions.active { display: block; }
                .selected-count { font-weight: bold; color: #e74c3c; }
                
                .files-container { background: white; border-radius: 10px; 
                                  box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
                                  overflow: hidden; }
                
                .file-table { width: 100%; border-collapse: collapse; }
                .file-table th { background: #f8f9fa; padding: 15px; text-align: left; 
                                border-bottom: 2px solid #dee2e6; font-weight: 600; }
                .file-table td { padding: 12px 15px; border-bottom: 1px solid #dee2e6; }
                .file-table tr:hover { background: #f8f9fa; }
                
                .risk-badge { padding: 3px 8px; border-radius: 4px; font-size: 12px; 
                             font-weight: bold; }
                .risk-high { background: #ffebee; color: #c62828; }
                .risk-medium { background: #fff3e0; color: #ef6c00; }
                .risk-low { background: #e8f5e9; color: #2e7d32; }
                
                .action-buttons { display: flex; gap: 5px; }
                .action-btn { padding: 5px 10px; border: none; border-radius: 3px; 
                             cursor: pointer; font-size: 12px; display: inline-flex;
                             align-items: center; gap: 5px; }
                
                .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; 
                        width: 100%; height: 100%; background: rgba(0,0,0,0.5); }
                .modal-content { background: white; margin: 50px auto; padding: 30px; 
                                border-radius: 10px; width: 80%; max-width: 900px; 
                                max-height: 80vh; overflow-y: auto; }
                .modal-header { display: flex; justify-content: space-between; 
                               align-items: center; margin-bottom: 20px; }
                .close { font-size: 30px; cursor: pointer; color: #666; }
                
                .file-preview { background: #f8f9fa; padding: 20px; border-radius: 5px; 
                               font-family: monospace; white-space: pre-wrap; 
                               max-height: 400px; overflow-y: auto; }
                
                .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
                .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
                
                .pagination { padding: 20px; text-align: center; }
                .page-link { padding: 8px 12px; margin: 0 5px; background: #f8f9fa; 
                            border: 1px solid #dee2e6; border-radius: 3px; cursor: pointer; }
                .page-link.active { background: #3498db; color: white; }
                
                .checkbox-cell { width: 40px; text-align: center; }
                .checkbox-cell input { width: 18px; height: 18px; cursor: pointer; }
                
                .empty-state { padding: 50px; text-align: center; color: #666; }
                
                .loading { display: none; position: fixed; top: 0; left: 0; width: 100%; 
                          height: 100%; background: rgba(255,255,255,0.8); z-index: 9999; 
                          justify-content: center; align-items: center; }
                .loading.active { display: flex; }
                .spinner { border: 5px solid #f3f3f3; border-top: 5px solid #3498db; 
                          border-radius: 50%; width: 50px; height: 50px; 
                          animation: spin 1s linear infinite; }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .back-link { margin-bottom: 20px; }
                .back-link a { color: white; text-decoration: none; display: inline-flex;
                              align-items: center; gap: 8px; background: rgba(255,255,255,0.2);
                              padding: 10px 15px; border-radius: 5px; }
                .back-link a:hover { background: rgba(255,255,255,0.3); }
                
                @media (max-width: 768px) {
                    .stats-container { flex-direction: column; }
                    .control-panel { flex-direction: column; align-items: stretch; }
                }
            </style>
        </head>
        <body>
            <div class="loading" id="loading">
                <div class="spinner"></div>
            </div>
            
            <div class="container">
                <div class="back-link">
                    <a href="?">
                        <i class="fas fa-arrow-left"></i> Kembali ke Setup Scan
                    </a>
                </div>
                
                <div class="header">
                    <h1><i class="fas fa-shield-alt"></i> WebShell Detector - Hasil Scan</h1>
                    <div style="display: flex; gap: 20px; margin-top: 10px; flex-wrap: wrap;">
                        <div>
                            <strong><i class="fas fa-folder"></i> Directory:</strong> 
                            <?php echo htmlspecialchars($this->targetDirectory); ?>
                        </div>
                        <div>
                            <strong><i class="fas fa-calendar"></i> Rentang Waktu:</strong> 
                            <?php echo $this->startDate->format('Y-m-d'); ?> hingga <?php echo $this->endDate->format('Y-m-d'); ?>
                        </div>
                        <div>
                            <strong><i class="fas fa-clock"></i> Scan Time:</strong> 
                            <?php echo date('Y-m-d H:i:s'); ?>
                        </div>
                    </div>
                </div>
                
                <div class="stats-container">
                    <div class="stat-card scanned">
                        <div class="stat-number"><?php echo $scannedCount; ?></div>
                        <div class="stat-label">File Di-scan</div>
                    </div>
                    <div class="stat-card total">
                        <div class="stat-number"><?php echo $totalFiles; ?></div>
                        <div class="stat-label">Dalam Rentang</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number"><?php echo $highRisk; ?></div>
                        <div class="stat-label">High Risk</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number"><?php echo $mediumRisk; ?></div>
                        <div class="stat-label">Medium Risk</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-number"><?php echo $totalFiles - $highRisk - $mediumRisk; ?></div>
                        <div class="stat-label">Low Risk</div>
                    </div>
                </div>
                
                <!-- Alert Messages -->
                <div id="alertContainer"></div>
                
                <!-- Bulk Actions Panel -->
                <div class="bulk-actions" id="bulkActionsPanel">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong><span id="selectedCount">0</span> file terpilih</strong>
                            <button class="btn btn-info" onclick="selectAllFiles()" style="margin-left: 15px;">
                                <i class="fas fa-check-square"></i> Pilih Semua
                            </button>
                            <button class="btn btn-secondary" onclick="deselectAllFiles()" style="margin-left: 10px;">
                                <i class="far fa-square"></i> Batal Pilih
                            </button>
                        </div>
                        <div>
                            <button class="btn btn-danger" onclick="bulkDeleteSelected()">
                                <i class="fas fa-trash"></i> Hapus File Terpilih
                            </button>
                            <button class="btn btn-secondary" onclick="cancelBulkActions()" style="margin-left: 10px;">
                                <i class="fas fa-times"></i> Batal
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Control Panel -->
                <div class="control-panel">
                    <input type="text" id="searchInput" placeholder="Cari file..." style="flex: 1;">
                    <select id="riskFilter">
                        <option value="">Semua Risk</option>
                        <option value="HIGH">High Risk</option>
                        <option value="MEDIUM">Medium Risk</option>
                        <option value="LOW">Low Risk</option>
                    </select>
                    <button class="btn btn-primary" onclick="scanAgain()">
                        <i class="fas fa-redo"></i> Scan Ulang
                    </button>
                    <button class="btn btn-info" onclick="enableBulkActions()">
                        <i class="fas fa-tasks"></i> Bulk Actions
                    </button>
                    <button class="btn btn-success" onclick="exportToCSV()">
                        <i class="fas fa-file-export"></i> Export CSV
                    </button>
                    <button class="btn btn-secondary" onclick="window.location.href='?'">
                        <i class="fas fa-cog"></i> Scan Baru
                    </button>
                </div>
                
                <!-- Files Table -->
                <div class="files-container">
                    <?php if (empty($files)): ?>
                        <div class="empty-state">
                            <h3><i class="far fa-check-circle"></i> Tidak ada file PHP yang ditemukan dalam rentang waktu tersebut.</h3>
                            <p style="margin-top: 10px;">Semua file PHP berada di luar rentang waktu <?php echo $this->startDate->format('Y-m-d'); ?> hingga <?php echo $this->endDate->format('Y-m-d'); ?></p>
                            <div style="margin-top: 20px;">
                                <button class="btn btn-primary" onclick="window.location.href='?'">
                                    <i class="fas fa-search"></i> Lakukan Scan dengan Parameter Berbeda
                                </button>
                            </div>
                        </div>
                    <?php else: ?>
                        <table class="file-table" id="fileTable">
                            <thead>
                                <tr>
                                    <th class="checkbox-cell" id="selectAllHeader" style="display: none;">
                                        <input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll(this)">
                                    </th>
                                    <th width="5%">#</th>
                                    <th width="30%">File Path</th>
                                    <th width="10%">Ext</th>
                                    <th width="15%">Dibuat</th>
                                    <th width="10%">Ukuran</th>
                                    <th width="10%">Risk</th>
                                    <th width="20%">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="fileTableBody">
                                <?php foreach ($files as $index => $file): ?>
                                <tr id="fileRow_<?php echo $index; ?>" 
                                    data-risk="<?php echo $file['risk_level']; ?>" 
                                    data-filename="<?php echo htmlspecialchars($file['filename']); ?>"
                                    data-path="<?php echo htmlspecialchars($file['encoded_path']); ?>"
                                    data-exists="<?php echo $file['file_exists'] ? 'true' : 'false'; ?>">
                                    
                                    <td class="checkbox-cell" style="display: none;">
                                        <input type="checkbox" class="file-checkbox" 
                                               data-index="<?php echo $index; ?>"
                                               data-path="<?php echo $file['encoded_path']; ?>"
                                               onchange="updateSelection()">
                                    </td>
                                    
                                    <td><?php echo $index + 1; ?></td>
                                    <td>
                                        <div style="display: flex; flex-direction: column;">
                                            <strong><?php echo htmlspecialchars($file['relative_path']); ?></strong>
                                            <small style="color: #666; margin-top: 5px;">
                                                <i class="fas fa-link"></i> 
                                                <?php 
                                                $url = $this->generateFileUrl($file['path']);
                                                if ($url): ?>
                                                    <a href="<?php echo htmlspecialchars($url); ?>" target="_blank" 
                                                       title="<?php echo htmlspecialchars($url); ?>">
                                                        <?php echo htmlspecialchars(substr($url, 0, 50)) . (strlen($url) > 50 ? '...' : ''); ?>
                                                    </a>
                                                <?php else: ?>
                                                    <span>URL tidak tersedia</span>
                                                <?php endif; ?>
                                            </small>
                                            <?php if (!$file['file_exists']): ?>
                                                <small style="color: #e74c3c; margin-top: 3px;">
                                                    <i class="fas fa-exclamation-triangle"></i> File sudah dihapus
                                                </small>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span style="font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px;">
                                            <?php echo htmlspecialchars($file['extension']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo $file['created']; ?></td>
                                    <td><?php echo $file['size']; ?></td>
                                    <td>
                                        <span class="risk-badge risk-<?php echo strtolower($file['risk_level']); ?>">
                                            <?php echo $file['risk_level']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <button class="action-btn btn-primary" 
                                                    onclick="previewFile('<?php echo $file['encoded_path']; ?>', <?php echo $index; ?>)"
                                                    title="Preview file"
                                                    <?php echo !$file['file_exists'] ? 'disabled' : ''; ?>>
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="action-btn btn-warning" 
                                                    onclick="downloadFile('<?php echo $file['encoded_path']; ?>')"
                                                    title="Download file"
                                                    <?php echo !$file['file_exists'] ? 'disabled' : ''; ?>>
                                                <i class="fas fa-download"></i>
                                            </button>
                                            <button class="action-btn btn-danger" 
                                                    onclick="deleteFile('<?php echo $file['encoded_path']; ?>', '<?php echo htmlspecialchars(addslashes($file['filename'])); ?>', <?php echo $index; ?>)"
                                                    title="Hapus file"
                                                    <?php echo !$file['file_exists'] ? 'disabled' : ''; ?>>
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        
                        <div class="pagination" id="pagination"></div>
                    <?php endif; ?>
                </div>
                
                <!-- Custom Scan Form -->
                <div style="background: white; padding: 25px; border-radius: 10px; margin-top: 30px;">
                    <h3><i class="fas fa-cogs"></i> Scan dengan Parameter Berbeda</h3>
                    <form method="GET" action="" style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 15px; margin-top: 15px; align-items: end;">
                        <input type="hidden" name="scan" value="1">
                        <div>
                            <label>Directory Path:</label>
                            <input type="text" name="dir" value="<?php echo htmlspecialchars($this->targetDirectory); ?>" 
                                   style="width: 100%; padding: 10px; margin-top: 5px;">
                        </div>
                        <div>
                            <label>Start Date:</label>
                            <input type="date" name="start_date" value="<?php echo $this->startDate->format('Y-m-d'); ?>" 
                                   style="width: 100%; padding: 10px; margin-top: 5px;">
                        </div>
                        <div>
                            <label>End Date:</label>
                            <input type="date" name="end_date" value="<?php echo $this->endDate->format('Y-m-d'); ?>" 
                                   style="width: 100%; padding: 10px; margin-top: 5px;">
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary" style="height: 42px;">
                                <i class="fas fa-search"></i> Scan Ulang
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Preview Modal -->
            <div id="previewModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2><i class="fas fa-file-code"></i> File Preview</h2>
                        <span class="close" onclick="closeModal('previewModal')">&times;</span>
                    </div>
                    <div id="previewContent"></div>
                </div>
            </div>
            
            <!-- Delete Confirmation Modal -->
            <div id="deleteModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2><i class="fas fa-trash"></i> Konfirmasi Hapus File</h2>
                        <span class="close" onclick="closeModal('deleteModal')">&times;</span>
                    </div>
                    <div id="deleteConfirmContent"></div>
                </div>
            </div>
            
            <!-- JavaScript sama seperti sebelumnya -->
            <script>
                // State management
                let selectedFiles = new Set();
                let currentPage = 1;
                let rowsPerPage = 50;
                let isBulkMode = false;
                
                // Show loading
                function showLoading() {
                    document.getElementById('loading').classList.add('active');
                }
                
                // Hide loading
                function hideLoading() {
                    document.getElementById('loading').classList.remove('active');
                }
                
                // Show alert message
                function showAlert(message, type = 'success') {
                    const alertContainer = document.getElementById('alertContainer');
                    const alertId = 'alert_' + Date.now();
                    
                    const alertHTML = `
                        <div class="alert alert-${type}" id="${alertId}">
                            <div style="display: flex; justify-content: space-between; align-items: start;">
                                <div>${message}</div>
                                <button onclick="document.getElementById('${alertId}').remove()" 
                                        style="background: none; border: none; font-size: 20px; cursor: pointer; color: #666;">
                                    &times;
                                </button>
                            </div>
                        </div>
                    `;
                    
                    alertContainer.insertAdjacentHTML('afterbegin', alertHTML);
                    
                    // Auto remove after 5 seconds
                    setTimeout(() => {
                        const alertElement = document.getElementById(alertId);
                        if (alertElement) {
                            alertElement.remove();
                        }
                    }, 5000);
                }
                
                // Initialize
                document.addEventListener('DOMContentLoaded', function() {
                    // Check for URL parameters to show alerts
                    const urlParams = new URLSearchParams(window.location.search);
                    if (urlParams.has('message')) {
                        const message = urlParams.get('message');
                        const type = urlParams.get('type') || 'success';
                        showAlert(decodeURIComponent(message), type);
                    }
                    
                    // Setup pagination if there are files
                    if (document.getElementById('fileTableBody')) {
                        setupPagination();
                    }
                });
                
                // Filter dan pencarian
                document.getElementById('searchInput').addEventListener('keyup', filterTable);
                document.getElementById('riskFilter').addEventListener('change', filterTable);
                
                function filterTable() {
                    const search = document.getElementById('searchInput').value.toLowerCase();
                    const riskFilter = document.getElementById('riskFilter').value;
                    const rows = document.querySelectorAll('#fileTableBody tr');
                    
                    rows.forEach(row => {
                        const filename = row.getAttribute('data-filename').toLowerCase();
                        const path = row.cells[2].textContent.toLowerCase();
                        const risk = row.getAttribute('data-risk');
                        
                        const matchSearch = filename.includes(search) || path.includes(search);
                        const matchRisk = !riskFilter || risk === riskFilter;
                        
                        row.style.display = (matchSearch && matchRisk) ? '' : 'none';
                    });
                    
                    // Update pagination after filtering
                    setupPagination();
                }
                
                // Modal functions
                function openModal(modalId) {
                    document.getElementById(modalId).style.display = 'block';
                }
                
                function closeModal(modalId) {
                    document.getElementById(modalId).style.display = 'none';
                }
                
                // File actions with AJAX - NO PAGE RELOAD
                function previewFile(encodedPath, rowIndex) {
                    showLoading();
                    
                    fetch('?scan=1&action=preview&ajax=1&path=' + encodedPath)
                        .then(response => response.json())
                        .then(data => {
                            let content = '<h3>' + escapeHtml(data.path) + '</h3>';
                            content += '<p><strong>MD5:</strong> ' + data.md5 + '</p>';
                            content += '<p><strong>Total Lines:</strong> ' + data.total_lines + '</p>';
                            content += '<p><strong>Size:</strong> ' + data.total_size + ' bytes</p>';
                            
                            if (data.is_binary) {
                                content += '<div class="alert alert-warning">' +
                                          '<i class="fas fa-exclamation-triangle"></i> ' +
                                          'File ini tampaknya binary, preview mungkin tidak terbaca</div>';
                            }
                            
                            content += '<div class="file-preview">' + 
                                      (data.is_binary ? 'Binary content cannot be displayed' : 
                                      escapeHtml(data.preview)) + '</div>';
                            
                            document.getElementById('previewContent').innerHTML = content;
                            openModal('previewModal');
                            hideLoading();
                        })
                        .catch(error => {
                            showAlert('Error loading preview: ' + error, 'danger');
                            hideLoading();
                        });
                }
                
                function downloadFile(encodedPath) {
                    // Download langsung tanpa AJAX
                    window.open('?scan=1&action=download&path=' + encodedPath, '_blank');
                }
                
                function deleteFile(encodedPath, filename, rowIndex) {
                    const confirmContent = `
                        <p>Anda yakin ingin menghapus file berikut?</p>
                        <p><strong>${escapeHtml(filename)}</strong></p>
                        <p>File akan dipindahkan ke folder quarantine sebelum dihapus.</p>
                        <div style="margin-top: 20px; display: flex; gap: 10px;">
                            <button class="btn btn-danger" onclick="confirmDelete('${encodedPath}', ${rowIndex})">
                                <i class="fas fa-trash"></i> Ya, Hapus File
                            </button>
                            <button class="btn btn-secondary" onclick="closeModal('deleteModal')">
                                <i class="fas fa-times"></i> Batal
                            </button>
                        </div>
                    `;
                    
                    document.getElementById('deleteConfirmContent').innerHTML = confirmContent;
                    openModal('deleteModal');
                }
                
                function confirmDelete(encodedPath, rowIndex) {
                    showLoading();
                    
                    fetch('?scan=1&action=delete&ajax=1&path=' + encodedPath)
                        .then(response => response.json())
                        .then(result => {
                            if (result.success) {
                                // Update UI tanpa refresh
                                const row = document.getElementById('fileRow_' + rowIndex);
                                if (row) {
                                    // Update status
                                    row.setAttribute('data-exists', 'false');
                                    
                                    // Disable delete and download buttons
                                    const buttons = row.querySelectorAll('.action-btn');
                                    buttons[0].disabled = true; // Preview button
                                    buttons[1].disabled = true; // Download button
                                    buttons[2].disabled = true; // Delete button
                                    
                                    // Add warning message
                                    const pathCell = row.cells[2];
                                    const existingWarning = pathCell.querySelector('.file-warning');
                                    if (!existingWarning) {
                                        const warningHTML = `<small style="color: #e74c3c; margin-top: 3px;">
                                            <i class="fas fa-exclamation-triangle"></i> File sudah dihapus
                                        </small>`;
                                        pathCell.querySelector('div').insertAdjacentHTML('beforeend', warningHTML);
                                    }
                                }
                                
                                showAlert(result.message, 'success');
                                updateSelection(); // Update bulk selection
                            } else {
                                showAlert(result.message, 'danger');
                            }
                            
                            closeModal('deleteModal');
                            hideLoading();
                        })
                        .catch(error => {
                            showAlert('Error deleting file: ' + error, 'danger');
                            hideLoading();
                            closeModal('deleteModal');
                        });
                }
                
                // Bulk Actions
                function enableBulkActions() {
                    isBulkMode = true;
                    document.getElementById('bulkActionsPanel').classList.add('active');
                    
                    // Show checkboxes
                    const checkboxes = document.querySelectorAll('.checkbox-cell');
                    checkboxes.forEach(cell => cell.style.display = '');
                    
                    document.getElementById('selectAllHeader').style.display = '';
                    
                    showAlert('Bulk mode aktif. Pilih file yang ingin dihapus.', 'info');
                }
                
                function cancelBulkActions() {
                    isBulkMode = false;
                    selectedFiles.clear();
                    document.getElementById('bulkActionsPanel').classList.remove('active');
                    
                    // Hide checkboxes
                    const checkboxes = document.querySelectorAll('.checkbox-cell');
                    checkboxes.forEach(cell => cell.style.display = 'none');
                    
                    document.getElementById('selectAllHeader').style.display = 'none';
                    
                    // Uncheck all
                    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
                    document.getElementById('selectAllCheckbox').checked = false;
                    
                    updateSelection();
                }
                
                function updateSelection() {
                    selectedFiles.clear();
                    
                    document.querySelectorAll('.file-checkbox:checked').forEach(checkbox => {
                        selectedFiles.add(checkbox.getAttribute('data-path'));
                    });
                    
                    document.getElementById('selectedCount').textContent = selectedFiles.size;
                    
                    // Update select all checkbox
                    const totalVisible = document.querySelectorAll('#fileTableBody tr[style=""]').length;
                    const selectedCount = selectedFiles.size;
                    document.getElementById('selectAllCheckbox').checked = selectedCount > 0 && selectedCount === totalVisible;
                }
                
                function toggleSelectAll(checkbox) {
                    const isChecked = checkbox.checked;
                    document.querySelectorAll('.file-checkbox').forEach(cb => {
                        cb.checked = isChecked;
                    });
                    
                    updateSelection();
                }
                
                function selectAllFiles() {
                    document.querySelectorAll('.file-checkbox').forEach(cb => {
                        cb.checked = true;
                    });
                    updateSelection();
                }
                
                function deselectAllFiles() {
                    document.querySelectorAll('.file-checkbox').forEach(cb => {
                        cb.checked = false;
                    });
                    updateSelection();
                }
                
                function bulkDeleteSelected() {
                    if (selectedFiles.size === 0) {
                        showAlert('Tidak ada file yang dipilih', 'warning');
                        return;
                    }
                    
                    if (!confirm(`Anda yakin ingin menghapus ${selectedFiles.size} file?`)) {
                        return;
                    }
                    
                    showLoading();
                    
                    const filesArray = Array.from(selectedFiles);
                    
                    fetch('?scan=1&action=bulk_delete&ajax=1', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ files: filesArray })
                    })
                    .then(response => response.json())
                    .then(result => {
                        if (result.success_count > 0) {
                            // Update UI for successfully deleted files
                            result.results.forEach(fileResult => {
                                if (fileResult.success) {
                                    // Find and update the row
                                    const rows = document.querySelectorAll('#fileTableBody tr');
                                    rows.forEach(row => {
                                        const encodedPath = row.getAttribute('data-path');
                                        if (encodedPath === btoa(fileResult.path)) {
                                            row.setAttribute('data-exists', 'false');
                                            
                                            const buttons = row.querySelectorAll('.action-btn');
                                            buttons[0].disabled = true;
                                            buttons[1].disabled = true;
                                            buttons[2].disabled = true;
                                            
                                            // Add warning message
                                            const pathCell = row.cells[2];
                                            const existingWarning = pathCell.querySelector('.file-warning');
                                            if (!existingWarning) {
                                                const warningHTML = `<small style="color: #e74c3c; margin-top: 3px;">
                                                    <i class="fas fa-exclamation-triangle"></i> File sudah dihapus
                                                </small>`;
                                                pathCell.querySelector('div').insertAdjacentHTML('beforeend', warningHTML);
                                            }
                                        }
                                    });
                                }
                            });
                            
                            showAlert(`Berhasil menghapus ${result.success_count} file. ${result.error_count} gagal.`, 'success');
                        } else {
                            showAlert('Tidak ada file yang berhasil dihapus', 'warning');
                        }
                        
                        // Clear selection
                        selectedFiles.clear();
                        document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
                        updateSelection();
                        
                        hideLoading();
                    })
                    .catch(error => {
                        showAlert('Error during bulk delete: ' + error, 'danger');
                        hideLoading();
                    });
                }
                
                function scanAgain() {
                    // Just reload with current parameters
                    window.location.reload();
                }
                
                function exportToCSV() {
                    const rows = [];
                    const visibleRows = Array.from(document.querySelectorAll('#fileTableBody tr')).filter(row => row.style.display !== 'none');
                    
                    // Header
                    rows.push(['No', 'Path', 'Extension', 'Created', 'Size', 'Risk Level', 'URL', 'Status'].join(','));
                    
                    // Data
                    visibleRows.forEach((row, index) => {
                        const cells = row.querySelectorAll('td');
                        const relativePath = cells[1].querySelector('strong').textContent;
                        const urlLink = cells[1].querySelector('a');
                        const url = urlLink ? urlLink.href : 'N/A';
                        const status = row.getAttribute('data-exists') === 'true' ? 'Exists' : 'Deleted';
                        
                        const rowData = [
                            index + 1,
                            `"${relativePath.replace(/"/g, '""')}"`,
                            cells[2].textContent.trim(),
                            cells[3].textContent,
                            cells[4].textContent,
                            cells[5].textContent.trim(),
                            url,
                            status
                        ];
                        
                        rows.push(rowData.join(','));
                    });
                    
                    const csvContent = "data:text/csv;charset=utf-8," + rows.join("\n");
                    const encodedUri = encodeURI(csvContent);
                    const link = document.createElement("a");
                    link.setAttribute("href", encodedUri);
                    link.setAttribute("download", "webshell_scan_" + new Date().toISOString().split('T')[0] + ".csv");
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
                
                // Pagination
                function setupPagination() {
                    const rows = Array.from(document.querySelectorAll('#fileTableBody tr')).filter(row => row.style.display !== 'none');
                    const pageCount = Math.ceil(rows.length / rowsPerPage);
                    
                    if (pageCount <= 1) {
                        document.getElementById('pagination').innerHTML = '';
                        return;
                    }
                    
                    let paginationHtml = '';
                    for (let i = 1; i <= pageCount; i++) {
                        paginationHtml += `<span class="page-link" onclick="showPage(${i})">${i}</span>`;
                    }
                    
                    document.getElementById('pagination').innerHTML = paginationHtml;
                    showPage(1);
                }
                
                function showPage(pageNum) {
                    currentPage = pageNum;
                    const rows = Array.from(document.querySelectorAll('#fileTableBody tr'));
                    const visibleRows = rows.filter(row => row.style.display !== 'none');
                    const start = (pageNum - 1) * rowsPerPage;
                    const end = start + rowsPerPage;
                    
                    let visibleIndex = 0;
                    rows.forEach((row, index) => {
                        if (row.style.display !== 'none') {
                            row.style.display = (visibleIndex >= start && visibleIndex < end) ? '' : 'none';
                            visibleIndex++;
                        } else {
                            row.style.display = 'none';
                        }
                    });
                    
                    // Update active page
                    document.querySelectorAll('.page-link').forEach((link, index) => {
                        link.classList.toggle('active', (index + 1) === pageNum);
                    });
                }
                
                function escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
            </script>
        </body>
        </html>
        <?php
    }
}

// ==================== MAIN EXECUTION ====================
session_start();

// Jika tidak ada parameter scan, tampilkan form awal
if (!isset($_GET['scan']) || $_GET['scan'] != '1') {
    PHPFileMonitor::displayInitialForm(
        $_GET['dir'] ?? '',
        $_GET['start_date'] ?? '',
        $_GET['end_date'] ?? ''
    );
    exit;
}

// Handle AJAX requests
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
    header('Content-Type: application/json');
    
    try {
        // Get parameters dari request
        $dir = $_GET['dir'] ?? ($_SESSION['scan_state']['directory'] ?? '');
        $start_date = $_GET['start_date'] ?? ($_SESSION['scan_state']['start_date'] ?? '');
        $end_date = $_GET['end_date'] ?? ($_SESSION['scan_state']['end_date'] ?? '');
        
        if (empty($dir) || empty($start_date)) {
            echo json_encode(['error' => 'Parameters tidak lengkap. Silakan scan ulang.']);
            exit;
        }
        
        $monitor = new PHPFileMonitor($dir, $start_date, $end_date);
        
        if (isset($_GET['action'])) {
            $action = $_GET['action'];
            
            if ($action === 'preview' && isset($_GET['path'])) {
                $filePath = base64_decode($_GET['path']);
                $preview = $monitor->previewFile($filePath);
                echo json_encode($preview);
                
            } elseif ($action === 'download' && isset($_GET['path'])) {
                $filePath = base64_decode($_GET['path']);
                $fileInfo = $monitor->downloadFile($filePath);
                
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $fileInfo['filename'] . '"');
                header('Content-Length: ' . $fileInfo['size']);
                echo $fileInfo['content'];
                exit;
                
            } elseif ($action === 'delete' && isset($_GET['path'])) {
                $filePath = base64_decode($_GET['path']);
                $result = $monitor->deleteFile($filePath);
                echo json_encode($result);
                
            } elseif ($action === 'bulk_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                if (isset($data['files'])) {
                    $result = $monitor->bulkDeleteFiles($data['files']);
                    echo json_encode(array_merge($result, ['success' => true]));
                } else {
                    echo json_encode(['success' => false, 'message' => 'No files specified']);
                }
            }
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// Regular scan page load
try {
    // Get parameters dari URL
    $dir = $_GET['dir'] ?? '/var/www/html';
    $start_date = $_GET['start_date'] ?? '2023-05-11';
    $end_date = $_GET['end_date'] ?? date('Y-m-d');
    
    // Validasi input
    if (empty($dir) || empty($start_date)) {
        header('Location: ?error=' . urlencode('Parameter tidak lengkap. Silakan isi semua field.'));
        exit;
    }
    
    $monitor = new PHPFileMonitor($dir, $start_date, $end_date);
    
    // Scan files
    $scanResult = $monitor->scanPHPFilesInRange();
    
    // Save log
    $monitor->saveScanResults($scanResult['files']);
    
    // Display dashboard
    $monitor->displayDashboard($scanResult);
    
} catch (Exception $e) {
    // Redirect kembali ke form dengan error message
    $errorMessage = urlencode($e->getMessage());
    header("Location: ?error=$errorMessage&dir=" . urlencode($_GET['dir'] ?? '') . 
           "&start_date=" . urlencode($_GET['start_date'] ?? '') . 
           "&end_date=" . urlencode($_GET['end_date'] ?? ''));
    exit;
}
