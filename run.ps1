# Script khởi chạy ứng dụng phòng lab Path Traversal trên Windows 11
# Tự động định vị Java 21 và chạy file JAR đã đóng gói

$javaCmd = "java"
if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
    $javaCmd = "$env:JAVA_HOME\bin\java.exe"
} elseif (Test-Path "C:\Program Files\Android\Android Studio\jbr\bin\java.exe") {
    $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
    $javaCmd = "$env:JAVA_HOME\bin\java.exe"
}

$jarPath = "target\path-traversal-lab-1.0.0.jar"

# Nếu chưa có file JAR thì tự động build trước
if (-not (Test-Path $jarPath)) {
    Write-Host "[INFO] Đang đóng gói dự án thành tệp JAR..." -ForegroundColor Cyan
    .\mvnw.ps1 package -DskipTests
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " KHỞI CHẠY PHÒNG LAB PATH TRAVERSAL (CWE-22) - JAVA 21" -ForegroundColor Green
Write-Host " Cổng lắng nghe: http://localhost:8080" -ForegroundColor Green
Write-Host " Profile: lab" -ForegroundColor Green
Write-Host " Nhấn Ctrl + C để dừng ứng dụng khi kết thúc" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Green

& $javaCmd -jar $jarPath --spring.profiles.active=lab
