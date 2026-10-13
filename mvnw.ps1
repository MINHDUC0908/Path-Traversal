# Maven Wrapper PowerShell Launcher
# Tự động định vị Java 21 và chạy Maven Wrapper mượt mà trên Windows

param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MavenArgs
)

# 1. Xác định Java executable
$javaCmd = "java"
if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
    $javaCmd = "$env:JAVA_HOME\bin\java.exe"
} elseif (Test-Path "C:\Program Files\Android\Android Studio\jbr\bin\java.exe") {
    $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
    $javaCmd = "$env:JAVA_HOME\bin\java.exe"
}

# 2. Xử lý trường hợp chạy ứng dụng (run / spring-boot:run)
# Vì thư mục chứa ký tự tiếng Việt (Bảo mật), lệnh spring-boot:run của Maven bị lỗi khi phân giải classpath
# Chạy trực tiếp qua JAR đóng gói đảm bảo 100% ổn định và nhanh chóng
if ($MavenArgs -and ($MavenArgs -contains "spring-boot:run" -or $MavenArgs -contains "run")) {
    $jarPath = "target\path-traversal-lab-1.0.0.jar"
    if (-not (Test-Path $jarPath)) {
        Write-Host "[INFO] Đang đóng gói tệp JAR..." -ForegroundColor Cyan
        & $javaCmd "-Dmaven.multiModuleProjectDirectory=." -cp ".mvn\wrapper\maven-wrapper.jar" org.apache.maven.wrapper.MavenWrapperMain package -DskipTests
    }
    Write-Host ">>> Khởi chạy Path Traversal Lab trên cổng 8080 (Profile: lab) <<<" -ForegroundColor Green
    & $javaCmd -jar $jarPath --spring.profiles.active=lab
    exit $LASTEXITCODE
}

$wrapperJar = ".mvn\wrapper\maven-wrapper.jar"
if (-not (Test-Path $wrapperJar)) {
    Write-Error "Không tìm thấy $wrapperJar"
    exit 1
}

# 3. Gọi Maven Wrapper cho các tác vụ khác (compile, test, package...)
& $javaCmd "-Dmaven.multiModuleProjectDirectory=." -cp $wrapperJar org.apache.maven.wrapper.MavenWrapperMain @MavenArgs
exit $LASTEXITCODE
