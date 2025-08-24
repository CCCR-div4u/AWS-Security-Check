# AWS 보안 대시보드 EC2 배포 가이드

이 문서는 GitHub 레포지토리에서 AWS EC2 인스턴스로 직접 클론하여 배포하는 상세한 가이드입니다.

## 🚀 배포 개요

### 배포 방식
- **소스**: GitHub 레포지토리
- **대상**: AWS EC2 인스턴스
- **방법**: Git clone 후 직접 설치
- **웹서버**: Streamlit 내장 서버
- **포트**: 8501

### 시스템 요구사항
- **OS**: Amazon Linux 2, Ubuntu 18.04+ 또는 CentOS 7+
- **Python**: 3.8 이상 (3.9 권장)
- **메모리**: 최소 1GB (2GB 권장)
- **디스크**: 최소 2GB 여유 공간
- **네트워크**: 인터넷 연결 (AWS API 접근)

## 📋 1단계: EC2 인스턴스 준비

### 1.1 EC2 인스턴스 생성

#### 권장 인스턴스 사양
```
인스턴스 타입: t3.small 이상
운영체제: Amazon Linux 2 AMI
스토리지: 8GB gp3 (최소)
```

#### 보안 그룹 설정
```
인바운드 규칙:
- SSH (22): 관리자 IP만 허용
- HTTP (8501): 필요한 IP 범위로 제한
  * 0.0.0.0/0은 보안상 권장하지 않음
  * 회사 IP 대역 또는 VPN IP만 허용 권장
```

### 1.2 IAM 역할 설정 (권장)

#### IAM 역할 생성
1. AWS IAM 콘솔에서 새 역할 생성
2. 신뢰할 수 있는 엔터티: AWS 서비스 → EC2
3. 권한 정책 연결:
   - `ReadOnlyAccess` (간단한 방법)
   - 또는 커스텀 정책 (보안 강화)

#### 커스텀 정책 예시
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:List*",
                "iam:Get*",
                "cloudtrail:Describe*",
                "cloudtrail:Get*",
                "cloudtrail:LookupEvents",
                "s3:ListAllMyBuckets",
                "s3:GetBucket*",
                "s3:GetPublicAccessBlock",
                "guardduty:List*",
                "guardduty:Get*",
                "wafv2:List*",
                "wafv2:Get*",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

#### EC2에 역할 연결
1. EC2 콘솔에서 인스턴스 선택
2. 작업 → 보안 → IAM 역할 수정
3. 생성한 역할 선택 후 저장

## 🔧 2단계: 시스템 환경 설정

### 2.1 EC2 인스턴스 접속
```bash
# SSH로 EC2 접속
ssh -i your-key.pem ec2-user@your-ec2-public-ip
```

### 2.2 시스템 업데이트 및 필수 패키지 설치

#### Amazon Linux 2
```bash
# 시스템 업데이트
sudo yum update -y

# 필수 패키지 설치
sudo yum install -y python3 python3-pip git curl

# Python 가상환경 도구 설치
sudo pip3 install virtualenv
```

#### Ubuntu
```bash
# 시스템 업데이트
sudo apt update && sudo apt upgrade -y

# 필수 패키지 설치
sudo apt install -y python3 python3-pip python3-venv git curl

# 추가 의존성
sudo apt install -y python3-dev build-essential
```

### 2.3 방화벽 설정 (필요시)

#### Amazon Linux 2 (firewalld 사용시)
```bash
# 방화벽 상태 확인
sudo systemctl status firewalld

# 포트 8501 열기
sudo firewall-cmd --permanent --add-port=8501/tcp
sudo firewall-cmd --reload
```

#### Ubuntu (ufw 사용시)
```bash
# 포트 8501 열기
sudo ufw allow 8501/tcp
sudo ufw reload
```

## 📥 3단계: 애플리케이션 배포

### 3.1 GitHub 레포지토리 클론
```bash
# 홈 디렉토리로 이동
cd ~

# 레포지토리 클론
git clone https://github.com/your-username/aws-security-dashboard.git

# 프로젝트 디렉토리로 이동
cd aws-security-dashboard
```

### 3.2 Python 가상환경 설정
```bash
# 가상환경 생성
python3 -m venv venv

# 가상환경 활성화
source venv/bin/activate

# pip 업그레이드
pip install --upgrade pip
```

### 3.3 의존성 설치
```bash
# requirements.txt에서 패키지 설치
pip install -r requirements.txt

# 설치 확인
pip list
```

### 3.4 애플리케이션 테스트
```bash
# 애플리케이션 실행 테스트
streamlit run app.py --server.port 8501 --server.address 0.0.0.0

# 브라우저에서 http://your-ec2-ip:8501 접속하여 확인
# Ctrl+C로 중지
```

## 🔄 4단계: 서비스 등록 (선택사항)

### 4.1 systemd 서비스 설정
```bash
# 서비스 파일 복사
sudo cp systemd/aws-security-dashboard.service /etc/systemd/system/

# 서비스 파일 편집 (경로 수정)
sudo nano /etc/systemd/system/aws-security-dashboard.service
```

#### 서비스 파일 내용 확인/수정
```ini
[Unit]
Description=AWS Security Dashboard
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/aws-security-dashboard
Environment=PATH=/home/ec2-user/aws-security-dashboard/venv/bin
ExecStart=/home/ec2-user/aws-security-dashboard/venv/bin/streamlit run app.py --server.port 8501 --server.address 0.0.0.0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 4.2 서비스 활성화 및 시작
```bash
# systemd 데몬 리로드
sudo systemctl daemon-reload

# 서비스 활성화 (부팅시 자동 시작)
sudo systemctl enable aws-security-dashboard

# 서비스 시작
sudo systemctl start aws-security-dashboard

# 서비스 상태 확인
sudo systemctl status aws-security-dashboard
```

### 4.3 서비스 관리 명령어
```bash
# 서비스 중지
sudo systemctl stop aws-security-dashboard

# 서비스 재시작
sudo systemctl restart aws-security-dashboard

# 로그 확인
sudo journalctl -u aws-security-dashboard -f

# 서비스 비활성화
sudo systemctl disable aws-security-dashboard
```

## 🌐 5단계: 웹 접속 및 확인

### 5.1 접속 URL 확인
```bash
# 퍼블릭 IP 확인
curl http://169.254.169.254/latest/meta-data/public-ipv4

# 접속 URL: http://[퍼블릭-IP]:8501
```

### 5.2 애플리케이션 동작 확인
1. 웹 브라우저에서 `http://your-ec2-ip:8501` 접속
2. AWS 자격 증명 입력 화면 확인
3. IAM 역할 사용 또는 수동 자격 증명 입력
4. 보안 스캔 실행 및 결과 확인

## 🔒 6단계: 보안 강화 (권장)

### 6.1 HTTPS 설정 (Nginx 사용)

#### Nginx 설치
```bash
# Amazon Linux 2
sudo amazon-linux-extras install nginx1

# Ubuntu
sudo apt install nginx
```

#### SSL 인증서 설정 (Let's Encrypt)
```bash
# Certbot 설치
sudo yum install -y certbot python3-certbot-nginx  # Amazon Linux 2
# 또는
sudo apt install -y certbot python3-certbot-nginx  # Ubuntu

# SSL 인증서 발급
sudo certbot --nginx -d your-domain.com
```

#### Nginx 설정
```bash
# 설정 파일 복사
sudo cp nginx/aws-security-dashboard.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/aws-security-dashboard.conf /etc/nginx/sites-enabled/

# 설정 테스트
sudo nginx -t

# Nginx 재시작
sudo systemctl restart nginx
```

### 6.2 접근 제한 설정

#### IP 기반 접근 제한 (Nginx)
```nginx
# /etc/nginx/sites-available/aws-security-dashboard.conf에 추가
location / {
    allow 192.168.1.0/24;  # 허용할 IP 대역
    allow 10.0.0.0/8;      # 허용할 IP 대역
    deny all;              # 나머지 모든 IP 차단
    
    proxy_pass http://127.0.0.1:8501;
    # ... 기타 설정
}
```

#### 보안 그룹 재검토
- EC2 보안 그룹에서 불필요한 포트 차단
- SSH 접근을 관리자 IP로만 제한
- 애플리케이션 포트를 필요한 IP 대역으로만 제한

## 🔄 7단계: 업데이트 및 유지보수

### 7.1 애플리케이션 업데이트
```bash
# 프로젝트 디렉토리로 이동
cd ~/aws-security-dashboard

# 최신 코드 가져오기
git pull origin main

# 가상환경 활성화
source venv/bin/activate

# 의존성 업데이트 (필요시)
pip install -r requirements.txt --upgrade

# 서비스 재시작
sudo systemctl restart aws-security-dashboard
```

### 7.2 자동 업데이트 스크립트
```bash
# 업데이트 스크립트 생성
cat > ~/update-dashboard.sh << 'EOF'
#!/bin/bash
cd ~/aws-security-dashboard
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade
sudo systemctl restart aws-security-dashboard
echo "업데이트 완료: $(date)"
EOF

# 실행 권한 부여
chmod +x ~/update-dashboard.sh

# 실행
./update-dashboard.sh
```

### 7.3 로그 모니터링
```bash
# 실시간 로그 확인
sudo journalctl -u aws-security-dashboard -f

# 최근 로그 확인
sudo journalctl -u aws-security-dashboard --since "1 hour ago"

# 오류 로그만 확인
sudo journalctl -u aws-security-dashboard -p err
```

### 7.4 백업 및 복구
```bash
# 설정 백업
tar -czf aws-dashboard-backup-$(date +%Y%m%d).tar.gz ~/aws-security-dashboard

# 복구 (필요시)
tar -xzf aws-dashboard-backup-YYYYMMDD.tar.gz -C ~/
```

## 🚨 8단계: 문제 해결

### 8.1 일반적인 문제

#### 포트 접근 불가
```bash
# 포트 사용 확인
sudo netstat -tlnp | grep 8501

# 프로세스 확인
ps aux | grep streamlit

# 방화벽 상태 확인
sudo systemctl status firewalld  # Amazon Linux 2
sudo ufw status                  # Ubuntu
```

#### 서비스 시작 실패
```bash
# 서비스 상태 확인
sudo systemctl status aws-security-dashboard

# 상세 로그 확인
sudo journalctl -u aws-security-dashboard -n 50

# 수동 실행으로 오류 확인
cd ~/aws-security-dashboard
source venv/bin/activate
streamlit run app.py
```

#### AWS 권한 오류
```bash
# IAM 역할 확인
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS CLI로 권한 테스트
aws sts get-caller-identity
aws iam list-users --max-items 1
```

### 8.2 성능 최적화

#### 메모리 사용량 확인
```bash
# 메모리 사용량 모니터링
free -h
top -p $(pgrep -f streamlit)
```

#### 로그 로테이션 설정
```bash
# logrotate 설정
sudo nano /etc/logrotate.d/aws-security-dashboard
```

```
/var/log/aws-security-dashboard/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 ec2-user ec2-user
}
```

## 📞 9단계: 지원 및 문의

### 9.1 로그 수집 (문제 보고시)
```bash
# 시스템 정보 수집
echo "=== 시스템 정보 ===" > debug-info.txt
uname -a >> debug-info.txt
cat /etc/os-release >> debug-info.txt

echo "=== Python 버전 ===" >> debug-info.txt
python3 --version >> debug-info.txt

echo "=== 서비스 상태 ===" >> debug-info.txt
sudo systemctl status aws-security-dashboard >> debug-info.txt

echo "=== 최근 로그 ===" >> debug-info.txt
sudo journalctl -u aws-security-dashboard --since "1 hour ago" >> debug-info.txt

echo "=== 네트워크 상태 ===" >> debug-info.txt
sudo netstat -tlnp | grep 8501 >> debug-info.txt
```

### 9.2 유용한 링크
- **AWS 문서**: https://docs.aws.amazon.com/
- **Streamlit 문서**: https://docs.streamlit.io/
- **Python 가상환경**: https://docs.python.org/3/tutorial/venv.html

## ✅ 배포 완료 체크리스트

- [ ] EC2 인스턴스 생성 및 보안 그룹 설정
- [ ] IAM 역할 생성 및 EC2에 연결
- [ ] 시스템 패키지 설치 (Python, Git 등)
- [ ] GitHub 레포지토리 클론
- [ ] Python 가상환경 생성 및 의존성 설치
- [ ] 애플리케이션 수동 실행 테스트
- [ ] systemd 서비스 등록 (선택사항)
- [ ] 웹 브라우저에서 접속 확인
- [ ] AWS 자격 증명 테스트
- [ ] 보안 스캔 기능 테스트
- [ ] HTTPS 설정 (선택사항)
- [ ] 접근 제한 설정
- [ ] 백업 및 업데이트 절차 확인

## 🎉 배포 완료!

축하합니다! AWS 보안 대시보드가 성공적으로 배포되었습니다.

**접속 URL**: `http://your-ec2-ip:8501` (또는 HTTPS 설정시 `https://your-domain.com`)

정기적인 업데이트와 보안 점검을 통해 안전하게 운영하시기 바랍니다.