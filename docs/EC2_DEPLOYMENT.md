# EC2 배포 완전 가이드

## 🚀 단계별 배포 프로세스

### 1단계: EC2 인스턴스 생성

```bash
# 권장 사양
- AMI: Ubuntu 22.04 LTS (ami-0c02fb55956c7d316)
- 인스턴스 타입: t3.small (2 vCPU, 2GB RAM)
- 스토리지: 20GB gp3
- 보안 그룹: SSH(22), HTTP(80), HTTPS(443), Custom(8501)
```

### 2단계: 보안 그룹 설정

```bash
# 인바운드 규칙
Type        Protocol    Port Range    Source
SSH         TCP         22           Your IP
HTTP        TCP         80           0.0.0.0/0
HTTPS       TCP         443          0.0.0.0/0
Custom TCP  TCP         8501         0.0.0.0/0
```

### 3단계: IAM 역할 연결

1. IAM 콘솔에서 역할 생성 (위의 IAM_ROLE_SETUP.md 참조)
2. EC2 인스턴스에 역할 연결

### 4단계: EC2 접속 및 초기 설정

```bash
# SSH 접속
ssh -i your-key.pem ubuntu@your-ec2-public-ip

# 초기 설정 스크립트 실행
curl -sSL https://raw.githubusercontent.com/your-repo/aws-security-dashboard/main/scripts/ec2_setup.sh | bash
```

### 5단계: 애플리케이션 배포

```bash
# 애플리케이션 디렉터리로 이동
cd /opt/aws-security-dashboard

# GitHub에서 코드 클론
git clone https://github.com/your-username/aws-security-dashboard.git .

# 가상환경 활성화
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# Python 버전 확인 (3.10.x여야 함)
python3 --version
```

### 6단계: 서비스 설정

```bash
# systemd 서비스 파일 복사
sudo cp systemd/aws-security-dashboard.service /etc/systemd/system/

# 서비스 활성화 및 시작
sudo systemctl daemon-reload
sudo systemctl enable aws-security-dashboard
sudo systemctl start aws-security-dashboard

# 서비스 상태 확인
sudo systemctl status aws-security-dashboard
```

### 7단계: Nginx 설정 (선택사항)

```bash
# Nginx 설치
sudo apt install nginx -y

# 설정 파일 복사
sudo cp nginx/aws-security-dashboard.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/aws-security-dashboard.conf /etc/nginx/sites-enabled/

# Nginx 재시작
sudo systemctl restart nginx
```

## 🔧 환경 변수 설정

```bash
# /opt/aws-security-dashboard/.env 파일 생성
cat > /opt/aws-security-dashboard/.env << EOF
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
AWS_DEFAULT_REGION=ap-northeast-2
EOF
```

## 📊 모니터링 설정

### 로그 확인
```bash
# 애플리케이션 로그
sudo journalctl -u aws-security-dashboard -f

# Nginx 로그 (사용하는 경우)
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### 시스템 리소스 모니터링
```bash
# CPU, 메모리 사용량
htop

# 디스크 사용량
df -h

# 네트워크 연결
netstat -tlnp | grep 8501
```

## 🔒 보안 강화

### 1. 방화벽 설정
```bash
# UFW 활성화
sudo ufw enable

# 필요한 포트만 열기
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 8501
```

### 2. SSL 인증서 설정 (Let's Encrypt)
```bash
# Certbot 설치
sudo apt install certbot python3-certbot-nginx -y

# SSL 인증서 발급
sudo certbot --nginx -d your-domain.com
```

### 3. 자동 업데이트 설정
```bash
# 보안 업데이트 자동 설치
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 🚨 문제 해결

### 서비스가 시작되지 않는 경우
```bash
# 로그 확인
sudo journalctl -u aws-security-dashboard --no-pager

# 수동 실행으로 오류 확인
cd /opt/aws-security-dashboard
source venv/bin/activate
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

### 포트 접근 불가 시
```bash
# 포트 사용 확인
sudo netstat -tlnp | grep 8501

# 보안 그룹 확인
# AWS 콘솔에서 EC2 보안 그룹 인바운드 규칙 확인
```

### IAM 권한 오류 시
```bash
# IAM 역할 연결 확인
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS CLI로 권한 테스트
aws sts get-caller-identity
```

## 📈 성능 최적화

### 1. 시스템 튜닝
```bash
# 스왑 파일 생성 (메모리 부족 시)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 2. 애플리케이션 최적화
```bash
# Streamlit 설정 최적화
mkdir -p ~/.streamlit
cat > ~/.streamlit/config.toml << EOF
[server]
maxUploadSize = 200
maxMessageSize = 200

[browser]
gatherUsageStats = false
EOF
```

## ✅ 배포 완료 체크리스트

- [ ] EC2 인스턴스 생성 및 보안 그룹 설정
- [ ] IAM 역할 생성 및 연결
- [ ] Python 3.10 설치 및 가상환경 설정
- [ ] 애플리케이션 코드 배포
- [ ] systemd 서비스 설정 및 시작
- [ ] 웹 브라우저에서 접속 확인
- [ ] IAM 역할로 AWS 연결 테스트
- [ ] 보안 스캔 기능 테스트
- [ ] 로그 모니터링 설정
- [ ] 백업 및 복구 계획 수립

## 🌐 접속 정보

```bash
# 애플리케이션 URL
http://your-ec2-public-ip:8501

# 또는 도메인 사용 시
https://your-domain.com
```