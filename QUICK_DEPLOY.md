# 🚀 AWS 보안 대시보드 빠른 배포 가이드

EC2에서 5분 만에 배포하는 간단한 가이드입니다.

## 📋 사전 준비

1. **EC2 인스턴스**: t3.small 이상, Amazon Linux 2
2. **보안 그룹**: 포트 8501 오픈
3. **IAM 역할**: ReadOnlyAccess 정책 연결 (권장)

## ⚡ 빠른 배포 (5분)

### 1. EC2 접속
```bash
ssh -i your-key.pem ec2-user@your-ec2-ip
```

### 2. 시스템 준비
```bash
# 패키지 업데이트 및 설치
sudo yum update -y
sudo yum install -y python3 python3-pip git

# 프로젝트 클론
git clone https://github.com/your-username/aws-security-dashboard.git
cd aws-security-dashboard
```

### 3. 애플리케이션 설치
```bash
# 가상환경 생성
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. 실행
```bash
# 애플리케이션 시작
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

### 5. 접속
브라우저에서 `http://your-ec2-ip:8501` 접속

## 🔄 백그라운드 실행 (선택사항)

```bash
# 백그라운드 실행
nohup streamlit run app.py --server.port 8501 --server.address 0.0.0.0 > app.log 2>&1 &

# 프로세스 확인
ps aux | grep streamlit

# 로그 확인
tail -f app.log
```

## 🛑 중지

```bash
# 프로세스 찾기
ps aux | grep streamlit

# 프로세스 종료
kill [PID]
```

## 📞 문제 해결

### 포트 접근 안됨
- EC2 보안 그룹에서 포트 8501 확인
- `sudo netstat -tlnp | grep 8501`로 포트 사용 확인

### AWS 권한 오류
- EC2에 IAM 역할이 연결되어 있는지 확인
- 또는 수동으로 AWS 자격 증명 입력

### Python 패키지 오류
```bash
# 가상환경 재생성
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 🔗 상세 가이드
더 자세한 배포 방법은 [DEPLOYMENT.md](DEPLOYMENT.md)를 참조하세요.