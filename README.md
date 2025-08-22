# AWS 보안 대시보드

AWS 운영자를 위한 종합 보안 대시보드는 AWS 계정의 전반적인 보안 상태를 점검하고 위협 사항을 식별할 수 있는 Python 웹 애플리케이션입니다.

## 🚀 주요 기능

### 📊 종합 보안 분석
- **보안 점수**: 0-100점 종합 보안 평가
- **위험도별 이슈 분류**: High/Medium/Low 위험도 분류
- **서비스별 상태 모니터링**: 5개 핵심 AWS 서비스 분석
- **실시간 시각화**: Plotly 기반 인터랙티브 차트

### 🔐 IAM 보안 분석
- IAM 사용자, 역할, 그룹 보안 상태 점검
- MFA 설정 현황 및 미설정 사용자 탐지
- 오래된 액세스 키 및 과도한 권한 탐지
- 루트 계정 보안 위험 요소 분석

### 📋 CloudTrail 모니터링
- CloudTrail 활성화 상태 확인
- 최근 24시간 API 호출 이력 분석
- 의심스러운 활동 패턴 탐지
- 시간별 활동 분포 시각화

### 🗄️ S3 데이터 보안
- S3 버킷 공개 설정 검사
- 버킷 암호화 상태 확인
- 버전 관리 및 MFA Delete 설정 검토
- 액세스 로깅 설정 확인

### 🛡️ GuardDuty 위협 탐지
- GuardDuty 활성화 상태 확인
- 위협 탐지 결과 및 발견 사항 조회
- 심각도별 위협 분류 및 표시
- 데이터 소스 설정 상태 확인

### 🌐 WAF 네트워크 보안
- WAF 웹 ACL 설정 상태 확인
- 관리형 규칙 및 사용자 정의 규칙 분석
- Rate limiting 및 지리적 차단 설정 검토
- 연결된 리소스 현황 확인

### 🎯 AI 기반 권장사항
- 각 보안 이슈별 상세한 해결 단계 제공
- Amazon Q 기반 맞춤형 권장사항 (선택사항)
- 예상 해결 시간 및 비용 영향 안내
- AWS 공식 문서 링크 제공

## 📋 시스템 요구사항

### 최소 요구사항
- **Python**: 3.8 이상
- **메모리**: 512MB 이상
- **디스크**: 100MB 이상
- **네트워크**: 인터넷 연결 (AWS API 접근)

### 권장 요구사항
- **Python**: 3.9 이상
- **메모리**: 1GB 이상
- **디스크**: 500MB 이상
- **CPU**: 2코어 이상

## 🛠️ 설치 및 실행

### 1. 프로젝트 다운로드
```bash
# Git을 사용하는 경우
git clone <repository-url>
cd aws-security-dashboard

# 또는 ZIP 파일 다운로드 후 압축 해제
```

### 2. Python 가상환경 설정 (권장)
```bash
# 가상환경 생성
python -m venv venv

# 가상환경 활성화
# Linux/Mac:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### 3. 의존성 설치
```bash
pip install -r requirements.txt
```

### 4. 애플리케이션 실행

#### 로컬 개발 환경
```bash
streamlit run app.py
```

#### 프로덕션 환경 (EC2 등)
```bash
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

#### 편리한 실행 스크립트 사용
```bash
# Linux/Mac
chmod +x run.sh
./run.sh

# Windows
run.bat
```

### 5. 웹 브라우저 접속
- **로컬**: http://localhost:8501
- **EC2**: http://[EC2-Public-IP]:8501

## 🔐 AWS 권한 설정

### 필수 권한 목록

#### IAM 권한
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:GetUser",
                "iam:GetRole",
                "iam:GetAccountSummary",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:GetGroupsForUser"
            ],
            "Resource": "*"
        }
    ]
}
```

#### CloudTrail 권한
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

#### S3 권한
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetPublicAccessBlock"
            ],
            "Resource": "*"
        }
    ]
}
```

#### GuardDuty 권한
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "guardduty:ListFindings",
                "guardduty:GetFindings"
            ],
            "Resource": "*"
        }
    ]
}
```

#### WAF 권한
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "wafv2:ListWebACLs",
                "wafv2:GetWebACL",
                "wafv2:ListResourcesForWebACL"
            ],
            "Resource": "*"
        }
    ]
}
```

#### STS 권한 (필수)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

### 권장 설정 방법

#### 방법 1: ReadOnlyAccess 정책 사용 (간단)
```bash
# AWS CLI를 사용하여 ReadOnlyAccess 정책 연결
aws iam attach-user-policy --user-name [사용자명] --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

#### 방법 2: 커스텀 정책 생성 (보안 강화)
1. AWS IAM 콘솔에서 새 정책 생성
2. 위의 JSON 정책들을 하나로 결합
3. 사용자 또는 역할에 정책 연결

#### 방법 3: EC2 인스턴스 프로파일 사용 (권장)
1. IAM 역할 생성 및 정책 연결
2. EC2 인스턴스에 역할 연결
3. 애플리케이션에서 "인스턴스 프로파일 사용" 선택

## 🚀 EC2 배포 가이드

### 1. EC2 인스턴스 준비
```bash
# Amazon Linux 2 기준
sudo yum update -y
sudo yum install -y python3 python3-pip git

# Ubuntu 기준
sudo apt update
sudo apt install -y python3 python3-pip git
```

### 2. 애플리케이션 배포
```bash
# 프로젝트 클론
git clone <repository-url>
cd aws-security-dashboard

# 의존성 설치
pip3 install -r requirements.txt

# 백그라운드 실행
nohup streamlit run app.py --server.port 8501 --server.address 0.0.0.0 > app.log 2>&1 &
```

### 3. 보안 그룹 설정
- 인바운드 규칙에 포트 8501 추가
- 소스: 필요한 IP 범위로 제한 (0.0.0.0/0은 권장하지 않음)

### 4. 도메인 및 HTTPS 설정 (선택사항)
```bash
# Nginx 설치 및 설정
sudo yum install -y nginx
# 또는
sudo apt install -y nginx

# SSL 인증서 설정 (Let's Encrypt 등)
```

## 📊 사용 방법

### 1. 자격 증명 입력
- **수동 입력**: AWS Access Key, Secret Key, 계정 ID, 리전
- **인스턴스 프로파일**: EC2에서 실행 시 자동 인증

### 2. 스캔 옵션 선택
- **기본 스캔**: 모든 서비스 스캔
- **선택적 스캔**: 특정 서비스만 스캔
- **심화 분석**: 더 상세한 분석 (시간 소요)

### 3. 결과 확인
- **보안 점수**: 전체 보안 상태 점수
- **서비스별 상태**: 각 서비스의 보안 현황
- **우선순위 이슈**: 즉시 해결이 필요한 이슈
- **권장사항**: 단계별 해결 방법

### 4. 보고서 활용
- **대시보드**: 실시간 보안 상태 모니터링
- **차트**: 시각적 데이터 분석
- **권장사항**: 구체적인 해결 단계

## 🔧 문제 해결

### 일반적인 오류

#### 1. 자격 증명 오류
**증상**: "AWS 자격 증명이 올바르지 않습니다"
**해결방법**:
- Access Key와 Secret Key 재확인
- 계정 ID가 12자리 숫자인지 확인
- 복사/붙여넣기 시 공백 제거

#### 2. 권한 부족 오류
**증상**: "접근 권한이 없습니다"
**해결방법**:
- 필요한 IAM 권한 확인
- ReadOnlyAccess 정책 연결 시도
- 관리자에게 권한 요청

#### 3. 네트워크 연결 오류
**증상**: "AWS 서비스에 연결할 수 없습니다"
**해결방법**:
- 인터넷 연결 확인
- 방화벽/프록시 설정 확인
- AWS 서비스 상태 확인

#### 4. 포트 접근 오류
**증상**: 웹 브라우저에서 접속 불가
**해결방법**:
- 포트 8501이 열려있는지 확인
- 보안 그룹 설정 확인 (EC2)
- 방화벽 설정 확인

### 로그 확인
```bash
# 애플리케이션 로그 확인
tail -f app.log

# Streamlit 로그 확인
streamlit run app.py --logger.level debug
```

### 성능 최적화
- **메모리 부족**: 스캔 범위 축소 또는 인스턴스 업그레이드
- **느린 응답**: 네트워크 연결 상태 확인
- **타임아웃**: AWS API 한도 확인

## 🛡️ 보안 고려사항

### 데이터 보안
- 자격 증명은 메모리에서만 처리
- 세션 종료 시 모든 데이터 삭제
- 로그 파일에 민감 정보 저장 안함

### 네트워크 보안
- HTTPS 사용 권장 (프로덕션)
- 접근 IP 제한 설정
- VPN 또는 프라이빗 네트워크 사용 권장

### 권한 관리
- 최소 권한 원칙 적용
- 읽기 전용 권한만 사용
- 정기적인 권한 검토

## 📞 지원 및 문의

### 기술 지원
- **AWS 지원**: https://console.aws.amazon.com/support/
- **AWS 문서**: https://docs.aws.amazon.com/
- **서비스 상태**: https://status.aws.amazon.com/

### 문제 보고 시 포함할 정보
- 오류 메시지 전문
- 사용 중인 AWS 리전
- 스캔하려던 서비스
- 오류 발생 시간
- 브라우저 및 운영체제 정보

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🔄 업데이트 이력

### v1.0.0 (2024-01-XX)
- 초기 릴리스
- 5개 AWS 서비스 보안 스캔 기능
- 실시간 대시보드 및 시각화
- AI 기반 권장사항 제공