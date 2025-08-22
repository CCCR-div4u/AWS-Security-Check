# AWS 보안 대시보드 테스트

이 디렉터리는 AWS 보안 대시보드 애플리케이션의 테스트 코드를 포함합니다.

## 테스트 구조

### 1. 기본 테스트 (`test_basic_simple.py`)
- **AWS 자격 증명 검증**: 계정 ID, Access Key 형식 검증
- **보안 스캔 기능**: 스캔 시간 계산, 보안 점수 계산
- **데이터 포맷팅**: 날짜/시간, 파일 크기 포맷팅
- **오류 처리**: AWS 오류 메시지 처리

### 2. AWS 연결 테스트 (`test_aws_connection.py`)
- **Mock 연결 테스트**: 모든 AWS 서비스 연결 시뮬레이션
- **실제 연결 테스트**: 환경 변수가 설정된 경우 실제 AWS 연결
- **오류 처리 테스트**: 다양한 AWS 오류 상황 테스트

### 3. 통합 테스트 (`test_integration.py`)
- **전체 워크플로우**: 인증부터 스캔까지 전체 프로세스
- **성능 테스트**: 대용량 데이터 처리, 동시 API 호출
- **보안 테스트**: 민감한 데이터 처리, 입력 검증

## 테스트 실행 방법

### 전체 테스트 실행
```bash
python3 tests/run_tests.py
```

### 특정 테스트 모듈 실행
```bash
python3 -m unittest tests.test_basic_simple -v
python3 -m unittest tests.test_aws_connection -v
python3 -m unittest tests.test_integration -v
```

### 특정 테스트 클래스 실행
```bash
python3 -m unittest tests.test_basic_simple.TestAWSCredentialsValidation -v
```

### 특정 테스트 메서드 실행
```bash
python3 -m unittest tests.test_basic_simple.TestAWSCredentialsValidation.test_account_id_format_validation -v
```

## 실제 AWS 연결 테스트

실제 AWS 서비스와의 연결을 테스트하려면 다음 환경 변수를 설정하세요:

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="ap-northeast-2"
```

**주의**: 실제 AWS 연결 테스트는 읽기 전용 권한만 사용하지만, 테스트용 계정을 사용하는 것을 권장합니다.

## 테스트 커버리지

### 기능별 테스트 커버리지
- ✅ AWS 자격 증명 검증
- ✅ 권한 확인
- ✅ 보안 스캔 기능
- ✅ 데이터 포맷팅
- ✅ 오류 처리
- ✅ 전체 워크플로우
- ✅ 성능 및 확장성
- ✅ 보안 및 규정 준수

### AWS 서비스별 테스트
- ✅ STS (Security Token Service)
- ✅ IAM (Identity and Access Management)
- ✅ S3 (Simple Storage Service)
- ✅ CloudTrail
- ✅ GuardDuty
- ✅ WAF (Web Application Firewall)

## 테스트 결과 해석

### 성공률
- **100%**: 모든 테스트 통과
- **95% 이상**: 양호한 상태
- **90% 미만**: 문제 해결 필요

### 건너뛴 테스트
- 실제 AWS 연결 테스트는 환경 변수가 설정되지 않으면 자동으로 건너뜁니다.
- 이는 정상적인 동작이며 오류가 아닙니다.

## 문제 해결

### 의존성 오류
```bash
pip install boto3 botocore pandas plotly streamlit
```

### 모듈 import 오류
프로젝트 루트 디렉터리에서 테스트를 실행하세요:
```bash
cd aws-security-dashboard
python3 tests/run_tests.py
```

### AWS 권한 오류
테스트용 IAM 사용자에게 다음 권한을 부여하세요:
- `sts:GetCallerIdentity`
- `iam:GetAccountSummary`
- `s3:ListBuckets`
- 기타 읽기 전용 권한

## 테스트 추가 가이드

새로운 테스트를 추가할 때는 다음 규칙을 따르세요:

1. **테스트 파일명**: `test_*.py` 형식
2. **테스트 클래스명**: `Test*` 형식으로 시작
3. **테스트 메서드명**: `test_*` 형식으로 시작
4. **문서화**: 각 테스트에 한국어 docstring 추가
5. **Mock 사용**: 외부 의존성은 Mock으로 처리

### 예시
```python
class TestNewFeature(unittest.TestCase):
    """새로운 기능 테스트"""
    
    def test_new_functionality(self):
        """새로운 기능 테스트"""
        # 테스트 코드
        pass
```