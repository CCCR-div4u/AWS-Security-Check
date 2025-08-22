# EC2 IAM 역할 설정 가이드

## 🔐 IAM 역할 생성 (권장 방법)

### 1. IAM 정책 생성

AWS 콘솔 → IAM → 정책 → 정책 생성

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityDashboardReadOnly",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:GetUser",
        "iam:GetRole",
        "iam:GetAccountSummary",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "waf:ListWebACLs",
        "waf:GetWebACL"
      ],
      "Resource": "*"
    }
  ]
}
```

**정책 이름**: `AWSSecurityDashboardReadOnly`

### 2. IAM 역할 생성

AWS 콘솔 → IAM → 역할 → 역할 생성

1. **신뢰할 수 있는 엔터티 유형**: AWS 서비스
2. **사용 사례**: EC2
3. **권한 정책**: 위에서 생성한 `AWSSecurityDashboardReadOnly` 정책 연결
4. **역할 이름**: `EC2-SecurityDashboard-Role`

### 3. EC2 인스턴스에 역할 연결

#### 새 인스턴스 생성 시:
- 인스턴스 시작 → 고급 세부 정보 → IAM 인스턴스 프로파일 → `EC2-SecurityDashboard-Role` 선택

#### 기존 인스턴스에 연결:
1. EC2 콘솔 → 인스턴스 선택
2. 작업 → 보안 → IAM 역할 수정
3. `EC2-SecurityDashboard-Role` 선택 → 업데이트

## 🔧 애플리케이션 설정

IAM 역할을 사용하는 경우, 애플리케이션에서 **인스턴스 프로파일 사용** 체크박스를 선택하세요.

```python
# 코드에서는 자동으로 IAM 역할 사용
session = boto3.Session()  # 자격 증명 입력 불필요
```

## ✅ 권한 테스트

```bash
# EC2에서 권한 테스트
aws sts get-caller-identity
aws iam list-users --max-items 1
aws s3 ls
```

## 🚨 보안 모범 사례

1. **최소 권한 원칙**: 필요한 권한만 부여
2. **정기적 검토**: 권한 사용 현황 정기 점검
3. **CloudTrail 활성화**: API 호출 로그 기록
4. **태그 활용**: 리소스 관리 및 비용 추적

## 🔍 문제 해결

### 권한 오류 발생 시:
1. IAM 역할이 EC2에 올바르게 연결되었는지 확인
2. 정책에 필요한 권한이 모두 포함되었는지 확인
3. CloudTrail 로그에서 거부된 API 호출 확인

### 역할 연결 확인:
```bash
# EC2에서 실행
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```